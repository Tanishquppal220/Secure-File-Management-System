"""
Main authentication manager
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from src.database.connection import db_connection
from src.database.models import UserModel, AccessLogModel
from src.auth.password_manager import PasswordManager
from src. auth.two_factor import TwoFactorAuth
from src.utils.validators import Validators
from src.utils.logger import logger
from io import BytesIO  
from typing import Optional

class AuthManager:
    """Manage user authentication and authorization"""

    def __init__(self):
        self.db = db_connection.db
        self.users_collection = self.db.users
        self.access_logs = self.db.access_logs
        self.password_manager = PasswordManager()
        self.two_fa = TwoFactorAuth()
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 15

    def register_user(self, username: str, email: str, password: str,
                      role: str = "user") -> Tuple[bool, str]:
        """
        Register a new user
        Args:
            username: Desired username
            email: User email
            password: User password
            role: User role (default: "user")
        Returns:
            (success: bool, message: str)
        """
        try:
            # Validate inputs
            valid, msg = Validators.validate_username(username)
            if not valid:
                return False, msg

            valid, msg = Validators.validate_email(email)
            if not valid:
                return False, msg

            valid, msg = Validators.validate_password(password)
            if not valid:
                return False, msg

            # Check if user already exists
            if self.users_collection.find_one({"username": username}):
                return False, "Username already exists"

            if self.users_collection.find_one({"email": email}):
                return False, "Email already registered"

            # Hash password
            password_hash = self.password_manager.hash_password(password)

            # Create user document
            user_doc = UserModel.create_user(
                username, email, password_hash, role)

            # Insert into database
            self.users_collection.insert_one(user_doc)

            logger.info(f"New user registered: {username}")
            return True, "Registration successful"

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False, f"Registration failed: {str(e)}"

    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Authenticate user
        Args:
            username: Username
            password: Password
        Returns:
            (success: bool, message: str, user_data: Optional[Dict])
        """
        try:
            # Find user
            user = self.users_collection.find_one({"username": username})

            if not user:
                self._log_access(username, "login", status="failed",
                                 details="User not found")
                return False, "Invalid username or password", None

            # Check if account is locked
            if user.get('account_locked_until'):
                if datetime.now(datetime.timezone.utc) < user['account_locked_until']:
                    return False, "Account is temporarily locked.  Please try again later.", None
                else:
                    # Unlock account
                    self.users_collection.update_one(
                        {"username": username},
                        {"$set": {
                            "account_locked_until": None,
                            "failed_login_attempts": 0
                        }}
                    )

            # Verify password
            if not self.password_manager.verify_password(password, user['password_hash']):
                # Increment failed attempts
                failed_attempts = user.get('failed_login_attempts', 0) + 1
                update_data = {"failed_login_attempts": failed_attempts}

                # Lock account if max attempts exceeded
                if failed_attempts >= self.max_failed_attempts:
                    lockout_until = datetime.now(datetime.timezone.utc) + timedelta(minutes=self. lockout_duration_minutes)
                    update_data['account_locked_until'] = lockout_until

                    self.users_collection.update_one(
                        {"username": username},
                        {"$set": update_data}
                    )

                    self._log_access(username, "login", status="blocked",
                                     details="Account locked due to multiple failed attempts")
                    return False, f"Too many failed attempts. Account locked for {self.lockout_duration_minutes} minutes.", None

                self. users_collection.update_one(
                    {"username": username},
                    {"$set": update_data}
                )

                self._log_access(username, "login", status="failed",
                                 details="Invalid password")
                return False, "Invalid username or password", None

            # Check if account is active
            if not user.get('is_active', True):
                self._log_access(username, "login", status="blocked",
                                 details="Account inactive")
                return False, "Account is inactive", None

            # Password correct - reset failed attempts
            self.users_collection.update_one(
                {"username": username},
                {"$set": {
                    "failed_login_attempts": 0,
                    "account_locked_until": None,
                    "last_login": datetime.utcnow()
                }}
            )

            # Check if 2FA is enabled
            if user.get('two_fa_enabled', False):
                return True, "2fa_required", UserModel.get_public_fields(user)

            # Login successful
            self._log_access(username, "login", status="success")
            logger.info(f"User logged in: {username}")

            return True, "Login successful", UserModel.get_public_fields(user)

        except Exception as e:
            logger.error(f"Login error: {e}")
            return False, f"Login failed: {str(e)}", None

    def verify_2fa_and_login(self, username: str, token: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Verify 2FA token and complete login
        Args:
            username: Username
            token: 6-digit TOTP token
        Returns:
            (success: bool, message: str, user_data: Optional[Dict])
        """
        try:
            user = self.users_collection.find_one({"username": username})

            if not user:
                return False, "User not found", None

            if not user.get('two_fa_enabled', False):
                return False, "2FA is not enabled for this account", None

            # Verify TOTP token
            if not self.two_fa.verify_totp(user['two_fa_secret'], token):
                self._log_access(username, "2fa_verification", status="failed",
                                 details="Invalid 2FA token")
                return False, "Invalid 2FA code", None

            # 2FA verification successful
            self._log_access(username, "2fa_verification", status="success")
            logger.info(f"2FA verified for user: {username}")

            return True, "Login successful", UserModel.get_public_fields(user)

        except Exception as e:
            logger.error(f"2FA verification error: {e}")
            return False, f"2FA verification failed: {str(e)}", None

    def enable_2fa(self, username: str) -> Tuple[bool, str, Optional[str], Optional[BytesIO]]:
        """
        Enable 2FA for user
        Args:
            username: Username
        Returns:
            (success: bool, message: str, secret: Optional[str], qr_code: Optional[BytesIO])
        """
        try:
            user = self.users_collection. find_one({"username": username})

            if not user:
                return False, "User not found", None, None

            if user.get('two_fa_enabled', False):
                return False, "2FA is already enabled", None, None

            # Generate secret
            secret = self.two_fa.generate_secret()

            # Generate QR code
            uri = self.two_fa.get_totp_uri(username, secret)
            qr_code = self.two_fa.generate_qr_code(uri)

            # Update user with secret (but don't enable yet)
            self.users_collection.update_one(
                {"username": username},
                {"$set": {"two_fa_secret": secret}}
            )

            logger.info(f"2FA setup initiated for user: {username}")

            return True, "Scan QR code with your authenticator app", secret, qr_code

        except Exception as e:
            logger.error(f"2FA setup error: {e}")
            return False, f"2FA setup failed: {str(e)}", None, None

    def confirm_2fa_setup(self, username: str, token: str) -> Tuple[bool, str]:
        """
        Confirm 2FA setup by verifying first token
        Args:
            username: Username
            token: 6-digit TOTP token
        Returns:
            (success: bool, message: str)
        """
        try:
            user = self.users_collection.find_one({"username": username})

            if not user:
                return False, "User not found"

            if not user.get('two_fa_secret'):
                return False, "2FA setup not initiated"

            # Verify token
            if not self.two_fa.verify_totp(user['two_fa_secret'], token):
                return False, "Invalid code.  Please try again."

            # Enable 2FA
            self.users_collection.update_one(
                {"username": username},
                {"$set": {"two_fa_enabled": True}}
            )

            self._log_access(username, "2fa_enabled", status="success")
            logger.info(f"2FA enabled for user: {username}")

            return True, "2FA enabled successfully"

        except Exception as e:
            logger.error(f"2FA confirmation error: {e}")
            return False, f"2FA confirmation failed: {str(e)}"

    def disable_2fa(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Disable 2FA (requires password confirmation)
        Args:
            username: Username
            password: User password
        Returns:
            (success: bool, message: str)
        """
        try:
            user = self.users_collection.find_one({"username": username})

            if not user:
                return False, "User not found"

            # Verify password
            if not self.password_manager.verify_password(password, user['password_hash']):
                return False, "Invalid password"

            # Disable 2FA
            self.users_collection.update_one(
                {"username": username},
                {"$set": {
                    "two_fa_enabled": False,
                    "two_fa_secret": None
                }}
            )

            self._log_access(username, "2fa_disabled", status="success")
            logger.info(f"2FA disabled for user: {username}")

            return True, "2FA disabled successfully"

        except Exception as e:
            logger.error(f"2FA disable error: {e}")
            return False, f"Failed to disable 2FA: {str(e)}"

    def change_password(self, username: str, old_password: str,
                        new_password: str) -> Tuple[bool, str]:
        """
        Change user password
        Args:
            username: Username
            old_password: Current password
            new_password: New password
        Returns:
            (success: bool, message: str)
        """
        try:
            user = self.users_collection.find_one({"username": username})

            if not user:
                return False, "User not found"

            # Verify old password
            if not self.password_manager. verify_password(old_password, user['password_hash']):
                self._log_access(username, "password_change", status="failed",
                                 details="Invalid old password")
                return False, "Current password is incorrect"

            # Validate new password
            valid, msg = Validators.validate_password(new_password)
            if not valid:
                return False, msg

            # Hash new password
            new_password_hash = self.password_manager.hash_password(
                new_password)

            # Update password
            self.users_collection. update_one(
                {"username": username},
                {"$set": {"password_hash": new_password_hash}}
            )

            self._log_access(username, "password_change", status="success")
            logger. info(f"Password changed for user: {username}")

            return True, "Password changed successfully"

        except Exception as e:
            logger.error(f"Password change error: {e}")
            return False, f"Password change failed: {str(e)}"

    def _log_access(self, user: str, action: str, file_id: Optional[str] = None,
                    status: str = "success", details: Optional[str] = None):
        """Log access event"""
        try:
            log_entry = AccessLogModel. create_log(
                user, action, file_id, details, status)
            self.access_logs.insert_one(log_entry)
        except Exception as e:
            logger.error(f"Failed to log access event: {e}")

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user data by username"""
        user = self.users_collection.find_one({"username": username})
        if user:
            return UserModel. get_public_fields(user)
        return None

    def logout(self, username: str):
        """Log user logout"""
        self._log_access(username, "logout", status="success")
        logger.info(f"User logged out: {username}")
