"""
Password hashing and verification using bcrypt
"""
import bcrypt


class PasswordManager:
    """Handle password hashing and verification"""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt
        Args:
            password: Plain text password
        Returns:
            Hashed password as string
        """
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        Args:
            password: Plain text password
            hashed_password: Hashed password
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password. encode('utf-8')
            )
        except Exception as e:
            print(f"Password verification error: {e}")
            return False
