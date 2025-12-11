"""
Two-Factor Authentication (2FA) implementation using TOTP
"""
import pyotp
import qrcode
from io import BytesIO  
from typing import Optional


class TwoFactorAuth:
    """Handle 2FA operations using TOTP"""

    @staticmethod
    def generate_secret() -> str:
        """
        Generate a new 2FA secret
        Returns: Base32 encoded secret
        """
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(username: str, secret: str, issuer: str = "Secure File Mgmt") -> str:
        """
        Generate TOTP URI for QR code
        Args:
            username: User's username
            secret: 2FA secret
            issuer: Application name
        Returns:
            TOTP URI string
        """
        return pyotp.totp. TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )

    @staticmethod
    def generate_qr_code(uri: str) -> BytesIO:
        """
        Generate QR code image for 2FA setup
        Args:
            uri: TOTP URI
        Returns:
            BytesIO object containing QR code image
        """
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        return buffer

    @staticmethod
    def verify_totp(secret: str, token: str) -> bool:
        """
        Verify TOTP token
        Args:
            secret: User's 2FA secret
            token: 6-digit token from authenticator app
        Returns:
            True if token is valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except Exception as e:
            print(f"2FA verification error: {e}")
            return False

    @staticmethod
    def get_current_totp(secret: str) -> str:
        """
        Get current TOTP (for testing purposes)
        Args:
            secret: 2FA secret
        Returns:
            Current 6-digit TOTP
        """
        totp = pyotp.TOTP(secret)
        return totp.now()
