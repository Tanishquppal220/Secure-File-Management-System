"""
File encryption and decryption utilities using Fernet (AES)
"""
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from typing import Tuple


class FileEncryption:
    """Handle file encryption and decryption operations"""

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a new encryption key
        Returns: Encryption key as bytes
        """
        return Fernet.generate_key()

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive encryption key from password using PBKDF2HMAC
        Args:
            password: Password to derive key from
            salt: Salt for key derivation (generated if None)
        Returns:
            (key, salt) tuple
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, key: bytes) -> bool:
        """
        Encrypt a file using Fernet (AES)
        Args:
            input_path: Path to original file
            output_path: Path to save encrypted file
            key: Encryption key
        Returns:
            True if successful, False otherwise
        """
        try:
            fernet = Fernet(key)

            # Read original file
            with open(input_path, 'rb') as file:
                original_data = file.read()

            # Encrypt data
            encrypted_data = fernet.encrypt(original_data)

            # Write encrypted data
            with open(output_path, 'wb') as file:
                file.write(encrypted_data)

            return True

        except Exception as e:
            print(f"Encryption error: {e}")
            return False

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, key: bytes) -> bool:
        """
        Decrypt a file using Fernet (AES)
        Args:
            input_path: Path to encrypted file
            output_path: Path to save decrypted file
            key: Decryption key
        Returns:
            True if successful, False otherwise
        """
        try:
            fernet = Fernet(key)

            # Read encrypted file
            with open(input_path, 'rb') as file:
                encrypted_data = file.read()

            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_data)

            # Write decrypted data
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)

            return True

        except Exception as e:
            print(f"Decryption error: {e}")
            return False

    @staticmethod
    def encrypt_data(data: bytes, key: bytes) -> bytes:
        """
        Encrypt raw data
        Args:
            data: Data to encrypt
            key: Encryption key
        Returns:
            Encrypted data
        """
        fernet = Fernet(key)
        return fernet.encrypt(data)

    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt raw data
        Args:
            encrypted_data: Encrypted data
            key: Decryption key
        Returns:
            Decrypted data
        """
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data)
