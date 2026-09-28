"""
Password hashing and verification using bcrypt with worker thread offload
"""
import bcrypt
from concurrent.futures import ThreadPoolExecutor

# Bounded thread pool so CPU-intensive bcrypt hashing/verification releases the GIL
# and avoids starving the event loop or blocking concurrent operations.
_bcrypt_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="bcrypt-worker")


class PasswordManager:
    """Handle password hashing and verification"""

    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash a password using bcrypt (work factor 12) offloaded to thread pool
        Args:
            password: Plain text password
        Returns:
            Hashed password as string
        """
        salt = bcrypt.gensalt(rounds=12)
        future = _bcrypt_executor.submit(bcrypt.hashpw, password.encode('utf-8'), salt)
        return future.result().decode('utf-8')

    @classmethod
    def verify_password(cls, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash offloaded to thread pool
        Args:
            password: Plain text password
            hashed_password: Hashed password
        Returns:
            True if password matches, False otherwise
        """
        try:
            future = _bcrypt_executor.submit(
                bcrypt.checkpw,
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
            return future.result()
        except Exception as e:
            print(f"Password verification error: {e}")
            return False
