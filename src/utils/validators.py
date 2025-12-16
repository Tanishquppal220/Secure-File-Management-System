"""
Input validation utilities
"""
import re
from typing import Tuple, List


class Validators:
    """Input validation functions"""

    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """
        Validate username format
        Rules: 3-20 chars, alphanumeric + underscore, must start with letter
        Returns: (is_valid, message)
        """
        if not username:
            return False, "Username cannot be empty"

        if len(username) < 3 or len(username) > 20:
            return False, "Username must be 3-20 characters long"

        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', username):
            return False, "Username must start with a letter and contain only letters, numbers, and underscores"

        return True, "Valid username"

    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """
        Validate email format
        Returns: (is_valid, message)
        """
        if not email:
            return False, "Email cannot be empty"

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return False, "Invalid email format"

        return True, "Valid email"

    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """
        Validate password strength
        Rules: Min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special char
        Returns: (is_valid, message)
        """
        if not password:
            return False, "Password cannot be empty"

        if len(password) < 8:
            return False, "Password must be at least 8 characters long"

        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"

        if not re. search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"

        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"

        if not re.search(r'[! @#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"

        return True, "Strong password"

    @staticmethod
    def validate_filename(filename: str, allowed_extensions: List[str] = None) -> Tuple[bool, str]:
        """
        Validate filename for security
        Returns: (is_valid, message)
        """
        if not filename:
            return False, "Filename cannot be empty"

        # Check for path traversal attempts
        if '. .' in filename or '/' in filename or '\\' in filename:
            return False, "Invalid filename: path traversal detected"

        # Check extension if allowed_extensions provided
        if allowed_extensions:
            ext = filename.split('.')[-1].lower() if '.' in filename else ''
            if ext not in allowed_extensions:
                return False, f"File type . {ext} not allowed.  Allowed types: {', '.join(allowed_extensions)}"

        return True, "Valid filename"

    @staticmethod
    def validate_file_size(file_size: int, max_size_mb: int = 50) -> Tuple[bool, str]:
        """
        Validate file size
        Returns: (is_valid, message)
        """
        max_size_bytes = max_size_mb * 1024 * 1024

        if file_size > max_size_bytes:
            return False, f"File size exceeds maximum allowed size of {max_size_mb}MB"

        if file_size == 0:
            return False, "File is empty"

        return True, "Valid file size"

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename by removing dangerous characters
        Returns: Sanitized filename
        """
        # Remove path separators and null bytes
        filename = filename.replace(
            '/', '_').replace('\\', '_').replace('\0', '')

        # Remove leading/trailing spaces and dots
        filename = filename.strip('. ')

        # Replace multiple spaces with single space
        filename = re.sub(r'\s+', ' ', filename)

        return filename
