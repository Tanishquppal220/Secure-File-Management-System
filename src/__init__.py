"""
Secure File Management System
Main package initialization
"""

__version__ = "1.0. 0"
__author__ = "Tanishq Uppal"

# Import main components
from src.auth import AuthManager
from src.file_ops import FileManager
from src.threat_detection import MalwareScanner
from src. database import db_connection

__all__ = [
    'AuthManager',
    'FileManager',
    'MalwareScanner',
    'db_connection'
]
