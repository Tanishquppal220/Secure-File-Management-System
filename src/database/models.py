"""
Database models and schemas
"""
from datetime import datetime
from typing import List, Dict
from enum import Enum


class UserRole(Enum):
    """User role enumeration"""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"


class FilePermission(Enum):
    """File permission enumeration"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SHARE = "share"


class ThreatLevel(Enum):
    """Threat level enumeration"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UserModel:
    """User data model"""

    @staticmethod
    def create_user(username: str, email: str, password_hash: str,
                    role: str = "user", two_fa_enabled: bool = False) -> Dict:
        """
        Create user document
        Returns: User document dictionary
        """
        return {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "role": role,
            "two_fa_enabled": two_fa_enabled,
            "two_fa_secret": None,
            "created_at": datetime.now(datetime.timezone.utc),
            "last_login": None,
            "is_active": True,
            "failed_login_attempts": 0,
            "account_locked_until": None
        }

    @staticmethod
    def get_public_fields(user_doc: Dict) -> Dict:
        """
        Get safe user fields (exclude sensitive data)
        Returns: Public user data
        """
        return {
            "username": user_doc. get("username"),
            "email": user_doc.get("email"),
            "role": user_doc.get("role"),
            "two_fa_enabled": user_doc.get("two_fa_enabled", False),
            "created_at": user_doc.get("created_at"),
            "last_login": user_doc. get("last_login")
        }


class FileModel:
    """File data model"""

    @staticmethod
    def create_file(file_id: str, filename: str, owner: str,
                    encrypted_path: str, encryption_key: str,
                    file_size: int, mime_type: str) -> Dict:
        """
        Create file document
        Returns: File document dictionary
        """
        return {
            "file_id": file_id,
            "filename": filename,
            "owner": owner,
            "encrypted_path": encrypted_path,
            "encryption_key": encryption_key,
            "file_size": file_size,
            "mime_type": mime_type,
            "uploaded_at": datetime.utcnow(),
            "last_accessed": datetime.utcnow(),
            "last_modified": datetime.utcnow(),
            "access_count": 0,
            "is_shared": False,
            "shared_with": [],
            "tags": [],
            "is_deleted": False,
            "threat_scan_status": "pending",
            "threat_scan_result": None
        }

    @staticmethod
    def add_shared_user(username: str, permissions: List[str]) -> Dict:
        """
        Create shared user entry
        Returns: Shared user document
        """
        return {
            "username": username,
            "permissions": permissions,
            "shared_at": datetime.utcnow()
        }


class AccessLogModel:
    """Access log model"""

    @staticmethod
    def create_log(user: str, action: str, file_id: str = None,
                   details: str = None, status: str = "success") -> Dict:
        """
        Create access log entry
        Returns: Log document
        """
        return {
            "timestamp": datetime.utcnow(),
            "user": user,
            "action": action,
            "file_id": file_id,
            "details": details,
            "status": status,
            "ip_address": None
        }


class SecurityLogModel:
    """Security event log model"""

    @staticmethod
    def create_log(event_type: str, threat_level: str, user: str = None,
                   file_id: str = None, details: str = "") -> Dict:
        """
        Create security log entry
        Returns: Security log document
        """
        return {
            "timestamp": datetime. utcnow(),
            "event_type": event_type,
            "threat_level": threat_level,
            "user": user,
            "file_id": file_id,
            "details": details,
            "resolved": False,
            "resolved_at": None,
            "resolved_by": None
        }
