"""
File management operations with encryption and security
"""
import os
import uuid
import shutil
from datetime import datetime
from typing import Optional, Tuple, Dict, List, BinaryIO
from pathlib import Path
from src.database.connection import db_connection
from src.database.models import FileModel, AccessLogModel, SecurityLogModel
from src.utils. encryption import FileEncryption
from src.utils.validators import Validators
from src.utils.logger import logger
from src.threat_detection.malware_scanner import MalwareScanner
import mimetypes
import streamlit as st


class FileManager:
    """Handle secure file operations with encryption"""

    def __init__(self):
        self.db = db_connection. db
        self.files_collection = self.db. files
        self.access_logs = self.db.access_logs
        self.security_logs = self.db.security_logs

        # Directories
        self.upload_dir = Path("uploads")
        self.encrypted_dir = Path("encrypted_files")

        # Create directories if they don't exist
        self.upload_dir.mkdir(exist_ok=True)
        self.encrypted_dir.mkdir(exist_ok=True)

        # File size limit (from env or default 50MB)
        self.max_file_size = int(
            st.secrets['app']['MAX_FILE_SIZE_MB']) * 1024 * 1024

        # Allowed file types
        allowed_types = st.secrets['app']['ALLOWED_FILE_TYPES']
        self.allowed_extensions = [ext.strip()
                                   for ext in allowed_types.split(',')]

        # Malware scanner
        self.malware_scanner = MalwareScanner()

    def upload_file(self, file_obj: BinaryIO, filename: str, owner: str,
                    tags: List[str] = None, scan_malware: bool = True, force_scan: bool = False) -> Tuple[bool, str, Optional[str]]:
        """
        Upload and encrypt a file

        Args:
            file_obj: File object (from Streamlit or similar)
            filename: Original filename
            owner: Username of file owner
            tags: Optional list of tags
            scan_malware: Whether to scan for malware
            force_scan: Whether to force a fresh malware scan (ignore cache)

        Returns:
            (success: bool, message: str, file_id: Optional[str])
        """
        try:
            # Sanitize filename
            filename = Validators.sanitize_filename(filename)

            # Validate filename
            valid, msg = Validators.validate_filename(
                filename, self.allowed_extensions)
            if not valid:
                return False, msg, None

            # Get file size
            file_obj.seek(0, 2)  # Seek to end
            file_size = file_obj.tell()
            file_obj.seek(0)  # Reset to beginning

            # Validate file size
            valid, msg = Validators.validate_file_size(
                file_size, self.max_file_size // (1024 * 1024))
            if not valid:
                return False, msg, None

            # Generate unique file ID
            file_id = str(uuid.uuid4())

            # Save temporary file
            temp_path = self. upload_dir / f"temp_{file_id}_{filename}"
            with open(temp_path, 'wb') as f:
                f.write(file_obj.read())

            logger.info(
                f"File uploaded temporarily: {filename} ({file_size} bytes)")

            # Malware scan
            if scan_malware:
                logger.info("Starting malware scan...")
                is_safe, scan_result = self.malware_scanner. scan_file(
                    str(temp_path), force_scan)

                if not is_safe:
                    # Log security event
                    self._log_security_event(
                        "malware_detected",
                        scan_result. get('threat_level', 'high'),
                        owner,
                        file_id,
                        f"Malware detected in file: {filename}"
                    )

                    # Delete temp file
                    temp_path.unlink()

                    return False, f"⚠️ Security threat detected!  {scan_result. get('message')}", None

                logger. info(
                    f"Malware scan passed: {scan_result.get('message')}")

            # Generate encryption key
            encryption_key = FileEncryption.generate_key()

            # Encrypt file
            encrypted_path = self. encrypted_dir / f"{file_id}. enc"
            success = FileEncryption.encrypt_file(
                str(temp_path), str(encrypted_path), encryption_key)

            if not success:
                temp_path.unlink()
                return False, "Failed to encrypt file", None

            logger.info(f"File encrypted: {encrypted_path}")

            # Get MIME type
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type is None:
                mime_type = "application/octet-stream"

            # Create file document
            file_doc = FileModel. create_file(
                file_id=file_id,
                filename=filename,
                owner=owner,
                encrypted_path=str(encrypted_path),
                encryption_key=encryption_key. decode('utf-8'),
                file_size=file_size,
                mime_type=mime_type
            )

            # Add tags
            if tags:
                file_doc['tags'] = tags

            # Add scan result
            if scan_malware:
                file_doc['threat_scan_status'] = 'clean'
                file_doc['threat_scan_result'] = scan_result

            # Save to database
            self.files_collection.insert_one(file_doc)

            # Delete temp file
            temp_path. unlink()

            # Log access
            self._log_access(owner, "upload", file_id,
                             f"Uploaded file: {filename}")

            logger.info(f"File upload complete: {file_id}")

            return True, "File uploaded and encrypted successfully", file_id

        except Exception as e:
            logger.error(f"File upload error: {e}")
            return False, f"Upload failed: {str(e)}", None

    def download_file(self, file_id: str, username: str) -> Tuple[bool, str, Optional[bytes], Optional[str]]:
        """
        Download and decrypt a file

        Args:
            file_id: File ID
            username: Username requesting download

        Returns:
            (success: bool, message: str, file_data: Optional[bytes], filename: Optional[str])
        """
        try:
            # Get file metadata
            file_doc = self. files_collection.find_one({"file_id": file_id})

            if not file_doc:
                return False, "File not found", None, None

            # Check if deleted
            if file_doc.get('is_deleted', False):
                return False, "File has been deleted", None, None

            # Check permissions
            if not self._check_permission(file_doc, username, 'read'):
                return False, "You don't have permission to download this file", None, None

            # Get encryption key
            encryption_key = file_doc['encryption_key']. encode('utf-8')
            encrypted_path = file_doc['encrypted_path']

            # Check if encrypted file exists
            if not Path(encrypted_path).exists():
                return False, "Encrypted file not found on server", None, None

            # Decrypt file to temporary location
            temp_decrypted = self. upload_dir / f"temp_dec_{file_id}"
            success = FileEncryption.decrypt_file(
                encrypted_path, str(temp_decrypted), encryption_key)

            if not success:
                return False, "Failed to decrypt file", None, None

            # Read decrypted data
            with open(temp_decrypted, 'rb') as f:
                file_data = f.read()

            # Delete temporary decrypted file
            temp_decrypted.unlink()

            # Update access metadata
            self. files_collection.update_one(
                {"file_id": file_id},
                {
                    "$set": {"last_accessed": datetime.utcnow()},
                    "$inc": {"access_count": 1}
                }
            )

            # Log access
            self._log_access(username, "download", file_id,
                             f"Downloaded file: {file_doc['filename']}")

            logger.info(f"File downloaded: {file_id} by {username}")

            return True, "File downloaded successfully", file_data, file_doc['filename']

        except Exception as e:
            logger.error(f"File download error: {e}")
            return False, f"Download failed: {str(e)}", None, None

    def share_file(self, file_id: str, owner: str, shared_with: str,
                   permissions: List[str]) -> Tuple[bool, str]:
        """
        Share a file with another user

        Args:
            file_id: File ID
            owner: File owner username
            shared_with: Username to share with
            permissions: List of permissions (e.g., ['read', 'download'])

        Returns:
            (success: bool, message: str)
        """
        try:
            # Get file
            file_doc = self.files_collection.find_one({"file_id": file_id})

            if not file_doc:
                return False, "File not found"

            # Check ownership
            if file_doc['owner'] != owner:
                return False, "Only the file owner can share files"

            # Check if already shared with this user
            shared_list = file_doc.get('shared_with', [])
            for shared in shared_list:
                if shared['username'] == shared_with:
                    return False, f"File is already shared with {shared_with}"

            # Add shared user
            shared_entry = FileModel.add_shared_user(shared_with, permissions)

            self.files_collection.update_one(
                {"file_id": file_id},
                {
                    "$set": {"is_shared": True},
                    "$push": {"shared_with": shared_entry}
                }
            )

            # Log access
            self._log_access(owner, "share", file_id,
                             f"Shared file with {shared_with}, permissions: {permissions}")

            logger.info(f"File shared: {file_id} with {shared_with}")

            return True, f"File shared successfully with {shared_with}"

        except Exception as e:
            logger.error(f"File share error: {e}")
            return False, f"Sharing failed: {str(e)}"

    def unshare_file(self, file_id: str, owner: str, revoke_user: str) -> Tuple[bool, str]:
        """
        Revoke file sharing access from a user

        Args:
            file_id: File ID
            owner: File owner username
            revoke_user: Username to revoke access from

        Returns:
            (success: bool, message: str)
        """
        try:
            # Get file
            file_doc = self.files_collection.find_one({"file_id": file_id})

            if not file_doc:
                return False, "File not found"

            # Check ownership
            if file_doc['owner'] != owner:
                return False, "Only the file owner can revoke access"

            # Check if user exists in shared_with list
            shared_list = file_doc.get('shared_with', [])
            user_found = False
            for shared in shared_list:
                if shared['username'] == revoke_user:
                    user_found = True
                    break

            if not user_found:
                return False, f"File is not shared with {revoke_user}"

            # Remove user from shared_with list
            self.files_collection.update_one(
                {"file_id": file_id},
                {"$pull": {"shared_with": {"username": revoke_user}}}
            )

            # Update is_shared flag if no more users
            updated_file = self.files_collection.find_one({"file_id": file_id})
            if not updated_file.get('shared_with', []):
                self.files_collection.update_one(
                    {"file_id": file_id},
                    {"$set": {"is_shared": False}}
                )

            # Log access
            self._log_access(owner, "unshare", file_id,
                             f"Revoked access from {revoke_user}")

            logger.info(f"File unshared: {file_id} from {revoke_user}")

            return True, f"Access revoked from {revoke_user}"

        except Exception as e:
            logger.error(f"File unshare error: {e}")
            return False, f"Revoke failed: {str(e)}"

    def get_file_metadata(self, file_id: str, username: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Get file metadata

        Args:
            file_id: File ID
            username: Username requesting metadata

        Returns:
            (success: bool, message: str, metadata: Optional[Dict])
        """
        try:
            file_doc = self.files_collection.find_one({"file_id": file_id})

            if not file_doc:
                return False, "File not found", None

            # Check permissions
            if not self._check_permission(file_doc, username, 'read'):
                return False, "You don't have permission to view this file", None

            # Build metadata (exclude sensitive data)
            metadata = {
                "file_id": file_doc['file_id'],
                "filename": file_doc['filename'],
                "owner": file_doc['owner'],
                "file_size": file_doc['file_size'],
                "mime_type": file_doc['mime_type'],
                "uploaded_at": file_doc['uploaded_at'],
                "last_accessed": file_doc. get('last_accessed'),
                "last_modified": file_doc.get('last_modified'),
                "access_count": file_doc. get('access_count', 0),
                "is_shared": file_doc.get('is_shared', False),
                "tags": file_doc.get('tags', []),
                "threat_scan_status": file_doc.get('threat_scan_status', 'unknown')
            }

            # Add sharing info if user is owner
            if file_doc['owner'] == username:
                metadata['shared_with'] = file_doc. get('shared_with', [])

            return True, "Metadata retrieved", metadata

        except Exception as e:
            logger.error(f"Get metadata error: {e}")
            return False, f"Failed to get metadata: {str(e)}", None

    def list_user_files(self, username: str) -> List[Dict]:
        """
        List all files owned by or shared with a user

        Args:
            username: Username

        Returns:
            List of file metadata dictionaries
        """
        try:
            # Find owned files
            owned_files = list(self.files_collection.find({
                "owner": username,
                "is_deleted": False
            }))

            # Find shared files
            shared_files = list(self.files_collection.find({
                "shared_with.username": username,
                "is_deleted": False
            }))

            # Combine and format
            all_files = []

            for file_doc in owned_files:
                all_files.append({
                    "file_id": file_doc['file_id'],
                    "filename": file_doc['filename'],
                    "owner": file_doc['owner'],
                    "file_size": file_doc['file_size'],
                    "uploaded_at": file_doc['uploaded_at'],
                    "is_shared": file_doc.get('is_shared', False),
                    "access_type": "owner"
                })

            for file_doc in shared_files:
                # Find user's permissions
                permissions = []
                for shared in file_doc.get('shared_with', []):
                    if shared['username'] == username:
                        permissions = shared['permissions']
                        break

                all_files.append({
                    "file_id": file_doc['file_id'],
                    "filename": file_doc['filename'],
                    "owner": file_doc['owner'],
                    "file_size": file_doc['file_size'],
                    "uploaded_at": file_doc['uploaded_at'],
                    "is_shared": True,
                    "access_type": "shared",
                    "permissions": permissions
                })

            # Sort by upload date (newest first)
            all_files.sort(key=lambda x: x['uploaded_at'], reverse=True)

            return all_files

        except Exception as e:
            logger.error(f"List files error: {e}")
            return []

    def delete_file(self, file_id: str, username: str) -> Tuple[bool, str]:
        """
        Delete a file (soft delete)

        Args:
            file_id: File ID
            username: Username requesting deletion

        Returns:
            (success: bool, message: str)
        """
        try:
            file_doc = self.files_collection.find_one({"file_id": file_id})

            if not file_doc:
                return False, "File not found"

            # Only owner can delete
            if file_doc['owner'] != username:
                return False, "Only the file owner can delete files"

            # Soft delete (mark as deleted)
            self.files_collection.update_one(
                {"file_id": file_id},
                {"$set": {"is_deleted": True}}
            )

            # Log access
            self._log_access(username, "delete", file_id,
                             f"Deleted file: {file_doc['filename']}")

            logger.info(f"File deleted: {file_id} by {username}")

            return True, "File deleted successfully"

        except Exception as e:
            logger.error(f"Delete file error: {e}")
            return False, f"Delete failed: {str(e)}"

    def _check_permission(self, file_doc: Dict, username: str, permission: str) -> bool:
        """Check if user has permission for a file"""
        # Owner has all permissions
        if file_doc['owner'] == username:
            return True

        # Check shared permissions
        for shared in file_doc.get('shared_with', []):
            if shared['username'] == username:
                return permission in shared['permissions']

        return False

    def _log_access(self, user: str, action: str, file_id: Optional[str] = None,
                    details: Optional[str] = None):
        """Log file access event"""
        try:
            log_entry = AccessLogModel.create_log(
                user, action, file_id, details, "success")
            self.access_logs.insert_one(log_entry)
        except Exception as e:
            logger.error(f"Failed to log access: {e}")

    def _log_security_event(self, event_type: str, threat_level: str,
                            user: Optional[str] = None, file_id: Optional[str] = None,
                            details: str = ""):
        """Log security event"""
        try:
            log_entry = SecurityLogModel.create_log(
                event_type, threat_level, user, file_id, details)
            self.security_logs.insert_one(log_entry)
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
