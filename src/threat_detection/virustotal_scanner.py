"""
VirusTotal malware scanner integration
"""
import requests
import time
import hashlib
from typing import Dict, Tuple, Optional
from pathlib import Path
import os
import streamlit as st
from src.utils.logger import logger


class VirusTotalScanner:
    """VirusTotal API integration for malware scanning"""

    def __init__(self):
        self.api_key = st.secrets['api']['VIRUSTOTAL_API_KEY']
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key
        }

        if not self.api_key:
            logger.warning(
                "VirusTotal API key not found.Malware scanning disabled.")

    def scan_file(self, file_path: str, force_scan: bool = False) -> Tuple[bool, Dict]:
        """
        Scan a file for malware using VirusTotal

        Args:
            file_path: Path to file to scan
            force_scan: Whether to force a fresh scan (ignore cache)

        Returns:
            (is_safe: bool, result: Dict)
        """
        if not self.api_key:
            return True, {
                "status": "skipped",
                "message": "VirusTotal API key not configured",
                "threat_level": "unknown",
                "is_safe": True
            }

        try:
            # Step 1: Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            logger.info(f"Scanning file with hash: {file_hash}")

            # Step 2: Check if file was already scanned
            if not force_scan:
                existing_result = self._get_file_report(file_hash)

                if existing_result:
                    logger.info("File already scanned, using cached results")
                    return self._parse_scan_result(existing_result)

            # Step 3: Upload and scan file
            logger.info("Uploading file for scanning...")
            scan_result = self._upload_file(file_path)

            if not scan_result:
                return False, {
                    "status": "error",
                    "message": "Failed to upload file",
                    "threat_level": "unknown",
                    "is_safe": False
                }

            # Step 4: Get analysis results
            analysis_id = scan_result.get('data', {}).get('id')

            if analysis_id:
                logger.info(f"File uploaded.Analysis ID: {analysis_id}")
                time.sleep(5)  # Wait for initial scan

                analysis_result = self._get_analysis_result(analysis_id)

                if analysis_result is None:
                    logger.error("Failed to get analysis result")
                    return False, {
                        "status": "timeout",
                        "message": "Scan timed out or failed.Please try again later.",
                        "threat_level": "unknown",
                        "is_safe": False
                    }

                return self._parse_scan_result(analysis_result)
            else:
                logger.error("No analysis ID returned from upload")
                return False, {
                    "status": "error",
                    "message": "Failed to initiate scan - no analysis ID",
                    "threat_level": "unknown",
                    "is_safe": False
                }

            return True, {
                "status": "pending",
                "message": "Scan initiated, results pending",
                "threat_level": "unknown",
                "is_safe": True
            }

        except Exception as e:
            logger.error(f"VirusTotal scan error: {e}")
            return False, {
                "status": "error",
                "message": str(e),
                "threat_level": "unknown",
                "is_safe": False
            }

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def _get_file_report(self, file_hash: str) -> Optional[Dict]:
        """Get existing file report by hash"""
        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code == 200:
                return response.json()

            return None

        except Exception as e:
            logger.error(f"Error getting file report: {e}")
            return None

    def _upload_file(self, file_path: str) -> Optional[Dict]:
        """Upload file to VirusTotal for scanning"""
        try:
            url = f"{self.base_url}/files"

            with open(file_path, 'rb') as f:
                files = {'file': (Path(file_path).name, f)}
                response = requests.post(
                    url,
                    headers=self.headers,
                    files=files,
                    timeout=60
                )

            if response.status_code == 200:
                return response.json()

            logger.error(
                f"Upload failed: {response.status_code} - {response.text}")
            return None

        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            return None

    def _get_analysis_result(self, analysis_id: str, max_attempts: int = 20) -> Optional[Dict]:
        """Get analysis result by ID (with retry)"""
        try:
            url = f"{self.base_url}/analyses/{analysis_id}"

            for attempt in range(max_attempts):
                response = requests.get(url, headers=self.headers, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    status = data.get('data', {}).get(
                        'attributes', {}).get('status')

                    if status == 'completed':
                        logger.info("Scan completed successfully")
                        return data

                    logger.info(
                        f"Scan in progress...(attempt {attempt + 1}/{max_attempts}) - Status: {status}")
                    time.sleep(3)
                else:
                    logger.error(
                        f"Error getting analysis: {response.status_code} - {response.text}")
                    break

            logger.warning(
                f"Scan did not complete after {max_attempts} attempts")
            return None

        except Exception as e:
            logger.error(f"Error getting analysis result: {e}")
            return None

    def _parse_scan_result(self, result: Dict) -> Tuple[bool, Dict]:
        """Parse VirusTotal scan result"""
        try:
            # Validate result structure
            if not result or 'data' not in result:
                logger.error("Invalid scan result: missing data")
                return False, {
                    "status": "error",
                    "message": "Invalid scan result structure",
                    "threat_level": "unknown",
                    "is_safe": False
                }

            attributes = result.get('data', {}).get('attributes', {})
            if not attributes:
                logger.error("Invalid scan result: missing attributes")
                return False, {
                    "status": "error",
                    "message": "Invalid scan result attributes",
                    "threat_level": "unknown",
                    "is_safe": False
                }

            # Handle both file report (last_analysis_stats) and analysis report (stats)
            stats = attributes.get(
                'last_analysis_stats') or attributes.get('stats', {})

            if not stats:
                logger.warning("No stats found in scan result")
                return False, {
                    "status": "error",
                    "message": "No scan statistics available",
                    "threat_level": "unknown",
                    "is_safe": False
                }

            # Get detection counts
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            harmless = stats.get('harmless', 0)

            total_scans = malicious + suspicious + undetected + harmless

            # Determine threat level
            if malicious > 0:
                threat_level = "high" if malicious > 3 else "medium"
                is_safe = False
            elif suspicious > 0:
                threat_level = "low"
                is_safe = False
            else:
                threat_level = "none"
                is_safe = True

            # Build result
            scan_info = {
                "status": "completed",
                "is_safe": is_safe,
                "threat_level": threat_level,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "harmless": harmless,
                "total_scans": total_scans,
                "scan_date": attributes.get('last_analysis_date'),
                "message": self._get_threat_message(malicious, suspicious)
            }

            logger.info(f"Scan result: {scan_info['message']}")

            return is_safe, scan_info

        except Exception as e:
            logger.error(f"Error parsing scan result: {e}")
            return False, {
                "status": "error",
                "message": "Failed to parse scan results",
                "threat_level": "unknown",
                "is_safe": False
            }

    def _get_threat_message(self, malicious: int, suspicious: int) -> str:
        """Generate threat message based on detection counts"""
        if malicious > 0:
            return f"⚠️ THREAT DETECTED!  {malicious} antivirus engines detected malware"
        elif suspicious > 0:
            return f"⚠️ Suspicious file. {suspicious} engines flagged as suspicious"
        else:
            return "✅ No threats detected. File appears safe."
