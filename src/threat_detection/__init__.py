"""
Threat detection module
"""
from .malware_scanner import MalwareScanner
from .virustotal_scanner import VirusTotalScanner

__all__ = ['MalwareScanner', 'VirusTotalScanner']
