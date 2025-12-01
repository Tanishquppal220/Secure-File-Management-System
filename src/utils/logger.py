"""
Logging utilities for the application
"""
import logging
import os
from datetime import datetime
from pathlib import Path


class AppLogger:
    """Application logger with file and console output"""

    def __init__(self, name: str = "secure_file_mgmt"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        # Prevent duplicate handlers
        if self.logger.handlers:
            return

        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        # File handler - detailed logs
        log_file = log_dir / f"app_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)

        # Console handler - info and above
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging. Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers
        self.logger.addHandler(file_handler)
        self. logger.addHandler(console_handler)

    def debug(self, message: str):
        """Log debug message"""
        self.logger. debug(message)

    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)

    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)

    def error(self, message: str):
        """Log error message"""
        self. logger.error(message)

    def critical(self, message: str):
        """Log critical message"""
        self.logger. critical(message)


# Global logger instance
logger = AppLogger()
