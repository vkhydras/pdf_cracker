"""
Logging utilities for the PDF Password Cracker.
"""

import logging
import os
import sys
from typing import Optional


class Logger:
    """Custom logger for PDF password cracker"""
    
    # Log levels
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL
    
    def __init__(self, name: str = "pdf_cracker", log_file: Optional[str] = None, 
                 level: int = logging.INFO, console: bool = True):
        """Initialize the logger
        
        Args:
            name: Logger name
            log_file: Optional file to log to
            level: Logging level
            console: Whether to log to console
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False
        
        # Clear any existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Add console handler if requested
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # Add file handler if log file is specified
        if log_file:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
                
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def get_logger(self):
        """Get the logger instance"""
        return self.logger


# Create a default logger for simple usage
default_logger = Logger().get_logger()


def debug(msg: str, *args, **kwargs):
    """Log a debug message"""
    default_logger.debug(msg, *args, **kwargs)


def info(msg: str, *args, **kwargs):
    """Log an info message"""
    default_logger.info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs):
    """Log a warning message"""
    default_logger.warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs):
    """Log an error message"""
    default_logger.error(msg, *args, **kwargs)


def critical(msg: str, *args, **kwargs):
    """Log a critical message"""
    default_logger.critical(msg, *args, **kwargs)