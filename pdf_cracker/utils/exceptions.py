"""
Custom exceptions for the PDF Password Cracker.
"""

class PDFCrackerError(Exception):
    """Base exception for PDF cracker errors"""
    pass


class PDFNotFoundError(PDFCrackerError):
    """PDF file not found"""
    pass


class PDFNotEncryptedError(PDFCrackerError):
    """PDF is not encrypted"""
    pass


class InvalidPasswordGeneratorError(PDFCrackerError):
    """Invalid password generator configuration"""
    pass


class StateIOError(PDFCrackerError):
    """Error reading or writing state file"""
    pass


class WorkerError(PDFCrackerError):
    """Error in worker process"""
    pass


class ConfigError(PDFCrackerError):
    """Error in configuration"""
    pass