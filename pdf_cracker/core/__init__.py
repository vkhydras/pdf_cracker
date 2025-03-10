"""
Core functionality for the PDF Password Cracker.
"""

from .cracker import PDFCracker
from .generator import (
    PasswordGenerator, 
    NumericPasswordGenerator,
    AlphabeticPasswordGenerator,
    AlphanumericPasswordGenerator,
    DictionaryPasswordGenerator,
    CompositePasswordGenerator,
    SmartPasswordGenerator
)
from .state import StateManager
from .worker import attempt_password, worker_process, PasswordTester