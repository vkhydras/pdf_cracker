"""
Advanced PDF Password Cracker

A modular tool for cracking password-protected PDF files using various strategies.
"""

from pdf_cracker.core.cracker import PDFCracker
from pdf_cracker.core.generator import (
    PasswordGenerator,
    NumericPasswordGenerator,
    AlphabeticPasswordGenerator,
    AlphanumericPasswordGenerator,
    DictionaryPasswordGenerator,
    CompositePasswordGenerator
)

__version__ = "0.1.0"