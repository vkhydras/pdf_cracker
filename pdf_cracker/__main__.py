#!/usr/bin/env python3
"""
Main entry point for running the PDF Password Cracker as a module.
"""

import sys
from pdf_cracker.cli import main, display_examples

if __name__ == "__main__":
    if len(sys.argv) == 1:
        display_examples()
        sys.exit(1)
        
    sys.exit(main())