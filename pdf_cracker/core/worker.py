"""
Worker module for the PDF Password Cracker.

This module contains functions for worker processes that try passwords in parallel.
"""

import multiprocessing
from typing import List, Optional
import pikepdf
import time


def attempt_password(pdf_path: str, password: str) -> bool:
    """Try a single password on the PDF
    
    Args:
        pdf_path: Path to the PDF file
        password: Password to try
        
    Returns:
        True if password is correct, False otherwise
    """
    try:
        with pikepdf.open(pdf_path, password=password) as pdf:
            return True
    except pikepdf.PasswordError:
        return False
    except Exception as e:
        print(f"Error trying password {password}: {str(e)}")
        return False


def worker_process(pdf_path: str, 
                  passwords: List[str], 
                  result_queue: multiprocessing.Queue,
                  progress_queue: multiprocessing.Queue,
                  report_frequency: int = 100,
                  worker_id: Optional[int] = None) -> None:
    """Worker process that tries a batch of passwords
    
    Args:
        pdf_path: Path to the PDF file
        passwords: List of passwords to try
        result_queue: Queue to report found password
        progress_queue: Queue to report progress
        report_frequency: How often to report progress
        worker_id: Optional ID for this worker
    """
    total = len(passwords)
    start_time = time.time()
    last_report_time = start_time
    
    # Create an identifying prefix for this worker
    worker_prefix = f"Worker-{worker_id}: " if worker_id is not None else ""
    
    for i, password in enumerate(passwords):
        # Update progress based on frequency (or every 0.5 seconds)
        current_time = time.time()
        if i % report_frequency == 0 or i == total - 1 or current_time - last_report_time >= 0.5:
            progress = min(i % report_frequency + 1 if i % report_frequency > 0 else report_frequency, 
                          total - (i - i % report_frequency))
            progress_queue.put(progress)
            last_report_time = current_time
        
        # Try the password
        if attempt_password(pdf_path, password):
            print(f"{worker_prefix}Found password: {password}")
            result_queue.put(password)
            return
    
    # Signal completion of batch with no success
    result_queue.put(None)
    print(f"{worker_prefix}Completed {total} passwords in {time.time() - start_time:.2f} seconds")


class PasswordTester:
    """Class for testing passwords against a PDF without multiprocessing
    
    Useful for testing and debugging without the complexity of multiprocessing
    """
    
    def __init__(self, pdf_path: str):
        """Initialize with PDF path"""
        self.pdf_path = pdf_path
        
    def test_passwords(self, passwords: List[str], callback=None) -> Optional[str]:
        """Test a list of passwords
        
        Args:
            passwords: List of passwords to try
            callback: Optional callback function called with (index, total) after each password
            
        Returns:
            The correct password if found, None otherwise
        """
        total = len(passwords)
        for i, password in enumerate(passwords):
            if callback and i % 100 == 0:
                callback(i, total)
                
            if attempt_password(self.pdf_path, password):
                return password
                
        return None