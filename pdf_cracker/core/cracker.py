"""
Main cracker class for the PDF Password Cracker.

This module provides the main PDFCracker class that coordinates the cracking process.
"""

import multiprocessing
import os
import time
import signal
from typing import Optional, Dict, Any, List, Tuple, Type, Union, Callable
import pikepdf
from tqdm import tqdm

from .generator import (
    PasswordGenerator, 
    NumericPasswordGenerator, 
    SmartPasswordGenerator,
    AlphabeticPasswordGenerator,
    AlphanumericPasswordGenerator
)
from .state import StateManager
from .worker import worker_process
from pdf_cracker.utils.exceptions import PDFNotFoundError, PDFNotEncryptedError
from pdf_cracker.utils.logger import Logger


class PDFCracker:
    """Main class for cracking PDF passwords"""
    
    def __init__(self, pdf_path: str, state_dir: Optional[str] = None, 
                 processes: Optional[int] = None, logger=None):
        """Initialize with PDF path, optional state directory, and process count
        
        Args:
            pdf_path: Path to the PDF file
            state_dir: Optional directory to store state files
            processes: Number of processes to use (default: CPU count - 1)
            logger: Optional logger instance
        """
        if not os.path.exists(pdf_path):
            raise PDFNotFoundError(f"PDF file not found: {pdf_path}")
            
        self.pdf_path = pdf_path
        self.state_manager = StateManager(pdf_path, state_dir)
        
        # Determine number of processes to use
        self.processes = processes or max(1, multiprocessing.cpu_count() - 1)
        
        # Set up logging
        self.logger = logger or Logger(
            name=f"pdf_cracker.{os.path.basename(pdf_path)}",
            level=20  # INFO
        ).get_logger()
        
        # Set default values
        self.batch_size = 10000
        self.save_interval = 5  # seconds
        self.progress_bar = None
        self.active_processes = []
        self.current_position = 0
        self.total_passwords_tried = 0
        self.start_time = 0
        
        # Signal handling
        self.original_sigint_handler = None
        
    def is_password_protected(self) -> bool:
        """Check if the PDF is actually password protected
        
        Returns:
            True if the PDF is password protected, False otherwise
        """
        try:
            with pikepdf.open(self.pdf_path) as pdf:
                return False  # No exception, so not password protected
        except pikepdf.PasswordError:
            return True
        except Exception as e:
            self.logger.error(f"Error checking PDF: {str(e)}")
            raise
            
    def _calculate_optimal_batch_size(self, total_passwords: int) -> int:
        """Calculate an optimal batch size based on total passwords and CPU count
        
        Args:
            total_passwords: Total number of passwords to try
            
        Returns:
            Optimal batch size
        """
        if total_passwords < 100000:
            # For small password spaces, use smaller batches
            batch_size = min(1000, total_passwords // (self.processes * 2))
        else:
            # For larger password spaces, use larger batches
            batch_size = min(10000, total_passwords // self.processes)
            
        # Make sure we have at least one batch per process
        batch_size = max(1, min(batch_size, total_passwords // max(1, self.processes)))
        
        return batch_size
        
    def _setup_signal_handlers(self):
        """Set up signal handlers to gracefully handle interruptions"""
        # Save original handler to restore later
        self.original_sigint_handler = signal.getsignal(signal.SIGINT)
        
        def sigint_handler(sig, frame):
            """Handle Ctrl+C by saving state and exiting"""
            self.logger.info("\nInterrupted by user. Saving state and cleaning up...")
            self._save_current_state()
            self._cleanup_processes()
            # Restore original handler and re-raise the signal
            signal.signal(signal.SIGINT, self.original_sigint_handler)
            raise KeyboardInterrupt
            
        # Set custom handler
        signal.signal(signal.SIGINT, sigint_handler)
        
    def _restore_signal_handlers(self):
        """Restore original signal handlers"""
        if self.original_sigint_handler:
            signal.signal(signal.SIGINT, self.original_sigint_handler)
            
    def _cleanup_processes(self):
        """Terminate and clean up any active worker processes"""
        for p in self.active_processes:
            if p.is_alive():
                p.terminate()
                p.join(timeout=1)
        self.active_processes = []
        
    def _save_current_state(self, generator_type=None, generator_params=None):
        """Save the current state
        
        Args:
            generator_type: Type of generator being used
            generator_params: Dictionary of generator parameters
        """
        self.state_manager.save_state(
            generator_type=generator_type or "unknown",
            generator_params=generator_params or {},
            current_position=self.current_position,
            passwords_tried=self.total_passwords_tried,
            start_time=self.start_time
        )
        
    def crack(self, 
             generator: PasswordGenerator,
             ignore_state: bool = False,
             progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Optional[str]:
        """Attempt to crack the PDF password using the given generator
        
        Args:
            generator: Password generator to use
            ignore_state: Whether to ignore saved state
            progress_callback: Optional callback function for progress updates
            
        Returns:
            The found password or None if not found
        """
        if not self.is_password_protected():
            self.logger.info("This PDF is not password protected!")
            raise PDFNotEncryptedError("This PDF is not password protected!")
            
        self.logger.info(f"PDF is password protected. Starting to crack...")
        self.logger.info(f"Using {self.processes} CPU cores")
        
        # Set up signal handlers
        self._setup_signal_handlers()
        
        try:
            # Get total passwords to try
            total_passwords = generator.get_total_count()
            self.logger.info(f"Total possible passwords: {total_passwords:,}")
            
            # Calculate optimal batch size
            self.batch_size = self._calculate_optimal_batch_size(total_passwords)
            self.logger.info(f"Using batch size of {self.batch_size:,} passwords per process")
            
            # Get generator type and parameters for state management
            generator_type = generator.__class__.__name__
            generator_params = {
                "total_count": generator.get_total_count(),
            }
            
            # If numeric generator, add digit length
            if isinstance(generator, NumericPasswordGenerator):
                generator_params["length"] = generator.length
            
            # Check for saved state for this specific generator configuration
            resume_state = None if ignore_state else self.state_manager.load_state(generator_type, generator_params)
            
            if resume_state and not ignore_state:
                self.logger.info(f"Found saved state from {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(resume_state['timestamp']))}")
                self.logger.info(f"Resuming from position {resume_state['current_position']:,}")
                self.logger.info(f"Already tried {resume_state['passwords_tried']:,} passwords over {resume_state['elapsed_time']:.2f} seconds")
                
                # Use the saved state to determine where to start
                self.start_time = time.time() - resume_state['elapsed_time']
                self.total_passwords_tried = resume_state['passwords_tried']
                self.current_position = resume_state['current_position']
            else:
                self.start_time = time.time()
                self.total_passwords_tried = 0
                self.current_position = 0
            
            # Create progress bar
            self.progress_bar = tqdm(total=total_passwords, initial=self.current_position, unit="pw")
            
            # Create queues for results and progress updates
            result_queue = multiprocessing.Queue()
            progress_queue = multiprocessing.Queue()
            
            # Start with no password found
            found_password = None
            
            # Calculate time for last state save
            last_save_time = time.time()
            
            # Start initial batch of processes
            for i in range(min(self.processes, (total_passwords - self.current_position + self.batch_size - 1) // self.batch_size)):
                if self.current_position >= total_passwords:
                    break
                    
                # Calculate how many passwords this batch will try
                batch_count = min(self.batch_size, total_passwords - self.current_position)
                
                # Generate passwords for this batch
                batch_passwords = generator.generate(self.current_position, batch_count)
                
                # Start a new process for this batch
                p = multiprocessing.Process(
                    target=worker_process,
                    args=(self.pdf_path, batch_passwords, result_queue, progress_queue),
                    kwargs={"worker_id": i}
                )
                p.start()
                self.active_processes.append(p)
                self.current_position += batch_count
            
            # Process until we find the password or exhaust all possibilities
            while self.active_processes and found_password is None:
                # Check for results (non-blocking)
                try:
                    result = result_queue.get(block=False)
                    if result is not None:
                        found_password = result
                        break
                        
                    # A process finished with no success, remove it from active
                    finished_processes = [p for p in self.active_processes if not p.is_alive()]
                    for p in finished_processes:
                        self.active_processes.remove(p)
                    
                    # Start new processes if we have more passwords to try
                    while self.current_position < total_passwords and len(self.active_processes) < self.processes:
                        batch_count = min(self.batch_size, total_passwords - self.current_position)
                        batch_passwords = generator.generate(self.current_position, batch_count)
                        
                        p = multiprocessing.Process(
                            target=worker_process,
                            args=(self.pdf_path, batch_passwords, result_queue, progress_queue),
                            kwargs={"worker_id": len(self.active_processes)}
                        )
                        p.start()
                        self.active_processes.append(p)
                        self.current_position += batch_count
                except multiprocessing.queues.Empty:
                    pass
                
                # Update progress (non-blocking)
                progress_received = 0
                try:
                    while True:
                        progress = progress_queue.get(block=False)
                        progress_received += progress
                except multiprocessing.queues.Empty:
                    pass
                
                # Update the progress bar and metrics
                if progress_received > 0:
                    self.total_passwords_tried += progress_received
                    self.progress_bar.update(progress_received)
                    
                    # Calculate and display speed and ETA
                    elapsed = time.time() - self.start_time
                    if elapsed > 0:
                        speed = self.total_passwords_tried / elapsed
                        if speed > 1_000_000:
                            speed_str = f"{speed/1_000_000:.2f}M/s"
                        elif speed > 1_000:
                            speed_str = f"{speed/1_000:.2f}K/s"
                        else:
                            speed_str = f"{speed:.2f}/s"
                        
                        # Calculate ETA
                        if speed > 0:
                            eta_seconds = (total_passwords - self.progress_bar.n) / speed
                            hours, remainder = divmod(eta_seconds, 3600)
                            minutes, seconds = divmod(remainder, 60)
                            eta_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
                        else:
                            eta_str = "unknown"
                        
                        self.progress_bar.set_description(
                            f"Tried: {self.total_passwords_tried:,} | Speed: {speed_str} | ETA: {eta_str}"
                        )
                        
                        # Call progress callback if provided
                        if progress_callback:
                            progress_data = {
                                "total_tried": self.total_passwords_tried,
                                "total_passwords": total_passwords,
                                "current_position": self.current_position,
                                "speed": speed,
                                "elapsed": elapsed,
                                "eta_seconds": eta_seconds if speed > 0 else None
                            }
                            progress_callback(progress_data)
                
                # Save state periodically
                if time.time() - last_save_time > self.save_interval:
                    # Save state with generator info
                    self._save_current_state(
                        generator_type=generator.__class__.__name__,
                        generator_params=generator_params
                    )
                    last_save_time = time.time()
                
                # Short sleep to prevent CPU thrashing
                time.sleep(0.01)
            
            # Clean up any remaining processes
            self._cleanup_processes()
            
            # Close the progress bar
            if self.progress_bar:
                self.progress_bar.close()
                self.progress_bar = None
            
            # Process result
            if found_password:
                self.logger.info(f"\n\nPASSWORD FOUND: {found_password}")
                self.logger.info(f"Time taken: {time.time() - self.start_time:.2f} seconds")
                self.logger.info(f"Passwords tried: {self.total_passwords_tried:,}")
                
                # Save the password to a file
                with open("found_password.txt", "w") as f:
                    f.write(f"PDF: {self.pdf_path}\nPassword: {found_password}")
                
                # Remove state file since we found the password
                self.state_manager.delete_state(
                    generator_type=generator.__class__.__name__,
                    generator_params=generator_params
                )
                
                return found_password
            else:
                self.logger.warning("\nPASSWORD NOT FOUND after trying all combinations in this strategy!")
                self.logger.info(f"Total passwords checked: {self.total_passwords_tried:,}")
                self.logger.info(f"Total time spent: {time.time() - self.start_time:.2f} seconds")
                self.logger.info(f"Average speed: {self.total_passwords_tried / (time.time() - self.start_time):.2f} passwords/second")
                
                return None
                
        finally:
            # Always restore signal handlers
            self._restore_signal_handlers()
            
            # Make sure we clean up any active processes
            self._cleanup_processes()
            
            # Make sure progress bar is closed
            if self.progress_bar:
                self.progress_bar.close()
                self.progress_bar = None
            
    def crack_with_strategy(self, 
                           strategies: List[str] = None,
                           min_length: int = 3,
                           max_length: int = 6,
                           exact_length: Optional[int] = None,
                           dictionary_path: Optional[str] = None,
                           ignore_state: bool = False) -> Optional[str]:
        """Crack a PDF using multiple strategies in sequence
        
        Args:
            strategies: List of strategies to try ('numeric', 'smart', 'alphabetic', 'alphanumeric', 'dictionary')
            min_length: Minimum password length
            max_length: Maximum password length
            exact_length: Exact password length (overrides min/max)
            dictionary_path: Path to dictionary file for dictionary strategy
            ignore_state: Whether to ignore saved state
            
        Returns:
            The found password or None if not found
        """
        # Default strategies if none provided
        if not strategies:
            strategies = ['smart', 'numeric']
            
        # If exact length specified, override min/max
        if exact_length is not None:
            min_length = max_length = exact_length
            
        # Try each strategy in sequence
        for strategy in strategies:
            self.logger.info(f"Trying strategy: {strategy}")
            
            if strategy == 'smart':
                # Use smart password generator with common patterns
                generator = SmartPasswordGenerator()
                
            elif strategy == 'numeric':
                # Try each length in sequence
                for length in range(min_length, max_length + 1):
                    self.logger.info(f"Trying {length}-digit numeric passwords")
                    generator = NumericPasswordGenerator(length)
                    password = self.crack(generator, ignore_state)
                    if password:
                        return password
                continue  # Already tried all lengths
                
            elif strategy == 'dictionary' and dictionary_path:
                # Use dictionary-based attack
                if not os.path.exists(dictionary_path):
                    self.logger.error(f"Dictionary file not found: {dictionary_path}")
                    continue
                    
                from .generator import DictionaryPasswordGenerator
                generator = DictionaryPasswordGenerator(dictionary_path)
                
            elif strategy == 'alphabetic':
                # Try each length in sequence
                for length in range(min_length, max_length + 1):
                    self.logger.info(f"Trying {length}-character alphabetic passwords")
                    from .generator import AlphabeticPasswordGenerator
                    generator = AlphabeticPasswordGenerator(length)
                    password = self.crack(generator, ignore_state)
                    if password:
                        return password
                continue  # Already tried all lengths
                
            elif strategy == 'alphanumeric':
                # Try each length in sequence
                for length in range(min_length, max_length + 1):
                    self.logger.info(f"Trying {length}-character alphanumeric passwords")
                    from .generator import AlphanumericPasswordGenerator
                    generator = AlphanumericPasswordGenerator(length)
                    password = self.crack(generator, ignore_state)
                    if password:
                        return password
                continue  # Already tried all lengths
                
            else:
                self.logger.warning(f"Unknown strategy: {strategy}")
                continue
                
            # Try the strategy
            password = self.crack(generator, ignore_state)
            if password:
                return password
                
        return None