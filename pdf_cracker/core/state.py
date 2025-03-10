"""
State management for the PDF Password Cracker.

This module handles saving and loading the cracker's state,
allowing for resumption of interrupted cracking sessions.
"""

import os
import json
import time
import hashlib
from typing import Dict, Any, Optional

from pdf_cracker.utils.exceptions import StateIOError


class StateManager:
    """Manages saving and loading of cracker state"""
    
    def __init__(self, pdf_path: str, state_dir: Optional[str] = None):
        """Initialize with PDF path and optional state directory"""
        self.pdf_path = pdf_path
        self.state_dir = state_dir or os.path.dirname(os.path.abspath(pdf_path))
        
        # Create state directory if it doesn't exist
        try:
            os.makedirs(self.state_dir, exist_ok=True)
        except OSError as e:
            raise StateIOError(f"Failed to create state directory: {e}")
        
    def get_state_filename(self, generator_type: str = None, generator_params: Dict[str, Any] = None) -> str:
        """Generate a state filename based on the PDF path and generator parameters
        
        Args:
            generator_type: Type of generator being used (e.g., 'numeric', 'alphabetic')
            generator_params: Dictionary of generator parameters
            
        Returns:
            Path to the state file
        """
        pdf_name = os.path.basename(self.pdf_path)
        sanitized_name = ''.join(c if c.isalnum() else '_' for c in pdf_name)
        
        # If we have generator info, include it in the filename to make it specific
        if generator_type and generator_params:
            # Create a hash of the generator type and parameters
            params_str = json.dumps(generator_params, sort_keys=True)
            params_hash = hashlib.md5((generator_type + params_str).encode()).hexdigest()[:8]
            return os.path.join(self.state_dir, f"pdf_cracker_{sanitized_name}_{params_hash}.json")
        else:
            return os.path.join(self.state_dir, f"pdf_cracker_{sanitized_name}.json")
    
    def save_state(self, 
                  generator_type: str,
                  generator_params: Dict[str, Any],
                  current_position: int,
                  passwords_tried: int,
                  start_time: float,
                  extra_data: Optional[Dict[str, Any]] = None) -> None:
        """Save the current state to a file"""
        state = {
            "pdf_path": self.pdf_path,
            "generator_type": generator_type,
            "generator_params": generator_params,
            "current_position": current_position,
            "passwords_tried": passwords_tried,
            "elapsed_time": time.time() - start_time,
            "timestamp": time.time()
        }
        
        if extra_data:
            state.update(extra_data)
        
        state_file = self.get_state_filename(generator_type, generator_params)
        try:
            with open(state_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            raise StateIOError(f"Failed to save state: {e}")
    
    def load_state(self, generator_type: str, generator_params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Load the saved state if it exists for this specific generator configuration
        
        Args:
            generator_type: Type of generator being used
            generator_params: Dictionary of generator parameters
            
        Returns:
            State dictionary or None if no state exists
        """
        state_file = self.get_state_filename(generator_type, generator_params)
        if os.path.exists(state_file):
            try:
                with open(state_file, "r") as f:
                    state = json.load(f)
                
                # Verify the state is for the correct PDF and parameters
                if (state.get("pdf_path") == self.pdf_path and
                    state.get("generator_type") == generator_type and
                    self._compare_params(state.get("generator_params", {}), generator_params)):
                    return state
                else:
                    # If parameters don't match, this state is not applicable
                    return None
            except Exception as e:
                raise StateIOError(f"Error loading state file: {e}")
        
        return None
    
    def _compare_params(self, params1: Dict[str, Any], params2: Dict[str, Any]) -> bool:
        """Compare two parameter dictionaries for semantic equality
        
        This allows for minor differences in representation without treating the parameters
        as completely different.
        
        Args:
            params1: First parameter dictionary
            params2: Second parameter dictionary
            
        Returns:
            True if parameters are semantically equivalent
        """
        # For numeric values, compare with some tolerance
        # For strings, compare case-insensitive
        # For lists and dicts, compare recursively
        
        if set(params1.keys()) != set(params2.keys()):
            return False
            
        for key in params1:
            val1 = params1[key]
            val2 = params2[key]
            
            # Handle different types
            if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                # For numeric values, allow small differences
                if abs(val1 - val2) > 0.001:
                    return False
            elif isinstance(val1, str) and isinstance(val2, str):
                # Case-insensitive string comparison
                if val1.lower() != val2.lower():
                    return False
            elif isinstance(val1, list) and isinstance(val2, list):
                # For lists, check length and elements
                if len(val1) != len(val2):
                    return False
                for i in range(len(val1)):
                    if val1[i] != val2[i]:
                        return False
            elif isinstance(val1, dict) and isinstance(val2, dict):
                # Recursive comparison for dictionaries
                if not self._compare_params(val1, val2):
                    return False
            elif val1 != val2:
                return False
                
        return True
        
    def delete_state(self, generator_type: str = None, generator_params: Dict[str, Any] = None) -> None:
        """Delete the state file if it exists
        
        Args:
            generator_type: Type of generator being used
            generator_params: Dictionary of generator parameters
        """
        state_file = self.get_state_filename(generator_type, generator_params)
        if os.path.exists(state_file):
            try:
                os.remove(state_file)
            except OSError as e:
                raise StateIOError(f"Failed to delete state file: {e}")
                
    def backup_state(self, generator_type: str = None, generator_params: Dict[str, Any] = None) -> None:
        """Create a backup of the current state file
        
        Args:
            generator_type: Type of generator being used
            generator_params: Dictionary of generator parameters
        """
        state_file = self.get_state_filename(generator_type, generator_params)
        if os.path.exists(state_file):
            backup_file = f"{state_file}.bak"
            try:
                with open(state_file, "r") as src, open(backup_file, "w") as dst:
                    dst.write(src.read())
            except Exception as e:
                raise StateIOError(f"Failed to create state backup: {e}")