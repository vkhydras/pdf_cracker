"""
Configuration handling for the PDF Password Cracker.
"""

import os
import json
from typing import Dict, Any, Optional, Union
from pdf_cracker.utils.exceptions import ConfigError


class Config:
    """Configuration manager for PDF password cracker"""
    
    DEFAULT_CONFIG = {
        "processes": None,  # Use CPU count - 1 by default
        "batch_size": 10000,
        "save_interval": 5,  # seconds
        "state_dir": None,  # Use PDF directory by default
        "verbosity": "info",
        "log_file": None,
        "smart_batch_size": True,
        "password_types": ["numeric"],  # Default to numeric passwords
        "min_length": 3,
        "max_length": 6,
        "dictionary_transforms": ["capitalize", "lowercase", "uppercase", "reverse", "digits"]
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize with optional path to config file"""
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_path = config_path or os.path.expanduser("~/.pdf_cracker_config.json")
        
        # Load config if it exists
        if os.path.exists(self.config_path):
            self.load()
    
    def load(self) -> None:
        """Load configuration from file"""
        try:
            with open(self.config_path, 'r') as f:
                user_config = json.load(f)
                self.config.update(user_config)
        except Exception as e:
            raise ConfigError(f"Error loading config file: {e}")
    
    def save(self) -> None:
        """Save current configuration to file"""
        try:
            # Create directory if it doesn't exist
            config_dir = os.path.dirname(self.config_path)
            if config_dir:
                os.makedirs(config_dir, exist_ok=True)
                
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            raise ConfigError(f"Error saving config file: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value"""
        self.config[key] = value
    
    def update(self, config_dict: Dict[str, Any]) -> None:
        """Update multiple configuration values"""
        self.config.update(config_dict)
        
    def as_dict(self) -> Dict[str, Any]:
        """Return the configuration as a dictionary"""
        return self.config.copy()
        
    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-like access to configuration"""
        return self.config[key]
        
    def __setitem__(self, key: str, value: Any) -> None:
        """Allow dictionary-like setting of configuration"""
        self.config[key] = value
        
    def __contains__(self, key: str) -> bool:
        """Allow 'in' operator on configuration"""
        return key in self.config


def verbosity_to_level(verbosity: Union[str, int]) -> int:
    """Convert verbosity string to logging level
    
    Args:
        verbosity: Verbosity string or logging level integer
        
    Returns:
        Logging level as integer
    """
    if isinstance(verbosity, int):
        return verbosity
        
    levels = {
        "debug": 10,
        "info": 20,
        "warning": 30,
        "error": 40,
        "critical": 50
    }
    
    return levels.get(verbosity.lower(), 20)  # Default to INFO