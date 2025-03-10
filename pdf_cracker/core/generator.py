"""
Password generator classes for the PDF Password Cracker.

This module provides various strategies for generating passwords to try.
"""

from abc import ABC, abstractmethod
import string
import os
import random
from typing import List, Optional, Callable


class PasswordGenerator(ABC):
    """Abstract base class for password generators"""
    
    @abstractmethod
    def generate(self, start_pos: int, count: int) -> List[str]:
        """Generate a batch of passwords from a starting position"""
        pass
        
    @abstractmethod
    def get_total_count(self) -> int:
        """Get the total number of possible passwords"""
        pass
    
    @abstractmethod
    def position_to_password(self, position: int) -> str:
        """Convert a numeric position to a password"""
        pass
    
    @abstractmethod
    def password_to_position(self, password: str) -> int:
        """Convert a password to its numeric position"""
        pass


class NumericPasswordGenerator(PasswordGenerator):
    """Generator for numeric passwords of a specific length"""
    
    def __init__(self, length: int):
        """Initialize with password length"""
        self.length = length
        
    def generate(self, start_pos: int, count: int) -> List[str]:
        """Generate a batch of passwords from a starting position"""
        return [str(i).zfill(self.length) for i in range(start_pos, start_pos + count)]
    
    def get_total_count(self) -> int:
        """Get the total number of possible passwords"""
        return 10 ** self.length
    
    def position_to_password(self, position: int) -> str:
        """Convert a numeric position to a password"""
        return str(position).zfill(self.length)
    
    def password_to_position(self, password: str) -> int:
        """Convert a password to its numeric position"""
        if len(password) != self.length:
            raise ValueError(f"Password length must be {self.length}")
        try:
            return int(password)
        except ValueError:
            raise ValueError("Password must be numeric")


class AlphabeticPasswordGenerator(PasswordGenerator):
    """Generator for alphabetic passwords of a specific length"""
    
    def __init__(self, length: int, lowercase: bool = True, uppercase: bool = True):
        """Initialize with password length and character sets"""
        self.length = length
        self.charset = ""
        if lowercase:
            self.charset += string.ascii_lowercase
        if uppercase:
            self.charset += string.ascii_uppercase
        if not self.charset:
            raise ValueError("At least one character set must be enabled")
        self.charset_size = len(self.charset)
        
    def generate(self, start_pos: int, count: int) -> List[str]:
        """Generate a batch of passwords from a starting position"""
        result = []
        for i in range(start_pos, start_pos + count):
            result.append(self.position_to_password(i))
        return result
    
    def get_total_count(self) -> int:
        """Get the total number of possible passwords"""
        return self.charset_size ** self.length
    
    def position_to_password(self, position: int) -> str:
        """Convert a numeric position to a password"""
        result = ""
        temp = position
        for _ in range(self.length):
            result = self.charset[temp % self.charset_size] + result
            temp //= self.charset_size
        return result
    
    def password_to_position(self, password: str) -> int:
        """Convert a password to its numeric position"""
        if len(password) != self.length:
            raise ValueError(f"Password length must be {self.length}")
        
        position = 0
        for char in password:
            if char not in self.charset:
                raise ValueError(f"Invalid character in password: {char}")
            position = position * self.charset_size + self.charset.index(char)
        return position


class AlphanumericPasswordGenerator(PasswordGenerator):
    """Generator for alphanumeric passwords of a specific length"""
    
    def __init__(self, length: int, lowercase: bool = True, uppercase: bool = True, 
                 digits: bool = True, symbols: bool = False):
        """Initialize with password length and character sets"""
        self.length = length
        self.charset = ""
        if lowercase:
            self.charset += string.ascii_lowercase
        if uppercase:
            self.charset += string.ascii_uppercase
        if digits:
            self.charset += string.digits
        if symbols:
            self.charset += string.punctuation
        if not self.charset:
            raise ValueError("At least one character set must be enabled")
        self.charset_size = len(self.charset)
        
    def generate(self, start_pos: int, count: int) -> List[str]:
        """Generate a batch of passwords from a starting position"""
        result = []
        for i in range(start_pos, start_pos + count):
            result.append(self.position_to_password(i))
        return result
    
    def get_total_count(self) -> int:
        """Get the total number of possible passwords"""
        return self.charset_size ** self.length
    
    def position_to_password(self, position: int) -> str:
        """Convert a numeric position to a password"""
        result = ""
        temp = position
        for _ in range(self.length):
            result = self.charset[temp % self.charset_size] + result
            temp //= self.charset_size
        return result
    
    def password_to_position(self, password: str) -> int:
        """Convert a password to its numeric position"""
        if len(password) != self.length:
            raise ValueError(f"Password length must be {self.length}")
        
        position = 0
        for char in password:
            if char not in self.charset:
                raise ValueError(f"Invalid character in password: {char}")
            position = position * self.charset_size + self.charset.index(char)
        return position


class DictionaryPasswordGenerator(PasswordGenerator):
    """Generator for passwords from a dictionary file"""
    
    def __init__(self, dictionary_path: str, transforms: Optional[List[Callable[[str], str]]] = None):
        """Initialize with path to dictionary file and optional transforms"""
        if not os.path.exists(dictionary_path):
            raise FileNotFoundError(f"Dictionary file not found: {dictionary_path}")
            
        self.dictionary_path = dictionary_path
        self.transforms = transforms or []
        
        # Load words and apply transforms
        with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.words = [line.strip() for line in f if line.strip()]
            
        # Apply transforms to generate more password candidates
        transformed_words = []
        for word in self.words:
            transformed_words.append(word)
            for transform in self.transforms:
                transformed_words.append(transform(word))
                
        self.passwords = list(set(transformed_words))  # Remove duplicates
        self.password_count = len(self.passwords)
        
    def generate(self, start_pos: int, count: int) -> List[str]:
        """Generate a batch of passwords from a starting position"""
        end_pos = min(start_pos + count, self.password_count)
        return self.passwords[start_pos:end_pos]
    
    def get_total_count(self) -> int:
        """Get the total number of possible passwords"""
        return self.password_count
    
    def position_to_password(self, position: int) -> str:
        """Convert a numeric position to a password"""
        if position < 0 or position >= self.password_count:
            raise ValueError(f"Position must be between 0 and {self.password_count-1}")
        return self.passwords[position]
    
    def password_to_position(self, password: str) -> int:
        """Convert a password to its numeric position"""
        try:
            return self.passwords.index(password)
        except ValueError:
            raise ValueError(f"Password not found in dictionary: {password}")


class CompositePasswordGenerator(PasswordGenerator):
    """Generator that combines multiple generators"""
    
    def __init__(self, generators: List[PasswordGenerator]):
        """Initialize with a list of generators"""
        if not generators:
            raise ValueError("At least one generator must be provided")
        self.generators = generators
        
        # Calculate cumulative counts for mapping positions to generators
        self.cumulative_counts = [0]
        total = 0
        for gen in self.generators:
            total += gen.get_total_count()
            self.cumulative_counts.append(total)
        
    def generate(self, start_pos: int, count: int) -> List[str]:
        """Generate a batch of passwords from a starting position"""
        result = []
        current_pos = start_pos
        remaining = count
        
        while remaining > 0:
            gen_idx, local_pos = self._find_generator_and_position(current_pos)
            gen = self.generators[gen_idx]
            
            # Calculate how many passwords to generate from this generator
            gen_remaining = gen.get_total_count() - local_pos
            batch_count = min(remaining, gen_remaining)
            
            # Generate passwords from this generator
            passwords = gen.generate(local_pos, batch_count)
            result.extend(passwords)
            
            # Update position and remaining count
            current_pos += batch_count
            remaining -= batch_count
            
            # Break if we've exhausted all generators
            if current_pos >= self.get_total_count():
                break
                
        return result
    
    def get_total_count(self) -> int:
        """Get the total number of possible passwords"""
        return self.cumulative_counts[-1]
    
    def _find_generator_and_position(self, global_pos: int):
        """Find which generator contains the given position and the local position within it"""
        if global_pos < 0 or global_pos >= self.get_total_count():
            raise ValueError(f"Position must be between 0 and {self.get_total_count()-1}")
            
        for i in range(len(self.generators)):
            if global_pos < self.cumulative_counts[i+1]:
                local_pos = global_pos - self.cumulative_counts[i]
                return i, local_pos
                
        # This should never happen
        raise RuntimeError("Could not find generator for position")
    
    def position_to_password(self, position: int) -> str:
        """Convert a numeric position to a password"""
        gen_idx, local_pos = self._find_generator_and_position(position)
        return self.generators[gen_idx].position_to_password(local_pos)
    
    def password_to_position(self, password: str) -> int:
        """Convert a password to its numeric position"""
        # Try each generator
        for i, gen in enumerate(self.generators):
            try:
                local_pos = gen.password_to_position(password)
                return self.cumulative_counts[i] + local_pos
            except ValueError:
                continue
                
        raise ValueError(f"Password not recognized by any generator: {password}")


class SmartPasswordGenerator(PasswordGenerator):
    """Smart password generator that uses common patterns and heuristics"""
    
    def __init__(self, max_passwords: int = 1000000):
        """Initialize with maximum number of passwords to generate"""
        self.max_passwords = max_passwords
        
        # Generate passwords based on common patterns
        self.passwords = []
        
        # Common patterns: birth years (1950-2023)
        for year in range(1950, 2024):
            self.passwords.append(str(year))
        
        # Common numeric patterns (123456, etc.)
        for i in range(4, 9):
            self.passwords.append(''.join(str(j % 10) for j in range(i)))
            self.passwords.append(''.join(str(9 - (j % 10)) for j in range(i)))
        
        # Repeated digits (1111, 2222, etc.)
        for digit in range(10):
            for length in range(4, 9):
                self.passwords.append(str(digit) * length)
        
        # Common number sequences
        common_sequences = [
            "123123", "112233", "121212", "123321", "654321",
            "789456", "456789", "147258", "258369", "159753"
        ]
        self.passwords.extend(common_sequences)
        
        # Dates in various formats (MMDDYYYY, DDMMYYYY, etc.)
        for year in range(1950, 2024):
            for month in range(1, 13):
                for day in range(1, 29):  # Most months have at least 28 days
                    # MMDDYYYY
                    self.passwords.append(f"{month:02d}{day:02d}{year}")
                    # DDMMYYYY
                    self.passwords.append(f"{day:02d}{month:02d}{year}")
                    # MMDDYY
                    self.passwords.append(f"{month:02d}{day:02d}{year % 100:02d}")
                    # DDMMYY
                    self.passwords.append(f"{day:02d}{month:02d}{year % 100:02d}")
        
        # Limit to max passwords
        random.shuffle(self.passwords)  # Randomize to get a good distribution
        self.passwords = self.passwords[:self.max_passwords]
        self.passwords.sort()  # Sort for consistent order
        self.password_count = len(self.passwords)
        
    def generate(self, start_pos: int, count: int) -> List[str]:
        """Generate a batch of passwords from a starting position"""
        end_pos = min(start_pos + count, self.password_count)
        return self.passwords[start_pos:end_pos]
    
    def get_total_count(self) -> int:
        """Get the total number of possible passwords"""
        return self.password_count
    
    def position_to_password(self, position: int) -> str:
        """Convert a numeric position to a password"""
        if position < 0 or position >= self.password_count:
            raise ValueError(f"Position must be between 0 and {self.password_count-1}")
        return self.passwords[position]
    
    def password_to_position(self, password: str) -> int:
        """Convert a password to its numeric position"""
        try:
            return self.passwords.index(password)
        except ValueError:
            raise ValueError(f"Password not found in generator: {password}")