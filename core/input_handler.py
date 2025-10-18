# core/input_handler.py
import sys
import os
from typing import Optional

class InputHandler:
    """Handle various input sources"""
    
    @staticmethod
    def get_input(input_file: Optional[str] = None, 
                 input_string: Optional[str] = None,
                 stdin: bool = False) -> bytes:
        """
        Get input data from various sources in priority order:
        1. Input string
        2. Input file
        3. STDIN
        """
        if input_string:
            return input_string.encode('utf-8')
        
        if input_file:
            return InputHandler._read_file(input_file)
        
        if stdin or not sys.stdin.isatty():
            return InputHandler._read_stdin()
        
        raise ValueError("No input source provided")
    
    @staticmethod
    def _read_file(file_path: str) -> bytes:
        """Read data from file"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input file not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            return f.read()
    
    @staticmethod
    def _read_stdin() -> bytes:
        """Read data from STDIN"""
        if sys.stdin.isatty():
            raise ValueError("No STDIN data available")
        
        return sys.stdin.buffer.read()
    
    @staticmethod
    def detect_encoding(data: bytes) -> str:
        """Detect encoding of data"""
        try:
            import chardet
            result = chardet.detect(data)
            return result['encoding'] or 'utf-8'
        except ImportError:
            # Fallback to UTF-8
            return 'utf-8'