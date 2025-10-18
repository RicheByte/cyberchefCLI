# core/output_handler.py
import sys
import os
from typing import Optional

class OutputHandler:
    """Handle various output destinations"""
    
    @staticmethod
    def write_output(data: bytes, 
                    output_file: Optional[str] = None,
                    stdout: bool = True,
                    encoding: str = 'utf-8') -> None:
        """
        Write output data to various destinations
        """
        try:
            # Try to decode as text for display
            text_output = data.decode(encoding, errors='replace')
        except:
            # Fallback to raw bytes
            text_output = str(data)
        
        if output_file:
            OutputHandler._write_file(output_file, data)
        
        if stdout:
            OutputHandler._write_stdout(text_output)
    
    @staticmethod
    def _write_file(file_path: str, data: bytes) -> None:
        """Write data to file"""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'wb') as f:
            f.write(data)
    
    @staticmethod
    def _write_stdout(data: str) -> None:
        """Write data to STDOUT"""
        print(data, end='')
    
    @staticmethod
    def format_for_display(data: bytes, max_length: int = 1000) -> str:
        """Format data for display, truncating if too long"""
        try:
            text = data.decode('utf-8', errors='replace')
            if len(text) > max_length:
                return text[:max_length] + f"... [truncated, total {len(text)} chars]"
            return text
        except:
            hex_repr = data.hex()
            if len(hex_repr) > max_length:
                return hex_repr[:max_length] + f"... [truncated, total {len(data)} bytes]"
            return hex_repr