# core/operations/analysis_ops.py
import re
import math
import json
from collections import Counter
from typing import Dict, List, Tuple
from .base_operation import Operation, OperationRegistry

class RegexSearch(Operation):
    def __init__(self):
        super().__init__("regex", "Search for patterns using regular expressions")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            pattern = kwargs.get('pattern', '')
            if not pattern:
                raise ValueError("Regex pattern is required")
            
            encoding = kwargs.get('encoding', 'utf-8')
            text = data.decode(encoding, errors='ignore')
            
            flags = 0
            if kwargs.get('ignore_case', False):
                flags |= re.IGNORECASE
            
            matches = re.findall(pattern, text, flags)
            
            if kwargs.get('count_only', False):
                return f"Found {len(matches)} matches".encode()
            else:
                result = {
                    "pattern": pattern,
                    "total_matches": len(matches),
                    "matches": matches[:kwargs.get('max_matches', 50)]  # Limit output
                }
                return json.dumps(result, indent=2).encode()
                
        except Exception as e:
            raise ValueError(f"Regex search error: {e}")

class FrequencyAnalysis(Operation):
    def __init__(self):
        super().__init__("frequency", "Analyze character frequency")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            # For text data
            try:
                text = data.decode('utf-8', errors='ignore')
                freq = Counter(text)
                total_chars = len(text)
                
                result = {
                    "type": "character_frequency",
                    "total_characters": total_chars,
                    "unique_characters": len(freq),
                    "top_characters": []
                }
                
                # Get top N characters
                top_n = kwargs.get('top', 20)
                for char, count in freq.most_common(top_n):
                    percentage = (count / total_chars) * 100
                    result["top_characters"].append({
                        "character": repr(char)[1:-1],  # Escape special chars
                        "count": count,
                        "percentage": round(percentage, 2)
                    })
                
                return json.dumps(result, indent=2).encode()
                
            except:
                # For binary data - byte frequency
                freq = Counter(data)
                total_bytes = len(data)
                
                result = {
                    "type": "byte_frequency", 
                    "total_bytes": total_bytes,
                    "unique_bytes": len(freq),
                    "top_bytes": []
                }
                
                top_n = kwargs.get('top', 20)
                for byte_val, count in freq.most_common(top_n):
                    percentage = (count / total_bytes) * 100
                    result["top_bytes"].append({
                        "byte": f"0x{byte_val:02x}",
                        "decimal": byte_val,
                        "count": count,
                        "percentage": round(percentage, 2)
                    })
                
                return json.dumps(result, indent=2).encode()
                
        except Exception as e:
            raise ValueError(f"Frequency analysis error: {e}")

class EntropyAnalysis(Operation):
    def __init__(self):
        super().__init__("entropy", "Calculate data entropy")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        if not data:
            return b"Entropy: 0.0"
        
        try:
            # Calculate Shannon entropy
            entropy = 0.0
            for x in range(256):
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            
            # Additional analysis
            result = {
                "shannon_entropy_bits_per_byte": round(entropy, 4),
                "data_size_bytes": len(data),
                "entropy_interpretation": self._interpret_entropy(entropy)
            }
            
            # Add compression estimate
            try:
                import zlib
                compressed = zlib.compress(data)
                compression_ratio = len(compressed) / len(data) if data else 0
                result["compression_ratio"] = round(compression_ratio, 4)
                result["estimated_compression"] = f"{compression_ratio * 100:.1f}%"
            except:
                pass
            
            return json.dumps(result, indent=2).encode()
            
        except Exception as e:
            raise ValueError(f"Entropy analysis error: {e}")
    
    def _interpret_entropy(self, entropy: float) -> str:
        if entropy < 2.0:
            return "Low entropy - likely structured data (text, code, etc.)"
        elif entropy < 6.0:
            return "Medium entropy - mixed content"
        elif entropy < 7.5:
            return "High entropy - likely compressed/encrypted data"
        else:
            return "Very high entropy - likely encrypted or random data"

class FileSignatureDetection(Operation):
    def __init__(self):
        super().__init__("file_signature", "Detect file type by magic bytes")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            signatures = {
                b'\xff\xd8\xff': 'JPEG image',
                b'\x89PNG\r\n\x1a\n': 'PNG image',
                b'GIF8': 'GIF image',
                b'%PDF': 'PDF document',
                b'PK\x03\x04': 'ZIP archive',
                b'PK\x05\x06': 'ZIP archive (empty)',
                b'PK\x07\x08': 'ZIP archive (spanned)',
                b'\x1f\x8b\x08': 'GZIP archive',
                b'BZh': 'BZIP2 archive',
                b'\x7fELF': 'ELF executable',
                b'MZ': 'Windows executable',
                b'#!/': 'Shell script',
                b'#!': 'Script file',
                b'<?xml': 'XML document',
                b'<!DOCTYPE HTML': 'HTML document',
                b'\x00\x00\x01\x00': 'ICO icon',
                b'\x52\x61\x72\x21\x1a\x07\x00': 'RAR archive',
                b'\x50\x4b\x03\x04': 'ZIP archive',
                b'\x50\x4b\x05\x06': 'ZIP archive (empty)',
                b'\x50\x4b\x07\x08': 'ZIP archive (spanned)',
            }
            
            matches = []
            for signature, file_type in signatures.items():
                if data.startswith(signature):
                    matches.append({
                        "file_type": file_type,
                        "signature_hex": signature.hex(),
                        "signature_length": len(signature)
                    })
            
            if matches:
                # Sort by signature length (longest first for most specific match)
                matches.sort(key=lambda x: x["signature_length"], reverse=True)
                best_match = matches[0]
                
                result = {
                    "detected_type": best_match["file_type"],
                    "confidence": "high",
                    "signature": best_match["signature_hex"],
                    "all_matches": matches
                }
            else:
                result = {
                    "detected_type": "Unknown",
                    "confidence": "low",
                    "message": "No known file signature detected"
                }
            
            return json.dumps(result, indent=2).encode()
            
        except Exception as e:
            raise ValueError(f"File signature detection error: {e}")

class StringExtract(Operation):
    def __init__(self):
        super().__init__("strings", "Extract printable strings from data")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            min_length = kwargs.get('min_length', 4)
            encoding = kwargs.get('encoding', 'utf-8')
            
            strings = []
            
            if encoding.lower() == 'utf-8':
                # Try UTF-8 string extraction
                current_string = ""
                for byte in data:
                    char = chr(byte) if 32 <= byte <= 126 else None
                    if char:
                        current_string += char
                    else:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ""
                
                # Don't forget the last string
                if len(current_string) >= min_length:
                    strings.append(current_string)
            
            # Also try to decode as text and extract words
            try:
                text = data.decode('utf-8', errors='ignore')
                # Extract words (sequences of printable chars)
                words = re.findall(r'[\\x20-\\x7E]{' + str(min_length) + ',}', text)
                strings.extend(words)
            except:
                pass
            
            # Remove duplicates while preserving order
            seen = set()
            unique_strings = []
            for s in strings:
                if s not in seen:
                    seen.add(s)
                    unique_strings.append(s)
            
            result = {
                "total_strings_found": len(unique_strings),
                "min_length": min_length,
                "strings": unique_strings[:kwargs.get('max_strings', 100)]  # Limit output
            }
            
            return json.dumps(result, indent=2).encode()
            
        except Exception as e:
            raise ValueError(f"String extraction error: {e}")

class HexDump(Operation):
    def __init__(self):
        super().__init__("hex_dump", "Create hex dump of data")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            bytes_per_line = kwargs.get('bytes_per_line', 16)
            offset = 0
            result_lines = []
            
            for i in range(0, len(data), bytes_per_line):
                chunk = data[i:i + bytes_per_line]
                
                # Offset
                line = f"{offset:08x}: "
                
                # Hex bytes
                hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
                line += hex_bytes.ljust(bytes_per_line * 3)
                
                # ASCII representation
                ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                line += f"  {ascii_repr}"
                
                result_lines.append(line)
                offset += bytes_per_line
            
            return '\n'.join(result_lines).encode()
            
        except Exception as e:
            raise ValueError(f"Hex dump error: {e}")

# Register analysis operations
OperationRegistry.register("regex", RegexSearch)
OperationRegistry.register("frequency", FrequencyAnalysis)
OperationRegistry.register("entropy", EntropyAnalysis)
OperationRegistry.register("file_signature", FileSignatureDetection)
OperationRegistry.register("strings", StringExtract)
OperationRegistry.register("hex_dump", HexDump)