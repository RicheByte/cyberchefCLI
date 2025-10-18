# core/operations/conversion_ops.py
import json
import chardet
from .base_operation import Operation, OperationRegistry

class JSONBeautify(Operation):
    def __init__(self):
        super().__init__("json_beautify", "Beautify JSON data")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            # Try to detect encoding
            encoding = chardet.detect(data)['encoding'] or 'utf-8'
            json_str = data.decode(encoding)
            parsed = json.loads(json_str)
            indent = kwargs.get('indent', 2)
            return json.dumps(parsed, indent=indent).encode()
        except Exception as e:
            raise ValueError(f"JSON beautify error: {e}")

class JSONMinify(Operation):
    def __init__(self):
        super().__init__("json_minify", "Minify JSON data")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            encoding = chardet.detect(data)['encoding'] or 'utf-8'
            json_str = data.decode(encoding)
            parsed = json.loads(json_str)
            return json.dumps(parsed, separators=(',', ':')).encode()
        except Exception as e:
            raise ValueError(f"JSON minify error: {e}")

class ToUpper(Operation):
    def __init__(self):
        super().__init__("to_upper", "Convert text to uppercase")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            encoding = chardet.detect(data)['encoding'] or 'utf-8'
            return data.decode(encoding).upper().encode(encoding)
        except:
            return data.upper()

class ToLower(Operation):
    def __init__(self):
        super().__init__("to_lower", "Convert text to lowercase")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            encoding = chardet.detect(data)['encoding'] or 'utf-8'
            return data.decode(encoding).lower().encode(encoding)
        except:
            return data.lower()

class EntropyAnalysis(Operation):
    def __init__(self):
        super().__init__("entropy", "Calculate data entropy")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        import math
        if not data:
            return b"Entropy: 0.0"
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        
        return f"Entropy: {entropy:.4f} bits/byte".encode()

# Register conversion operations
OperationRegistry.register("json_beautify", JSONBeautify)
OperationRegistry.register("json_minify", JSONMinify)
OperationRegistry.register("to_upper", ToUpper)
OperationRegistry.register("to_lower", ToLower)
OperationRegistry.register("entropy", EntropyAnalysis)