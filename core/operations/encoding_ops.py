# core/operations/encoding_ops.py
import base64
import binascii
from urllib.parse import quote, unquote
from .base_operation import Operation, OperationRegistry

class Base64Encode(Operation):
    def __init__(self):
        super().__init__("base64_encode", "Base64 encode data")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        return base64.b64encode(data)

class Base64Decode(Operation):
    def __init__(self):
        super().__init__("base64_decode", "Base64 decode data")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            return base64.b64decode(data)
        except Exception as e:
            raise ValueError(f"Base64 decode error: {e}")

class HexEncode(Operation):
    def __init__(self):
        super().__init__("hex_encode", "Convert data to hexadecimal")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        return binascii.hexlify(data)

class HexDecode(Operation):
    def __init__(self):
        super().__init__("hex_decode", "Convert hexadecimal to bytes")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            return binascii.unhexlify(data)
        except Exception as e:
            raise ValueError(f"Hex decode error: {e}")

class URLEncode(Operation):
    def __init__(self):
        super().__init__("url_encode", "URL encode data")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        return quote(data.decode('utf-8', errors='ignore')).encode()

class URLDecode(Operation):
    def __init__(self):
        super().__init__("url_decode", "URL decode data")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        try:
            return unquote(data.decode('utf-8', errors='ignore')).encode()
        except Exception as e:
            raise ValueError(f"URL decode error: {e}")

# Register encoding operations
OperationRegistry.register("base64_encode", Base64Encode)
OperationRegistry.register("base64_decode", Base64Decode)
OperationRegistry.register("hex_encode", HexEncode)
OperationRegistry.register("hex_decode", HexDecode)
OperationRegistry.register("url_encode", URLEncode)
OperationRegistry.register("url_decode", URLDecode)