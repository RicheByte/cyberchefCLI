# core/operations/crypto_ops.py (CORRECTED VERSION)
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from .base_operation import Operation, OperationRegistry

class MD5Hash(Operation):
    def __init__(self):
        super().__init__("md5", "Calculate MD5 hash")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        return hashlib.md5(data).hexdigest().encode()

class SHA1Hash(Operation):
    def __init__(self):
        super().__init__("sha1", "Calculate SHA1 hash")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        return hashlib.sha1(data).hexdigest().encode()

class SHA256Hash(Operation):
    def __init__(self):
        super().__init__("sha256", "Calculate SHA256 hash")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        return hashlib.sha256(data).hexdigest().encode()

class XOROperation(Operation):
    def __init__(self):
        super().__init__("xor", "XOR with key")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        key = kwargs.get('key', b'\x00')
        if isinstance(key, str):
            key = key.encode()
        elif isinstance(key, int):
            key = bytes([key])
        
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

class AESDecrypt(Operation):
    def __init__(self):
        super().__init__("aes_decrypt", "AES decryption")
    
    def execute(self, data: bytes, **kwargs) -> bytes:
        key = kwargs.get('key')
        iv = kwargs.get('iv', b'\x00' * 16)
        mode = kwargs.get('mode', 'CBC')
        
        if not key:
            raise ValueError("AES key is required")
        
        if isinstance(key, str):
            key = key.encode()
        
        # Pad key to proper length
        if len(key) not in [16, 24, 32]:
            key = key.ljust(32, b'\x00')[:32]
        
        if mode.upper() == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data), AES.block_size)
        else:
            raise ValueError(f"Unsupported AES mode: {mode}")

# Register crypto operations
OperationRegistry.register("md5", MD5Hash)
OperationRegistry.register("sha1", SHA1Hash)
OperationRegistry.register("sha256", SHA256Hash)
OperationRegistry.register("xor", XOROperation)
OperationRegistry.register("aes_decrypt", AESDecrypt)