# utils/helpers.py
import binascii

def is_hex(data: bytes) -> bool:
    """Check if data is valid hexadecimal"""
    try:
        binascii.unhexlify(data)
        return True
    except:
        return False

def is_base64(data: bytes) -> bool:
    """Check if data is valid base64"""
    try:
        import base64
        if len(data) % 4 == 0:
            base64.b64decode(data, validate=True)
            return True
    except:
        pass
    return False

def detect_format(data: bytes) -> str:
    """Auto-detect data format"""
    if is_hex(data):
        return "hex"
    elif is_base64(data):
        return "base64"
    else:
        try:
            data.decode('utf-8')
            return "text"
        except:
            return "binary"