# debug_crypto_fix.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=== DEBUGGING CRYPTO OPERATIONS ===")

# First, check if we can import crypto_ops directly
try:
    from core.operations import crypto_ops
    print("✓ Successfully imported crypto_ops")
except Exception as e:
    print(f"✗ Error importing crypto_ops: {e}")

# Check operations again
try:
    from core.operations.base_operation import OperationRegistry
    ops = OperationRegistry.list_operations()
    
    crypto_ops_to_check = ['md5', 'sha1', 'sha256', 'xor', 'aes_decrypt']
    print(f"\n=== CHECKING CRYPTO OPERATIONS REGISTRATION ===")
    
    for op_name in crypto_ops_to_check:
        if op_name in ops:
            print(f"✓ {op_name} is registered")
        else:
            print(f"✗ {op_name} is MISSING")
    
    print(f"\nTotal operations available: {len(ops)}")
    
except Exception as e:
    print(f"Error: {e}")