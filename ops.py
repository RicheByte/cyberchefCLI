# fix_operations.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Clear any cached modules
modules_to_clear = [name for name in sys.modules if name.startswith('core.operations')]
for module in modules_to_clear:
    del sys.modules[module]

# Now re-import everything
from core.operations.base_operation import OperationRegistry
from core.operations import encoding_ops, crypto_ops, conversion_ops, analysis_ops

print("=== FORCE RELOADED OPERATIONS ===")
ops = OperationRegistry.list_operations()
print(f"Total operations: {len(ops)}")

crypto_ops_list = ['md5', 'sha1', 'sha256', 'xor', 'aes_decrypt']
for op in crypto_ops_list:
    if op in ops:
        print(f"✓ {op} is available")
    else:
        print(f"✗ {op} is missing")

print("\nAll available operations:")
for op_name in sorted(ops.keys()):
    print(f"  - {op_name}")