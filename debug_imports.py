# debug_imports.py
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=== DEBUGGING IMPORTS ===")

try:
    # Test importing base operation
    from core.operations.base_operation import OperationRegistry
    print("✓ Successfully imported OperationRegistry")
    
    # Check if operations are registered
    ops = OperationRegistry.list_operations()
    print(f"✓ Found {len(ops)} operations")
    for op_name in ops:
        print(f"  - {op_name}")
        
except Exception as e:
    print(f"✗ Error importing OperationRegistry: {e}")
    import traceback
    traceback.print_exc()

print("\n=== TESTING CHEF IMPORT ===")
try:
    from core.chef import CyberChef
    print("✓ Successfully imported CyberChef")
    
    # Test creating instance
    chef = CyberChef()
    print("✓ Successfully created CyberChef instance")
    
except Exception as e:
    print(f"✗ Error importing CyberChef: {e}")
    import traceback
    traceback.print_exc()