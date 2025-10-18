# test_cyberchef.py (create in root directory)
#!/usr/bin/env python3
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from core.chef import CyberChef
    
    # Test basic functionality
    chef = CyberChef()
    chef.load_recipe(recipe_str="base64_encode")
    result = chef.execute(b"hello world")
    print("SUCCESS! Test result:", result.decode())
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()