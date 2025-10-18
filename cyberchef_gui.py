# cyberchef_gui.py
#!/usr/bin/env python3
"""
CyberChef GUI - A graphical interface for CyberChef CLI operations
Single file implementation - no dependencies on other project files
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import base64
import binascii
import hashlib
import json
import re
import math
from collections import Counter
from urllib.parse import quote, unquote

class CyberChefGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberChef GUI")
        self.root.geometry("1000x700")
        
        # Store operations and their parameters
        self.operations = self._get_operations()
        self.current_recipe = []
        
        self._setup_gui()
        
    def _get_operations(self):
        """Define all available operations and their parameters"""
        return {
            # Encoding operations
            "base64_encode": {"name": "Base64 Encode", "params": {}},
            "base64_decode": {"name": "Base64 Decode", "params": {}},
            "hex_encode": {"name": "Hex Encode", "params": {}},
            "hex_decode": {"name": "Hex Decode", "params": {}},
            "url_encode": {"name": "URL Encode", "params": {}},
            "url_decode": {"name": "URL Decode", "params": {}},
            
            # Crypto operations
            "md5": {"name": "MD5 Hash", "params": {}},
            "sha1": {"name": "SHA1 Hash", "params": {}},
            "sha256": {"name": "SHA256 Hash", "params": {}},
            "xor": {"name": "XOR", "params": {"key": "str"}},
            
            # Conversion operations
            "to_upper": {"name": "To Uppercase", "params": {}},
            "to_lower": {"name": "To Lowercase", "params": {}},
            "json_beautify": {"name": "JSON Beautify", "params": {"indent": "int"}},
            "json_minify": {"name": "JSON Minify", "params": {}},
            
            # Analysis operations
            "entropy": {"name": "Entropy Analysis", "params": {}},
            "frequency": {"name": "Frequency Analysis", "params": {"top": "int"}},
            "hex_dump": {"name": "Hex Dump", "params": {"bytes_per_line": "int"}},
            "strings": {"name": "Extract Strings", "params": {"min_length": "int"}},
            "regex": {"name": "Regex Search", "params": {"pattern": "str", "ignore_case": "bool"}},
            "file_signature": {"name": "File Signature", "params": {}},
        }
    
    def _setup_gui(self):
        """Setup the main GUI layout"""
        # Create main frames
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding="5")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, height=8, width=80)
        self.input_text.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        input_buttons = ttk.Frame(input_frame)
        input_buttons.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        ttk.Button(input_buttons, text="Load File", command=self.load_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(input_buttons, text="Clear", command=self.clear_input).pack(side=tk.LEFT)
        
        # Operations section
        ops_frame = ttk.LabelFrame(main_frame, text="Operations", padding="5")
        ops_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        ops_frame.columnconfigure(0, weight=1)
        ops_frame.rowconfigure(1, weight=1)
        
        # Operation categories
        categories = {
            "Encoding": ["base64_encode", "base64_decode", "hex_encode", "hex_decode", "url_encode", "url_decode"],
            "Crypto": ["md5", "sha1", "sha256", "xor"],
            "Conversion": ["to_upper", "to_lower", "json_beautify", "json_minify"],
            "Analysis": ["entropy", "frequency", "hex_dump", "strings", "regex", "file_signature"]
        }
        
        # Create notebook for categories
        notebook = ttk.Notebook(ops_frame)
        notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.operation_buttons = {}
        
        for category, ops in categories.items():
            category_frame = ttk.Frame(notebook, padding="5")
            notebook.add(category_frame, text=category)
            
            for i, op_id in enumerate(ops):
                op_name = self.operations[op_id]["name"]
                btn = ttk.Button(
                    category_frame, 
                    text=op_name,
                    command=lambda op=op_id: self.add_operation(op)
                )
                btn.grid(row=i//2, column=i%2, sticky=(tk.W, tk.E), padx=2, pady=2)
                self.operation_buttons[op_id] = btn
        
        # Parameters frame
        self.params_frame = ttk.LabelFrame(ops_frame, text="Operation Parameters", padding="5")
        self.params_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        self.params_frame.columnconfigure(0, weight=1)
        
        self.param_widgets = {}
        
        # Recipe section
        recipe_frame = ttk.LabelFrame(main_frame, text="Recipe", padding="5")
        recipe_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        recipe_frame.columnconfigure(0, weight=1)
        recipe_frame.rowconfigure(0, weight=1)
        
        self.recipe_listbox = tk.Listbox(recipe_frame)
        self.recipe_listbox.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        recipe_buttons = ttk.Frame(recipe_frame)
        recipe_buttons.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        ttk.Button(recipe_buttons, text="Remove Selected", command=self.remove_operation).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(recipe_buttons, text="Clear Recipe", command=self.clear_recipe).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(recipe_buttons, text="Move Up", command=self.move_up).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(recipe_buttons, text="Move Down", command=self.move_down).pack(side=tk.LEFT)
        
        # Output section
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="5")
        output_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, width=80)
        self.output_text.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        output_buttons = ttk.Frame(output_frame)
        output_buttons.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        ttk.Button(output_buttons, text="Execute Recipe", command=self.execute_recipe).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(output_buttons, text="Save Output", command=self.save_output).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(output_buttons, text="Clear Output", command=self.clear_output).pack(side=tk.LEFT)
        
        # Configure row weights
        main_frame.rowconfigure(1, weight=1)
        ops_frame.rowconfigure(1, weight=1)
        recipe_frame.rowconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
    
    def load_file(self):
        """Load file content into input"""
        filename = filedialog.askopenfilename()
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.input_text.delete(1.0, tk.END)
                self.input_text.insert(1.0, content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")
    
    def clear_input(self):
        """Clear input text"""
        self.input_text.delete(1.0, tk.END)
    
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete(1.0, tk.END)
    
    def clear_recipe(self):
        """Clear current recipe"""
        self.current_recipe.clear()
        self.recipe_listbox.delete(0, tk.END)
    
    def add_operation(self, operation_id):
        """Add operation to recipe with parameters"""
        op_info = self.operations[operation_id]
        params = op_info["params"]
        
        # If no parameters, add directly
        if not params:
            self._add_to_recipe(operation_id, {})
            return
        
        # Create parameter input dialog
        self._show_parameter_dialog(operation_id, params)
    
    def _show_parameter_dialog(self, operation_id, params):
        """Show dialog for operation parameters"""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Parameters for {self.operations[operation_id]['name']}")
        dialog.geometry("300x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        param_values = {}
        param_widgets = {}
        
        for i, (param_name, param_type) in enumerate(params.items()):
            ttk.Label(dialog, text=f"{param_name} ({param_type}):").grid(row=i, column=0, sticky=tk.W, padx=5, pady=5)
            
            if param_type == "bool":
                var = tk.BooleanVar()
                widget = ttk.Checkbutton(dialog, variable=var)
                widget.grid(row=i, column=1, sticky=tk.W, padx=5, pady=5)
            else:
                widget = ttk.Entry(dialog, width=20)
                widget.grid(row=i, column=1, sticky=tk.W, padx=5, pady=5)
            
            param_widgets[param_name] = (widget, param_type)
        
        def on_ok():
            for param_name, (widget, param_type) in param_widgets.items():
                if param_type == "bool":
                    param_values[param_name] = var.get()
                else:
                    value = widget.get()
                    if param_type == "int" and value:
                        try:
                            param_values[param_name] = int(value)
                        except ValueError:
                            messagebox.showerror("Error", f"Invalid integer for {param_name}")
                            return
                    else:
                        param_values[param_name] = value
            
            self._add_to_recipe(operation_id, param_values)
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=len(params), column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
    
    def _add_to_recipe(self, operation_id, params):
        """Add operation with parameters to recipe"""
        op_info = self.operations[operation_id]
        display_text = op_info["name"]
        
        if params:
            param_str = ", ".join(f"{k}={v}" for k, v in params.items())
            display_text += f" ({param_str})"
        
        self.current_recipe.append({"id": operation_id, "params": params})
        self.recipe_listbox.insert(tk.END, display_text)
    
    def remove_operation(self):
        """Remove selected operation from recipe"""
        selection = self.recipe_listbox.curselection()
        if selection:
            index = selection[0]
            self.recipe_listbox.delete(index)
            self.current_recipe.pop(index)
    
    def move_up(self):
        """Move selected operation up in recipe"""
        selection = self.recipe_listbox.curselection()
        if selection and selection[0] > 0:
            index = selection[0]
            # Swap in listbox
            item = self.recipe_listbox.get(index)
            self.recipe_listbox.delete(index)
            self.recipe_listbox.insert(index-1, item)
            self.recipe_listbox.selection_set(index-1)
            
            # Swap in recipe list
            self.current_recipe[index], self.current_recipe[index-1] = \
                self.current_recipe[index-1], self.current_recipe[index]
    
    def move_down(self):
        """Move selected operation down in recipe"""
        selection = self.recipe_listbox.curselection()
        if selection and selection[0] < len(self.current_recipe) - 1:
            index = selection[0]
            # Swap in listbox
            item = self.recipe_listbox.get(index)
            self.recipe_listbox.delete(index)
            self.recipe_listbox.insert(index+1, item)
            self.recipe_listbox.selection_set(index+1)
            
            # Swap in recipe list
            self.current_recipe[index], self.current_recipe[index+1] = \
                self.current_recipe[index+1], self.current_recipe[index]
    
    def execute_recipe(self):
        """Execute the current recipe on input data"""
        input_data = self.input_text.get(1.0, tk.END).strip()
        
        if not input_data:
            messagebox.showwarning("Warning", "No input data provided")
            return
        
        if not self.current_recipe:
            messagebox.showwarning("Warning", "No operations in recipe")
            return
        
        try:
            # Convert input to bytes
            data = input_data.encode('utf-8')
            
            # Execute each operation in sequence
            for op in self.current_recipe:
                data = self._execute_single_operation(op['id'], data, op['params'])
            
            # Convert result back to string for display
            try:
                result = data.decode('utf-8')
            except UnicodeDecodeError:
                result = f"Binary data (hex): {data.hex()}"
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, result)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to execute recipe: {e}")
    
    def _execute_single_operation(self, operation_id, data, params):
        """Execute a single operation"""
        try:
            if operation_id == "base64_encode":
                return base64.b64encode(data)
            elif operation_id == "base64_decode":
                return base64.b64decode(data)
            elif operation_id == "hex_encode":
                return binascii.hexlify(data)
            elif operation_id == "hex_decode":
                return binascii.unhexlify(data)
            elif operation_id == "url_encode":
                return quote(data.decode('utf-8')).encode()
            elif operation_id == "url_decode":
                return unquote(data.decode('utf-8')).encode()
            elif operation_id == "md5":
                return hashlib.md5(data).hexdigest().encode()
            elif operation_id == "sha1":
                return hashlib.sha1(data).hexdigest().encode()
            elif operation_id == "sha256":
                return hashlib.sha256(data).hexdigest().encode()
            elif operation_id == "xor":
                key = params.get('key', '0')
                if key.startswith('0x'):
                    key_bytes = bytes([int(key[2:], 16)])
                elif key.isdigit():
                    key_bytes = bytes([int(key)])
                else:
                    key_bytes = key.encode()
                
                result = bytearray()
                for i, byte in enumerate(data):
                    result.append(byte ^ key_bytes[i % len(key_bytes)])
                return bytes(result)
            elif operation_id == "to_upper":
                return data.upper()
            elif operation_id == "to_lower":
                return data.lower()
            elif operation_id == "json_beautify":
                indent = params.get('indent', 2)
                parsed = json.loads(data.decode('utf-8'))
                return json.dumps(parsed, indent=indent).encode()
            elif operation_id == "json_minify":
                parsed = json.loads(data.decode('utf-8'))
                return json.dumps(parsed, separators=(',', ':')).encode()
            elif operation_id == "entropy":
                if not data:
                    return b"Entropy: 0.0"
                entropy = 0.0
                for x in range(256):
                    p_x = float(data.count(x)) / len(data)
                    if p_x > 0:
                        entropy += - p_x * math.log(p_x, 2)
                return f"Shannon entropy: {entropy:.4f} bits/byte".encode()
            elif operation_id == "frequency":
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
                    
                    top_n = params.get('top', 20)
                    for char, count in freq.most_common(top_n):
                        percentage = (count / total_chars) * 100
                        result["top_characters"].append({
                            "character": repr(char)[1:-1],
                            "count": count,
                            "percentage": round(percentage, 2)
                        })
                    
                    return json.dumps(result, indent=2).encode()
                except:
                    # Binary frequency analysis
                    freq = Counter(data)
                    total_bytes = len(data)
                    
                    result = {
                        "type": "byte_frequency",
                        "total_bytes": total_bytes,
                        "unique_bytes": len(freq),
                        "top_bytes": []
                    }
                    
                    top_n = params.get('top', 20)
                    for byte_val, count in freq.most_common(top_n):
                        percentage = (count / total_bytes) * 100
                        result["top_bytes"].append({
                            "byte": f"0x{byte_val:02x}",
                            "decimal": byte_val,
                            "count": count,
                            "percentage": round(percentage, 2)
                        })
                    
                    return json.dumps(result, indent=2).encode()
            elif operation_id == "hex_dump":
                bytes_per_line = params.get('bytes_per_line', 16)
                offset = 0
                result_lines = []
                
                for i in range(0, len(data), bytes_per_line):
                    chunk = data[i:i + bytes_per_line]
                    line = f"{offset:08x}: "
                    hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
                    line += hex_bytes.ljust(bytes_per_line * 3)
                    ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    line += f"  {ascii_repr}"
                    result_lines.append(line)
                    offset += bytes_per_line
                
                return '\n'.join(result_lines).encode()
            elif operation_id == "strings":
                min_length = params.get('min_length', 4)
                strings = []
                current_string = ""
                
                for byte in data:
                    char = chr(byte) if 32 <= byte <= 126 else None
                    if char:
                        current_string += char
                    else:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ""
                
                if len(current_string) >= min_length:
                    strings.append(current_string)
                
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
                    "strings": unique_strings[:100]  # Limit output
                }
                
                return json.dumps(result, indent=2).encode()
            elif operation_id == "regex":
                pattern = params.get('pattern', '')
                if not pattern:
                    raise ValueError("Regex pattern is required")
                
                ignore_case = params.get('ignore_case', False)
                flags = re.IGNORECASE if ignore_case else 0
                
                text = data.decode('utf-8', errors='ignore')
                matches = re.findall(pattern, text, flags)
                
                result = {
                    "pattern": pattern,
                    "total_matches": len(matches),
                    "matches": matches[:50]  # Limit output
                }
                
                return json.dumps(result, indent=2).encode()
            elif operation_id == "file_signature":
                signatures = {
                    b'\xff\xd8\xff': 'JPEG image',
                    b'\x89PNG\r\n\x1a\n': 'PNG image',
                    b'GIF8': 'GIF image',
                    b'%PDF': 'PDF document',
                    b'PK\x03\x04': 'ZIP archive',
                    b'\x1f\x8b\x08': 'GZIP archive',
                    b'\x7fELF': 'ELF executable',
                    b'MZ': 'Windows executable',
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
            else:
                raise ValueError(f"Unknown operation: {operation_id}")
                
        except Exception as e:
            raise ValueError(f"Error in {operation_id}: {e}")
    
    def save_output(self):
        """Save output to file"""
        output_data = self.output_text.get(1.0, tk.END).strip()
        if not output_data:
            messagebox.showwarning("Warning", "No output to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(output_data)
                messagebox.showinfo("Success", "Output saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = CyberChefGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()