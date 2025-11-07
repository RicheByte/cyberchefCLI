# CyberChef CLI

A command-line implementation of the CyberChef tool for cryptographic, encoding, and data analysis operations.


![Demo Video](/assets/video.gif)

## Installation

```bash
# Clone the repository
git clone https://github.com/RicheByte/cyberchefCLI
cd cyberchefCLI

# Create virtual environment (optional but recommended)
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install in development mode
pip install -e .
```

## Quick Start

```bash
# Basic encoding
python cyberchef.py bake -s "hello world" -r "base64_encode"

# Multiple operations
python cyberchef.py bake -s "data" -r "to_upper,base64_encode,url_encode"

# File processing
python cyberchef.py bake -f input.txt -r "base64_encode" -o output.txt

# Using stdin
echo "hello" | python cyberchef.py bake -r "md5"
```


![Diagram](/assets/diagram.png)

## Available Operations

### Encoding Operations (6)

- **base64_encode** - Base64 encode data
- **base64_decode** - Base64 decode data
- **hex_encode** - Convert data to hexadecimal
- **hex_decode** - Convert hexadecimal to bytes
- **url_encode** - URL encode data
- **url_decode** - URL decode data

### Cryptographic Operations (5)

- **md5** - Calculate MD5 hash
- **sha1** - Calculate SHA1 hash
- **sha256** - Calculate SHA256 hash
- **xor** - XOR with key
- **aes_decrypt** - AES decryption

### Conversion Operations (4)

- **json_beautify** - Beautify JSON data
- **json_minify** - Minify JSON data
- **to_upper** - Convert text to uppercase
- **to_lower** - Convert text to lowercase

### Analysis Operations (6)

- **entropy** - Calculate data entropy
- **frequency** - Analyze character frequency
- **hex_dump** - Create hex dump of data
- **regex** - Search for patterns using regular expressions
- **strings** - Extract printable strings from data
- **file_signature** - Detect file type by magic bytes

## Usage Examples

### Basic Encoding/Decoding
![Demo Besic](/assets/basic.png)
```bash
# Base64
python cyberchef.py bake -s "hello world" -r "base64_encode"
python cyberchef.py bake -s "aGVsbG8gd29ybGQ=" -r "base64_decode"

# Hexadecimal
python cyberchef.py bake -s "hello" -r "hex_encode"
python cyberchef.py bake -s "68656c6c6f" -r "hex_decode"

# URL Encoding
python cyberchef.py bake -s "hello & world" -r "url_encode"
python cyberchef.py bake -s "hello%20%26%20world" -r "url_decode"
```

### Cryptographic Operations
![Cryptographic](/assets/Cryptographic%20.png)
```bash
# Hashing
python cyberchef.py bake -s "hello" -r "md5"
python cyberchef.py bake -s "hello" -r "sha1"
python cyberchef.py bake -s "hello" -r "sha256"

# XOR Encryption
python cyberchef.py bake -s "hello" -r "xor(key=0x41)"
python cyberchef.py bake -s "hello" -r "xor(key=115)"
```

### Data Analysis
![Analysis](/assets/Analysis.png)
```bash
# Entropy Analysis
python cyberchef.py bake -s "sample data" -r "entropy"

# Frequency Analysis
python cyberchef.py bake -s "hello world" -r "frequency"

# Hex Dump
python cyberchef.py bake -s "hello" -r "hex_dump"

# String Extraction
python cyberchef.py bake -s "binary data with strings" -r "strings"

# Regular Expression Search
python cyberchef.py bake -s "email: test@example.com" -r "regex(pattern=\w+@\w+\.\w+)"

# File Signature Detection
python cyberchef.py bake -s "%PDF-1.5" -r "file_signature"
```

### JSON Processing
![Processing](/assets/processing.png)
```bash
# Create JSON file for processing
echo '{"name":"john","age":30}' > data.json

# Beautify JSON
python cyberchef.py bake -f data.json -r "json_beautify"

# Minify JSON
python cyberchef.py bake -f data.json -r "json_minify"
```

### Text Conversion
![Conversion](/assets/conversion.png)
```bash
# Case conversion
python cyberchef.py bake -s "Hello World" -r "to_upper"
python cyberchef.py bake -s "HELLO WORLD" -r "to_lower"
```

### Complex Recipes

![Complex](/assets/complex.png)

```bash
# Multiple operations in sequence
python cyberchef.py bake -s "hello" -r "base64_encode,hex_encode"
python cyberchef.py bake -s "secret" -r "to_upper,base64_encode,url_encode"
python cyberchef.py bake -s "data" -r "xor(key=0x41),base64_encode"

# Analysis chain
python cyberchef.py bake -s "sample data" -r "entropy,frequency"
```

## Advanced Usage

### Interactive Mode

![Interactive](/assets/Interactive.gif)

```bash
python cyberchef.py bake --interactive
```

### Listing Operations

```bash
python cyberchef.py operations
```

### Getting Help

```bash
# Help for specific operation
python cyberchef.py help base64_encode
python cyberchef.py help xor
```

### File Input/Output

```bash
# Process file and save to output
python cyberchef.py bake -f input.txt -r "base64_encode" -o encoded.txt

# Process file and display result
python cyberchef.py bake -f data.json -r "json_beautify"

# Process binary files
python cyberchef.py bake -f binary.dat -r "hex_dump"
```

### Using STDIN

```bash
# Pipe data from other commands
cat file.txt | python cyberchef.py bake -r "to_upper"
echo "hello" | python cyberchef.py bake -r "md5"
curl -s http://example.com | python cyberchef.py bake -r "regex(pattern=\w+@\w+\.\w+)"
```

## Recipe Format

### String Format
```
operation1(arg1=value1),operation2,operation3(arg2=value2)
```

Examples:
```
base64_encode
hex_decode,base64_encode
xor(key=0x41),base64_encode
json_beautify(indent=4)
regex(pattern=\d+,ignore_case=true)
```

### JSON Format
Create a JSON file with the recipe:
```json
{
  "operations": [
    {"name": "base64_decode"},
    {"name": "xor", "args": {"key": "0x41"}},
    {"name": "json_beautify", "args": {"indent": 2}}
  ]
}
```

```bash
python cyberchef.py bake -s "data" --recipe-file recipe.json
```

## Operation Arguments

Some operations accept additional arguments:

- **xor**: `key` (hex, decimal, or string)
- **json_beautify**: `indent` (number of spaces)
- **regex**: `pattern`, `ignore_case`, `count_only`, `max_matches`
- **frequency**: `top` (number of top items to show)
- **strings**: `min_length`, `max_strings`

## Use Cases

### Security Analysis
- Analyze file entropy to detect encrypted content
- Extract strings from binary files for malware analysis
- Detect file types from magic bytes
- Calculate hash values for integrity checking

### Data Processing
- Encode/decode data for transmission
- Format JSON data for readability
- Convert between different data representations
- Search for patterns in large datasets

### Development & Debugging
- Inspect binary data with hex dumps
- Test regular expressions
- Process encoded API responses
- Analyze character distributions

## Requirements

- Python 3.7+
- click>=8.0.0
- rich>=13.0.0
- pycryptodome>=3.10.0
- chardet>=5.0.0

## Project Structure

```
cyberchef-cli/
├── core/
│   ├── operations/
│   │   ├── base_operation.py
│   │   ├── encoding_ops.py
│   │   ├── crypto_ops.py
│   │   ├── conversion_ops.py
│   │   └── analysis_ops.py
│   ├── recipe_parser.py
│   ├── input_handler.py
│   ├── output_handler.py
│   └── chef.py
├── cli/
│   └── main.py
├── utils/
│   └── helpers.py
├── requirements.txt
└── setup.py
```

## Troubleshooting

- Use file input for JSON data to avoid shell quoting issues
- For XOR with string keys, use hex or decimal representations
- Ensure input files exist and are readable
- Check operation names with `python cyberchef.py operations`

## License

This project is provided as-is for educational and development purposes.