# core/recipe_parser.py
import json
from typing import List, Dict, Any
from .operations.base_operation import OperationRegistry

class RecipeStep:
    """Represents a single operation in a recipe"""
    
    def __init__(self, operation_name: str, args: Dict[str, Any] = None):
        self.operation_name = operation_name
        self.args = args or {}
    
    def execute(self, data: bytes) -> bytes:
        """Execute this recipe step"""
        operation = OperationRegistry.get_operation(self.operation_name)
        return operation.execute(data, **self.args)

class Recipe:
    """Represents a sequence of operations"""
    
    def __init__(self, steps: List[RecipeStep] = None):
        self.steps = steps or []
    
    def add_step(self, step: RecipeStep):
        """Add a step to the recipe"""
        self.steps.append(step)
    
    def execute(self, input_data: bytes) -> bytes:
        """Execute the entire recipe on input data"""
        data = input_data
        for step in self.steps:
            data = step.execute(data)
        return data

class RecipeParser:
    """Parse recipes from various formats"""
    
    @staticmethod
    def parse_string(recipe_str: str) -> Recipe:
        """
        Parse recipe from string format: "operation1(arg1=val1),operation2"
        """
        steps = []
        
        # Split by commas, but respect parentheses
        parts = []
        current = ""
        paren_depth = 0
        
        for char in recipe_str:
            if char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth -= 1
            elif char == ',' and paren_depth == 0:
                parts.append(current.strip())
                current = ""
                continue
            current += char
        
        if current:
            parts.append(current.strip())
        
        for part in parts:
            if '(' in part and part.endswith(')'):
                # Operation with arguments
                op_name, args_str = part.split('(', 1)
                args_str = args_str[:-1]  # Remove trailing )
                args = RecipeParser._parse_args(args_str)
            else:
                # Operation without arguments
                op_name = part
                args = {}
            
            steps.append(RecipeStep(op_name.strip(), args))
        
        return Recipe(steps)
    
    @staticmethod
    def parse_json(recipe_json: str) -> Recipe:
        """Parse recipe from JSON string"""
        try:
            recipe_data = json.loads(recipe_json)
            steps = []
            
            if isinstance(recipe_data, list):
                # Simple list format
                for item in recipe_data:
                    if isinstance(item, str):
                        steps.append(RecipeStep(item))
                    elif isinstance(item, dict):
                        steps.append(RecipeStep(item['name'], item.get('args', {})))
            elif isinstance(recipe_data, dict):
                # Structured format
                for op_data in recipe_data.get('operations', []):
                    steps.append(RecipeStep(op_data['name'], op_data.get('args', {})))
            
            return Recipe(steps)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON recipe: {e}")
    
    @staticmethod
    def parse_file(file_path: str) -> Recipe:
        """Parse recipe from file"""
        with open(file_path, 'r') as f:
            content = f.read().strip()
        
        if file_path.endswith('.json'):
            return RecipeParser.parse_json(content)
        else:
            # Assume string format
            return RecipeParser.parse_string(content)
    
    @staticmethod
    def _parse_args(args_str: str) -> Dict[str, Any]:
        """Parse arguments string into dictionary"""
        args = {}
        if not args_str:
            return args
        
        # Simple key=value parsing
        for pair in args_str.split(','):
            if '=' in pair:
                key, value = pair.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Try to parse as different types
                if value.startswith('"') and value.endswith('"'):
                    args[key] = value[1:-1]  # String
                elif value.startswith("'") and value.endswith("'"):
                    args[key] = value[1:-1]  # String
                elif value.startswith('0x'):
                    args[key] = int(value[2:], 16)  # Hex
                elif value.isdigit():
                    args[key] = int(value)  # Integer
                elif value.lower() in ['true', 'false']:
                    args[key] = value.lower() == 'true'  # Boolean
                else:
                    args[key] = value  # String as fallback
        
        return args