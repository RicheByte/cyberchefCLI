# core/chef.py (CORRECTED VERSION)
from typing import Optional
from .recipe_parser import RecipeParser, Recipe
from .input_handler import InputHandler
from .output_handler import OutputHandler
from .operations.base_operation import OperationRegistry

class CyberChef:
    """Main CyberChef engine"""
    
    def __init__(self):
        self.recipe = None
    
    def load_recipe(self, recipe_str: Optional[str] = None,
                   recipe_file: Optional[str] = None) -> None:
        """Load a recipe from string or file"""
        if recipe_str:
            self.recipe = RecipeParser.parse_string(recipe_str)
        elif recipe_file:
            self.recipe = RecipeParser.parse_file(recipe_file)
        else:
            raise ValueError("No recipe provided")
    
    def execute(self, input_data: bytes) -> bytes:
        """Execute the loaded recipe on input data"""
        if not self.recipe:
            raise ValueError("No recipe loaded")
        
        return self.recipe.execute(input_data)
    
    def list_operations(self) -> dict:
        """List all available operations"""
        return OperationRegistry.list_operations()
    
    def get_operation_help(self, operation_name: str) -> str:
        """Get help for a specific operation"""
        operation = OperationRegistry.get_operation(operation_name)
        return operation.get_help()

def process_data(input_file: Optional[str] = None,
                input_string: Optional[str] = None,
                recipe_str: Optional[str] = None,
                recipe_file: Optional[str] = None,
                output_file: Optional[str] = None,
                from_stdin: bool = False) -> bytes:
    """
    High-level function to process data through CyberChef
    """
    # Get input data
    input_data = InputHandler.get_input(
        input_file=input_file,
        input_string=input_string,
        stdin=from_stdin
    )
    
    # Create chef and load recipe
    chef = CyberChef()
    chef.load_recipe(recipe_str=recipe_str, recipe_file=recipe_file)
    
    # Execute recipe
    output_data = chef.execute(input_data)
    
    # Write output
    OutputHandler.write_output(output_data, output_file=output_file)
    
    return output_data