# cli/main.py
#!/usr/bin/env python3
import click
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.chef import CyberChef, process_data
from core.operations.base_operation import OperationRegistry
# cli/main.py - ADD THESE LINES AT THE TOP after existing imports

# Force import all operations to ensure they're registered
from core.operations import encoding_ops, crypto_ops, conversion_ops, analysis_ops

console = Console()

@click.group()
def cli():
    """CyberChef CLI - The Swiss Army knife for cryptography and encoding"""
    pass

@cli.command()
@click.option('-f', '--file', 'input_file', help='Input file')
@click.option('-s', '--string', 'input_string', help='Input string')
@click.option('-r', '--recipe', 'recipe_str', help='Operation recipe string')
@click.option('--recipe-file', help='Recipe file (JSON or text)')
@click.option('-o', '--output', 'output_file', help='Output file')
@click.option('-i', '--interactive', is_flag=True, help='Interactive mode')
def bake(input_file, input_string, recipe_str, recipe_file, output_file, interactive):
    """Process data through a recipe of operations"""
    
    if interactive:
        interactive_mode()
        return
    
    try:
        # Check if we're reading from STDIN
        from_stdin = not sys.stdin.isatty()
        
        result = process_data(
            input_file=input_file,
            input_string=input_string,
            recipe_str=recipe_str,
            recipe_file=recipe_file,
            output_file=output_file,
            from_stdin=from_stdin
        )
        
        if not output_file:
            console.print("\n[bold green]Result:[/bold green]")
            console.print(Panel(result.decode('utf-8', errors='replace')))
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

@cli.command()
def operations():
    """List all available operations"""
    operations = OperationRegistry.list_operations()
    
    table = Table(title="Available Operations")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="green")
    
    for name, op in sorted(operations.items()):
        table.add_row(name, op.description)
    
    console.print(table)

@cli.command()
@click.argument('operation_name')
def help(operation_name):
    """Get help for a specific operation"""
    try:
        chef = CyberChef()
        help_text = chef.get_operation_help(operation_name)
        console.print(Panel(help_text, title=f"Help for {operation_name}"))
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

def interactive_mode():
    """Interactive mode for step-by-step processing"""
    console.print("[bold blue]CyberChef Interactive Mode[/bold blue]")
    console.print("Type 'quit' to exit, 'help' for operations list")
    
    chef = CyberChef()
    
    while True:
        try:
            # Get input
            input_data = click.prompt("\nEnter input data", type=str)
            if input_data.lower() == 'quit':
                break
            elif input_data.lower() == 'help':
                chef.list_operations()
                continue
            
            # Get recipe
            recipe_str = click.prompt("Enter recipe (comma-separated operations)")
            if recipe_str.lower() == 'quit':
                break
            
            # Process
            chef.load_recipe(recipe_str=recipe_str)
            result = chef.execute(input_data.encode())
            
            console.print("\n[bold green]Result:[/bold green]")
            console.print(Panel(result.decode('utf-8', errors='replace')))
            
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")

if __name__ == '__main__':
    cli()