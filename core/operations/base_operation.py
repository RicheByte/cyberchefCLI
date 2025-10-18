# core/operations/base_operation.py
from abc import ABC, abstractmethod
from typing import Any, Dict

class Operation(ABC):
    """Base class for all CyberChef operations"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
    
    @abstractmethod
    def execute(self, data: bytes, **kwargs) -> bytes:
        """Execute the operation on input data"""
        pass
    
    def validate_args(self, **kwargs) -> bool:
        """Validate operation arguments"""
        return True
    
    def get_help(self) -> str:
        """Get help text for this operation"""
        return self.description

class OperationRegistry:
    """Registry for all available operations"""
    
    _operations: Dict[str, Operation] = {}
    
    @classmethod
    def register(cls, name: str, operation_class: type):
        """Register an operation class"""
        cls._operations[name] = operation_class()
    
    @classmethod
    def get_operation(cls, name: str) -> Operation:
        """Get operation by name"""
        if name not in cls._operations:
            raise ValueError(f"Unknown operation: {name}")
        return cls._operations[name]
    
    @classmethod
    def list_operations(cls) -> Dict[str, Operation]:
        """List all available operations"""
        return cls._operations.copy()