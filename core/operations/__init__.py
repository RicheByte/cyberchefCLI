# core/operations/__init__.py
from .base_operation import Operation, OperationRegistry

# Import all operation categories to ensure they're registered
from . import encoding_ops
from . import crypto_ops
from . import conversion_ops  
from . import analysis_ops

__all__ = ['Operation', 'OperationRegistry']