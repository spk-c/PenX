"""Compatibility import; canonical implementation lives in the application package."""
import sys
from penx_app import app_paths as _implementation
sys.modules[__name__] = _implementation
