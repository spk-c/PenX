"""Compatibility import; canonical implementation lives in the application package."""
import sys
from penx_app.analysis import llm as _implementation
sys.modules[__name__] = _implementation
