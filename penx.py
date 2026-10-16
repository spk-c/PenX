#!/usr/bin/env python3
"""Compatible source launcher for the packaged PenX application."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))

if __name__ == '__main__':
    from penx_app.bootstrap import main
    raise SystemExit(main())
else:
    from penx_app.cli import app as _implementation
    sys.modules[__name__] = _implementation
