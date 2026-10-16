"""Allow `python -m penx` from a standard installed package."""
from penx_app.bootstrap import main

raise SystemExit(main())
