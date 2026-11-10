"""Read-only dependency report for packaged release verification.

This option does not contact the network or initialize PenX settings/scanners.
The release CI compares these imports from the *frozen executable* with the
repository's hash-locked runtime requirements.
"""
from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        import certifi
        import dns
        import PIL

        packages = {
            "certifi": str(certifi.__version__),
            "dnspython": str(dns.__version__),
            "pillow": str(PIL.__version__),
        }
    except (ImportError, AttributeError) as exc:
        print(f"[FAIL] Runtime dependency unavailable: {type(exc).__name__}", file=sys.stderr)
        return 1

    print(json.dumps({
        "frozen": bool(getattr(sys, "frozen", False)),
        "packages": packages,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
