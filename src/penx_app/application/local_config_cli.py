"""PX-305 explicit local-only configuration/IaC linting command.

Reads a single user-supplied file, lints it with a bounded, deterministic,
line-based parser and prints a stable JSON report. The linter never executes
configuration, never opens a network connection and never interprets
credentials; it only reports explicit, unambiguous weak settings.
"""
from __future__ import annotations

import argparse
import json

from penx_app.scanners.local_config import lint_local_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="penx config",
        description="Offline linting of local nginx/Apache/TLS, Docker Compose "
                    "and k8s configuration files; no shell execution, no network",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    lint = sub.add_parser("lint", help="Lint a single local configuration/IaC file")
    lint.add_argument("--file", required=True, help="Existing local configuration file")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    try:
        report = lint_local_config(args.file)
    except (OSError, ValueError, RecursionError, UnicodeError) as exc:
        print(json.dumps({
            "status": "unverified",
            "error": "config-lint-failed",
            "reason": str(exc),
            "network_access": False,
        }, sort_keys=True, ensure_ascii=True))
        return 2
    print(json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
