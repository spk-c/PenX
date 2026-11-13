"""PX-305: local OpenAPI JSON contract inventory (never sends HTTP requests)."""
from __future__ import annotations

import argparse
import json

from penx_app.analysis.openapi_contract_map import (
    build_contract_map, read_local_contract,
)
from penx_app.file_output import publish_unique


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="penx api-map",
        description="Offline API contract declaration inventory, NOT an API scan")
    parser.add_argument("--file", required=True, help="Local OpenAPI 3.x JSON file")
    parser.add_argument("--output", default="./reports",
                        help="Directory for an exclusive, separate JSON map")
    args = parser.parse_args(argv)
    try:
        document, digest = read_local_contract(args.file)
        report = build_contract_map(document, source_sha256=digest)
        path = publish_unique(
            args.output, "penx_openapi_contract", ".json",
            json.dumps(report, sort_keys=True, ensure_ascii=True, indent=2) + "\n")
        print("OpenAPI contract: " + report["coverage"] +
              "; declarations: " + str(report["mapped_operations"]) +
              "; output: " + str(path))
        return 0 if report["coverage"] == "COMPLETE" else 1
    except (ValueError, OSError, TypeError, UnicodeError, RecursionError):
        # Never echo source bytes, local private file paths, error bodies,
        # API key literals, credential examples or secret-bearing server URLs.
        print("OpenAPI mapping refused or incomplete; no network request was made.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
