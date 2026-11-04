"""PX-304 explicit local-only SBOM inventory inspection command."""
from __future__ import annotations

import argparse
import json
from penx_app.intelligence.sbom_inventory import SBOMError, inspect_sbom


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="penx sbom",
        description="Strict offline package inventory; no vulnerability lookup",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("inspect", help="Inspect a local CycloneDX/SPDX JSON file")
    audit.add_argument("--file", required=True, help="Existing local SBOM file")
    audit.add_argument("--show-identities", action="store_true",
                       help="Explicitly disclose package identifiers and versions")
    compare = sub.add_parser(
        "compare-osv", help="Offline exact listed OSV version candidates only")
    compare.add_argument("--file", required=True, help="Existing local SBOM JSON")
    compare.add_argument("--osv-file", required=True,
                         help="Existing bounded local collection of OSV detail JSON")
    compare.add_argument("--show-candidates", action="store_true",
                         help="Explicitly reveal candidate package names, versions and IDs")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    try:
        if args.command == "compare-osv":
            from penx_app.intelligence.osv_snapshot_match import (
                compare_local_osv_snapshot,
            )
            result = compare_local_osv_snapshot(
                args.file, args.osv_file,
                include_candidates=args.show_candidates)
        else:
            result = inspect_sbom(
                args.file, include_identities=args.show_identities)
    except (OSError, ValueError, TypeError, RecursionError, SBOMError):
        print(json.dumps({
            "status": "unverified",
            "error": ("sbom-offline-check-failed"
                      if args.command == "compare-osv"
                      else "sbom-inventory-check-failed"),
            "vulnerability_verified": False,
            "network_access": False,
        }))
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
