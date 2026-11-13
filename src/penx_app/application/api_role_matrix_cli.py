"""PX-309 opt-in disposable loopback API role comparison CLI."""
from __future__ import annotations

import argparse
import json

from penx_app.application.api_role_matrix import compare_roles, load_plan
from penx_app.file_output import publish_unique


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="penx api-role-compare",
        description="Compare status-code access for a disposable localhost API, NOT an IDOR verifier")
    parser.add_argument("--plan", required=True, help="Explicit local JSON case/policy manifest")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--consent", action="store_true")
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--budget", type=int, default=60)
    parser.add_argument("--output-dir", default="./reports")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        document, digest = load_plan(args.plan)
        report = compare_roles(
            document, source_sha256=digest, authorized=args.authorized,
            consent=args.consent, timeout=args.timeout, budget=args.budget)
        filename = publish_unique(
            args.output_dir, "penx_api_role_comparison", ".json",
            json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
        print("API role comparison: " + report["coverage"] +
              "; status checks: " + str(report["status_responses"]) +
              "; suspected mismatches: " + str(report["suspected_excess_access"]) +
              "; output: " + str(filename))
        return (1 if report["coverage"] == "PARTIAL"
                or report["suspected_excess_access"] or report["unexpected_denials"]
                else 0)
    except Exception:
        # Avoid ever echoing local bearer tokens, URL bodies, response headers,
        # untrusted server error text or filesystem paths on failure.
        print("Local API role comparison refused or unavailable; nothing verified.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
