#!/usr/bin/env python3
"""Generate a synthetic PenX HTML/PDF demo using the real project exporters.

No network traffic, scanner invocation, LLM request, or database connection.
Output is deliberately outside the version-controlled public example tree.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from penx_app.reporting.export import export_html, export_pdf  # noqa: E402


def sample_session() -> dict:
    """Fake rows matching the exporter data contract (not a real scan)."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        "history": (1, "example.test", timestamp, "active"),
        "vulns": [
            (101, 1, "Illustrative HTTP header review", "info", "possible",
             "443", "https",
             "Synthetic example only: a human should review response headers "
             "from an authorized test before reporting any issue."),
        ],
        "fixes": [],
        "exploits": [],
        "summary": (1, 1, "", "SYNTHETIC DEMO — no real target was contacted, "
                    "no scan ran, and no vulnerability was verified.", "LOW"),
        "corrections": [],
        "evaluations": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "demo_output",
        help="Output folder (default: ./demo_output; gitignored)",
    )
    args = parser.parse_args()
    target = args.output_dir.resolve()
    target.mkdir(parents=True, exist_ok=True)
    data = sample_session()
    for path in [export_html(data, str(target)), export_pdf(data, str(target))]:
        print(path)
    print("Synthetic report only; not evidence of any actual security finding.")


if __name__ == "__main__":
    main()
