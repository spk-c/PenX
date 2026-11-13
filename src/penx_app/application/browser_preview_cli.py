"""Explicit opt-in local-browser DOM preview; no vulnerability claims."""
from __future__ import annotations

import argparse
import json

from penx_app.application.browser_preview import crawl_loopback
from penx_app.file_output import publish_unique


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="penx browser-preview",
        description="Local lab-only JavaScript DOM discovery, NOT a vulnerability scan")
    parser.add_argument("--url", required=True,
                        help="Explicit http(s)://127.0.0.1:PORT/path lab URL")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--consent", action="store_true")
    parser.add_argument("--max-pages", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--budget", type=int, default=60)
    parser.add_argument("--channel", choices=("chromium", "chrome"),
                        default="chromium")
    parser.add_argument("--output-dir", default="./reports")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = crawl_loopback(
            args.url, authorized=args.authorized, consent=args.consent,
            max_pages=args.max_pages, timeout=args.timeout,
            budget=args.budget, channel=args.channel)
        # Exclusive publication: never overwrite an existing report.
        result = publish_unique(args.output_dir, "penx_browser_preview", ".json",
                                json.dumps(report, ensure_ascii=True, indent=2) + "\n")
        print("Browser preview status: " + report["status"]
              + "; saved: " + str(result))
        return 0 if report["status"] == "COMPLETE" else 1
    except Exception:
        # Do not leak web content, redirect targets, secrets or browser logs.
        print("Browser preview refused or unavailable; no verified findings.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
