#!/usr/bin/env python3
"""PX-403: opt-in local LLM evaluation on synthetic, labelled evidence only.

No scanner is started, and no real network target is scanned. The caller
explicitly supplies a loopback endpoint and an exact model ID. Reports
contain aggregate metrics only; no raw prompt, reply or target is saved.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from penx_app.analysis.ai_eval_benchmark import read_bounded_json  # noqa: E402
from penx_app.analysis.ai_eval_local_runner import run_local_benchmark  # noqa: E402
from penx_app.analysis.local_review_client import (  # noqa: E402
    local_endpoint, validate_review_options,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Opt-in synthetic evidence benchmark against a LOCAL model API")
    parser.add_argument("--corpus", default=str(
        ROOT / "tests" / "fixtures" / "ai_eval_corpus_v1.json"))
    parser.add_argument("--endpoint", required=True,
                        help="Explicit localhost/127.0.0.1/[::1] OpenAI-compatible server")
    parser.add_argument("--model", required=True, help="Exact requested model ID; no auto")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--batch-budget", type=int, default=600)
    parser.add_argument("--output", help="Optional NEW aggregate JSON file")
    args = parser.parse_args(argv)
    try:
        # Reject unsafe endpoints/models/overwrites BEFORE loading a corpus
        # or issuing any requests. No proxy or redirect is permitted by client.
        local_endpoint(args.endpoint)
        validate_review_options(args.model, args.timeout)
        dest = Path(args.output) if args.output else None
        if dest is not None and (dest.is_symlink() or dest.exists()):
            raise ValueError("Output exists")
        corpus, corpus_hash = read_bounded_json(args.corpus)
        report = run_local_benchmark(
            corpus, endpoint=args.endpoint, model=args.model,
            timeout=args.timeout, batch_budget=args.batch_budget)
        report["corpus_sha256"] = corpus_hash
        rendered = json.dumps(report, sort_keys=True, indent=2) + "\n"
        if dest is None:
            sys.stdout.write(rendered)
        else:
            with dest.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
            print("Aggregate metrics written; synthetic source and model replies omitted.")
        # An endpoint that never returned a completed answer is not a success.
        return 0 if report["local_endpoint_completions"] else 1
    except (OSError, ValueError, TypeError, UnicodeError):
        # Do not leak source data, prompts, URLs, tokens or remote error bodies.
        print("Local benchmark unavailable or input invalid.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
