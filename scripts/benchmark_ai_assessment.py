#!/usr/bin/env python3
"""PX-403: deterministic labelled-fixture scoring, offline by design.

This script NEVER calls an LLM, scanner or network endpoint. It scores
operator-supplied JSON predictions against a pinned synthetic corpus.
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

from penx_app.analysis.ai_eval_benchmark import (  # noqa: E402
    read_bounded_json,
    score_predictions,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline PX-403 synthetic finding/evidence rubric (no model requests)")
    parser.add_argument("--corpus", default=str(
        ROOT / "tests" / "fixtures" / "ai_eval_corpus_v1.json"))
    parser.add_argument("--predictions", default=str(
        ROOT / "tests" / "fixtures" / "ai_eval_predictions_v1.json"))
    parser.add_argument("--output", help="Optional NEW JSON report file; never overwrite")
    args = parser.parse_args(argv)
    try:
        corpus, corpus_hash = read_bounded_json(args.corpus)
        predictions, predictions_hash = read_bounded_json(args.predictions)
        report = score_predictions(corpus, predictions)
        # Only SHA-256 anchors and aggregate counts are released. No case
        # evidence, quoted scanner text, finding IDs or supplied prompts.
        report["corpus_sha256"] = corpus_hash
        report["predictions_sha256"] = predictions_hash
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            out = Path(args.output)
            if out.is_symlink() or out.exists():
                raise ValueError("The report output file already exists")
            with out.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        else:
            sys.stdout.write(rendered)
    except (ValueError, OSError):
        # Never print source/prediction data, DB identifiers or paths.
        print("Evaluation rejected: invalid, untrusted, or unwritable input.",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
