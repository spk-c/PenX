#!/usr/bin/env python3
"""Deterministic, no-network refactor performance baseline.

Never imports a user's database, starts a scanner, or calls an LLM. Reports
measure process startup, authoritative scan metadata, JSON report assembly,
bounded history paging over a synthetic history table, and representative
HTML/PDF report rendering of the synthetic session through the same export
path the application uses. They are diagnostic measurements, not release
performance promises. Threshold limits in ``scripts/benchmark_thresholds.json``
are calibrated upper bounds that catch catastrophic regressions on comparable
hardware; they are not performance promises.

Microbenchmarks (synthetic projection, history paging, HTML/PDF export) use a
small number of discarded warmups followed by ``runs`` repeated comparable
iterations, and report median and range. The p95 is reported only when there
are at least five samples, the minimum for a meaningful p95. The optional
``--offline-tests`` flag additionally runs the full offline test suite once as
a subprocess and records its wall time and exit code; it is not part of the
fast microbenchmark.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
HISTORY_ROWS = 10_000
P95_MIN_SAMPLES = 5


def synthetic_session(count: int = 40) -> dict:
    """Build synthetic evidence with no real hosts or customer data."""
    findings = [
        (i, 1, f"Fixture observation {i}", "low", "possible", "443",
         "https", "Synthetic observation; review-required")
        for i in range(1, count + 1)
    ]
    return {
        "history": (1, "example.test", "2026-10-15", "active"),
        "summary": (1, 1, "fixture without real scanner output", "fixture",
                    "LOW", "synthetic-model", "2026-10-15"),
        "vulns": findings, "fixes": [], "corrections": [], "evaluations": [],
    }


def median_and_range(samples: list[float]) -> dict[str, float]:
    return {"median_ms": round(statistics.median(samples) * 1000, 2),
            "min_ms": round(min(samples) * 1000, 2),
            "max_ms": round(max(samples) * 1000, 2)}


def median_range_p95(samples: list[float]) -> dict[str, float]:
    """Median and range, plus p95 only when there are adequate samples."""
    result = median_and_range(samples)
    if len(samples) >= P95_MIN_SAMPLES:
        result["p95_ms"] = round(
            statistics.quantiles(samples, n=100, method="inclusive")[94] * 1000, 2)
    return result


def render_report(output_dir: str, fmt: str) -> int:
    """Render one synthetic session report ('html' or 'pdf') via the app path."""
    if fmt not in ("html", "pdf"):
        raise ValueError("Report format must be 'html' or 'pdf'")
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    from penx_app.reporting.export import export_html, export_pdf
    render = export_html if fmt == "html" else export_pdf
    path = Path(render(synthetic_session(), output_dir))
    if not path.is_file() or path.stat().st_size <= 0:
        raise RuntimeError(f"Export produced no {fmt} artifact: {path}")
    return path.stat().st_size


def export_once(output_dir: str) -> dict[str, int]:
    """Render one synthetic session through the application export path."""
    return {"html_bytes": render_report(output_dir, "html"),
            "pdf_bytes": render_report(output_dir, "pdf")}


def check_thresholds(data: dict, thresholds: dict[str, float]) -> list[str]:
    """Return workloads whose measured median exceeds the calibrated limit."""
    violations = []
    for name, limit in thresholds.items():
        workload = data.get(name)
        if not isinstance(workload, dict):
            violations.append(f"{name}: workload missing from benchmark output")
            continue
        limit = float(limit)
        if workload["median_ms"] > limit:
            violations.append(
                f"{name}: median {workload['median_ms']} ms exceeds "
                f"calibrated limit {limit:g} ms")
    return violations


def history_paging_samples(runs: int, warmups: int) -> list[float]:
    """Time bounded keyset paging over a synthetic history table.

    Builds a temporary SQLite history with HISTORY_ROWS rows (the same shape
    as the PX-104 paging fixture), then measures one bounded page per run.
    The table build is a one-time setup cost, not part of the measured loop.
    """
    import sqlite3
    from contextlib import closing
    from penx_app.storage.db_backend import SQLiteConnection
    from penx_app.storage.schema_migrations import initialize_sqlite
    from penx_app.storage.session_repository import SessionRepository

    with tempfile.TemporaryDirectory(prefix="penx-history-benchmark-") as tmp:
        database = Path(tmp) / "history.sqlite3"
        with closing(sqlite3.connect(database)) as db:
            initialize_sqlite(db)
            entries = [
                (f"host-{i % 23}.example.test", "2026-11-04 10:00:00",
                 "active" if i % 7 else "pending")
                for i in range(1, HISTORY_ROWS + 1)
            ]
            db.executemany(
                "INSERT INTO history (target, scan_date, status) VALUES (?, ?, ?)",
                entries)
            db.commit()

        def factory():
            raw = sqlite3.connect(database)
            return SQLiteConnection(raw)

        repo = SessionRepository(factory)
        for _ in range(warmups):
            repo.history_page(limit=100)
        samples: list[float] = []
        for _ in range(runs):
            start = time.perf_counter()
            repo.history_page(limit=100)
            samples.append(time.perf_counter() - start)
        return samples


def measure_offline_tests(timeout: int = 600) -> dict:
    """Run the full offline test suite once as a subprocess and record runtime.

    This is a coarse, opt-in measurement, not a microbenchmark. It is not
    part of the fast ``measure()`` path so the benchmark stays reproducible and
    independent of the (possibly unavailable) heavy test dependencies.
    """
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, "offline_tests.py"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        stdin=subprocess.DEVNULL, cwd=ROOT, timeout=timeout, check=False,
    )
    elapsed = time.perf_counter() - start
    return {
        "returned": result.returncode,
        "ok": result.returncode == 0,
        "wall_ms": round(elapsed * 1000, 2),
        "workers": os.cpu_count(),
    }


def measure(runs: int = 5, warmups: int = 2) -> dict:
    if not 1 <= runs <= 10:
        raise ValueError("Benchmark runs must be between 1 and 10")
    sys.path.insert(0, str(SRC))
    from penx_app.domain.scan_models import ScannerResult, ScanResult
    from penx_app.reporting.machine_reports import report_payload
    from penx_app.reporting.report_view import ReportView

    cold: list[float] = []
    for _ in range(runs):
        start = time.perf_counter()
        result = subprocess.run(
            [sys.executable, str(ROOT / "penx.py"), "--version"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            stdin=subprocess.DEVNULL, cwd=ROOT, timeout=20, check=False,
        )
        cold.append(time.perf_counter() - start)
        if result.returncode != 0 or "PenX" not in result.stdout:
            raise RuntimeError("The launcher failed its noninteractive --version smoke test")

    scan = ScanResult(tuple(
        ScannerResult(f"fixture-{n}", f"synthetic scanner output {n}",
                      "COMPLETE" if n % 8 else "FAILED", n % 8 != 0, f"Fixture {n}")
        for n in range(1, 13)
    ))
    session = synthetic_session()
    # Warmup so the projection loop measures steady state, not import/cache fills.
    for _ in range(warmups):
        metadata = ScanResult.from_metadata(scan.metadata())
        view = ReportView.from_session(session)
        payload = report_payload(view.as_legacy())
        json.dumps(payload, ensure_ascii=False)
    projection: list[float] = []
    tracemalloc.start()
    try:
        for _ in range(runs):
            start = time.perf_counter()
            metadata = ScanResult.from_metadata(scan.metadata())
            view = ReportView.from_session(session)
            payload = report_payload(view.as_legacy())
            # Force actual JSON encoding in addition to building the mapping.
            encoded = json.dumps(payload, ensure_ascii=False)
            if not metadata.has_evidence or len(payload["findings"]) != 40 or not encoded:
                raise RuntimeError("Synthetic report contract failed")
            projection.append(time.perf_counter() - start)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    html_export: list[float] = []
    pdf_export: list[float] = []
    export_bytes: dict[str, int] = {}
    for _ in range(warmups):
        with tempfile.TemporaryDirectory(prefix="penx-benchmark-") as tmp:
            render_report(tmp, "html")
            render_report(tmp, "pdf")
    for _ in range(runs):
        with tempfile.TemporaryDirectory(prefix="penx-benchmark-") as tmp:
            start = time.perf_counter()
            html_size = render_report(tmp, "html")
            html_export.append(time.perf_counter() - start)
            start = time.perf_counter()
            pdf_size = render_report(tmp, "pdf")
            pdf_export.append(time.perf_counter() - start)
            export_bytes = {"html_bytes": html_size, "pdf_bytes": pdf_size}

    history_paging: list[float] = history_paging_samples(runs, warmups)

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=5, check=False,
        )
        commit_id = commit.stdout.strip() if commit.returncode == 0 else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        commit_id = "unknown"
    return {
        "schema": "penx-refactor-benchmark-v2",
        "commit": commit_id,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "runs": runs,
        "warmups": warmups,
        "worker_count": os.cpu_count(),
        "launcher_version": median_range_p95(cold),
        "synthetic_projection": median_range_p95(projection),
        "projection_peak_bytes": peak,
        "history_paging": median_range_p95(history_paging),
        "html_export": median_range_p95(html_export),
        "pdf_export": median_range_p95(pdf_export),
        "export_bytes": export_bytes,
        "fixture": {"scanners": 12, "findings": 40, "history_rows": HISTORY_ROWS,
                    "real_targets": False},
        "limitations": (
            "Synthetic local measurements only; no scan/network/LLM workload. "
            "HTML/PDF export renders the synthetic session through the "
            "application export path. History paging uses a temporary "
            f"{HISTORY_ROWS}-row SQLite history. Compare equal machines, Python "
            "versions and fixture sizes. Peak memory is the traced Python "
            "allocation peak (tracemalloc), not OS-level process RSS. Offline "
            "test runtime is only recorded with --offline-tests and is not part "
            "of the fast microbenchmark."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--output", type=Path, help="Optional JSON output path")
    parser.add_argument("--check-thresholds", type=Path, metavar="JSON",
                        help="Fail if any workload median exceeds the "
                             "calibrated limits in the given JSON file")
    parser.add_argument("--offline-tests", action="store_true",
                        help="Also run the full offline test suite once as a "
                             "subprocess and record its wall time and exit code")
    options = parser.parse_args(argv)
    try:
        data = measure(options.runs, options.warmups)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Benchmark failed: {exc}", file=sys.stderr)
        return 1
    if options.offline_tests:
        try:
            data["offline_tests"] = measure_offline_tests()
        except (OSError, subprocess.TimeoutExpired) as exc:
            data["offline_tests"] = {"returned": None, "ok": False,
                                     "wall_ms": None, "workers": os.cpu_count(),
                                     "error": str(exc)}
    if options.check_thresholds:
        try:
            thresholds_doc = json.loads(
                options.check_thresholds.read_text(encoding="utf-8"))
            thresholds = thresholds_doc["limits"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"Threshold file unreadable: {exc}", file=sys.stderr)
            return 1
        violations = check_thresholds(data, thresholds)
        data["threshold_check"] = {
            "file": str(options.check_thresholds),
            "passed": not violations,
            "violations": violations,
        }
    result = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if options.output:
        options.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")
    if options.check_thresholds and not data["threshold_check"]["passed"]:
        for line in data["threshold_check"]["violations"]:
            print(f"Threshold exceeded: {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
