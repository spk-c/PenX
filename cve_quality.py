"""Reproducible offline CVE/package-version quality gate.

Curated real published fix boundaries + explicitly marked synthetic edge cases.
This is NOT a live-host detection score, and never claims exploitability.
"""
from __future__ import annotations
import argparse
import json
import requests
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from penx_app.intelligence.package_inventory import compare_installed

CASES_PATH = Path(__file__).parent / "tests" / "fixtures" / "cve_quality_cases.json"

def evaluate_cases(cases: list[dict]) -> dict:
    rows = []
    counts = {"tp":0,"fp":0,"tn":0,"fn":0,"unknown":0}
    positives = {"below-published-fix"}
    negatives = {"at-or-above-published-fix"}
    for case in cases:
        actual = compare_installed(case["installed"],case["fixed"],case["kind"])
        expected = case["expected"]
        match = actual == expected
        if expected in positives and actual in positives:
            counts["tp"] += 1
        elif expected in positives and actual in negatives:
            counts["fn"] += 1
        elif expected in negatives and actual in positives:
            counts["fp"] += 1
        elif expected in negatives and actual in negatives:
            counts["tn"] += 1
        else:
            counts["unknown"] += 1
        rows.append({"id":case["id"],"expected":expected,"actual":actual,
                     "pass":match,"source":case["source"],
                     "synthetic":bool(case.get("synthetic",False))})
    tp,fp,fn,tn = (counts[k] for k in ("tp","fp","fn","tn"))
    precision = tp/(tp+fp) if tp+fp else None
    recall = tp/(tp+fn) if tp+fn else None
    return {"cases":len(rows),"passed":sum(r["pass"] for r in rows),
            "failed":sum(not r["pass"] for r in rows),"confusion":counts,
            "precision_on_classified_cases":precision,
            "recall_on_classified_cases":recall,
            "unknown_count":counts["unknown"],
            "note":"Fixture-level package-version boundary quality only. Not a real network detection metric.",
            "details":rows}

def live_catalogue_smoke() -> dict:
    """Optional real API smoke checks. No hosts are scanned; no private data sent."""
    from penx_app.intelligence.source_verification import lookup_nvd
    checks = []
    for cve in ("CVE-2024-6387", "CVE-2021-44228"):
        status = lookup_nvd(cve)
        checks.append({"source": "NVD", "id": cve, "status": status,
                       "pass": status == "listed"})
    try:
        response = requests.get("https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q",
                                timeout=(3, 10), allow_redirects=False)
        response.raise_for_status()
        data = response.json()
        ok = data.get("id") == "GHSA-jfh8-c2jp-5v3q"
        checks.append({"source": "OSV", "id": "GHSA-jfh8-c2jp-5v3q",
                       "status": "listed" if ok else "unavailable", "pass": ok})
    except (requests.RequestException, ValueError):
        checks.append({"source": "OSV", "id": "GHSA-jfh8-c2jp-5v3q",
                       "status": "unavailable", "pass": False})
    return {"checks": checks, "passed": sum(c["pass"] for c in checks),
            "note": "Live public API lookup only; does not prove CVE impact on a host."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json",action="store_true",help="Print machine-readable quality results")
    parser.add_argument("--live",action="store_true",help="Check public NVD/OSV records (may be rate-limited)")
    args=parser.parse_args()
    case_file=json.loads(CASES_PATH.read_text(encoding="utf-8"))
    result=evaluate_cases(case_file["cases"])
    if args.live:
        result["live_catalogue_smoke"] = live_catalogue_smoke()
    if args.json:
        print(json.dumps(result,indent=2,ensure_ascii=False))
    else:
        print(f"CVE quality fixture gate: {result['passed']}/{result['cases']} passed")
        print("Confusion:",result["confusion"])
        print(result["note"])
        for row in result["details"]:
            if not row["pass"]:
                print("FAIL:",row["id"],row["expected"],"vs",row["actual"])
    live_fail = args.live and any(not x["pass"] for x in result["live_catalogue_smoke"]["checks"])
    raise SystemExit(1 if result["failed"] or live_fail else 0)

if __name__=="__main__":
    main()
