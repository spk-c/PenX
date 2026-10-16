#!/usr/bin/env python3
"""Offline SOURCE package inventory export for explicitly authorized Debian/Ubuntu hosts."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess

def os_release():
    data = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k,v=line.split("=",1)
            data[k]=v.strip().strip('"')
    distro=data.get("ID","").lower()
    if distro not in ("ubuntu","debian"):
        raise ValueError("Only Debian and Ubuntu supported; create verified JSON manually for RHEL.")
    release=data.get("VERSION_CODENAME","").lower()
    if not release:
        raise ValueError("VERSION_CODENAME unavailable.")
    return distro,release

def export_sources(names: set[str]) -> list[dict]:
    proc=subprocess.run(["dpkg-query","-W","-f=${source:Package}\t${source:Version}\t${Status}\n"],
                        capture_output=True,text=True,check=True,timeout=30)
    result={}
    for line in proc.stdout.splitlines():
        parts=line.split("\t")
        if len(parts) < 3 or not parts[2].strip().endswith("installed"):
            continue
        source,version=parts[:2]
        if source not in names:
            continue
        if source in result and result[source] != version:
            raise ValueError("Conflicting source revisions for "+source+"; resolve manually.")
        result[source]=version
    missing=names.difference(result)
    if missing:
        raise ValueError("Source packages not installed: " + ", ".join(sorted(missing)))
    return [{"source":k,"version":v} for k,v in sorted(result.items())]

def main():
    parser=argparse.ArgumentParser(description="Export a minimal package inventory locally.")
    parser.add_argument("--sources",required=True,help="Comma-separated SOURCE packages, e.g. openssh,openssl")
    parser.add_argument("--output",required=True,help="Path to local JSON output")
    args=parser.parse_args()
    names={x.strip().lower() for x in args.sources.split(",") if x.strip()}
    if not names or len(names)>40:
        parser.error("Provide 1-40 source package names.")
    distro,release=os_release()
    info={"distro":distro,"release":release,"packages":export_sources(names)}
    target=Path(args.output).expanduser()
    target.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(str(target),os.O_WRONLY | os.O_CREAT | os.O_TRUNC,0o600)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as handle:
            json.dump(info,handle,indent=2)
            handle.write("\n")
    except Exception:
        try:os.close(fd)
        except OSError:pass
        raise
    print("Inventory written locally to",target)
    print("Review before sharing; package versions can disclose system details.")

if __name__=="__main__":
    main()
