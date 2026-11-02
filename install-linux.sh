#!/usr/bin/env bash
# Install from source without touching system Python or scanning networks.
set -euo pipefail
cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

usage() {
  printf '%s\n' 'Usage: ./install-linux.sh [--with-scanners]' \
    'Default: install Python dependencies into .venv only.' \
    '--with-scanners: explicitly request apt installation of nmap, whatweb and nikto.'
}
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then usage; exit 0; fi
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--with-scanners" ) ]]; then
  usage >&2; exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then echo "Linux only" >&2; exit 2; fi
python3 - <<'PY'
import sys
if not ((3, 10) <= sys.version_info[:2] < (3, 14)):
    raise SystemExit("PenX requires CPython 3.10–3.13")
print("Using Python", sys.version.split()[0])
PY
if [[ "${1:-}" == "--with-scanners" ]]; then
  command -v apt-get >/dev/null || { echo "apt-get required for --with-scanners" >&2; exit 2; }
  if [[ $EUID -eq 0 ]]; then
    apt-get update
    apt-get install -y nmap whatweb nikto
  else
    command -v sudo >/dev/null || { echo "sudo required for --with-scanners" >&2; exit 2; }
    sudo apt-get update
    sudo apt-get install -y nmap whatweb nikto
  fi
fi
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check --require-hashes -r requirements.lock.txt
.venv/bin/python -m pip install --disable-pip-version-check --no-deps -e .
echo
echo "PenX installed in .venv; no system Python packages changed."
echo "Launch: .venv/bin/penx"
echo "Check:  .venv/bin/penx --setup-status"
echo "Other scanners must be installed separately; see LINUX.md"
