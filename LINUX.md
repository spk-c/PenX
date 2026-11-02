# PenX on Linux and Kali Linux

PenX uses the **same Python application** on Windows and Linux. Linux support
is under development for the v0.6.0 milestone; the published v0.5.0 release
still provides Windows binaries only. Do not mistake an unmerged PR or
successful offline test for a finished Kali field-verified release.

## Requirements

- x86-64 or ARM64 Linux (Debian/Ubuntu/Kali preferred)
- CPython **3.10 to 3.13** for source installation
- Network access only to install dependencies and for intentionally selected
  scanners/CVE research, never for `--version` or `--setup-status`
- Optional third-party scanners, installed separately; no scanners or LLM
  weights are bundled into the PenX Python package or the binaries
- Optional local OpenAI-compatible model endpoint (e.g. Ollama or llama.cpp)

### Install from source (Kali, Debian, Ubuntu)

```bash
sudo apt update
sudo apt install git python3 python3-venv python3-pip
git clone https://github.com/spk-c/PenX.git
cd PenX
bash ./install-linux.sh
.venv/bin/penx --version
.venv/bin/penx --setup-status
.venv/bin/penx --check
.venv/bin/penx
```

Run the commands on the Linux-support branch until v0.6.0 is merged.
If your distribution's default Python is outside 3.10–3.13, install a
supported interpreter in a separate venv (do not override system Python).

To explicitly install the common distribution scanners during setup:

```bash
bash ./install-linux.sh --with-scanners
```

This asks for sudo permission if required, uses apt to install **nmap**,
**whatweb** and **nikto**, and should only be used on supported apt-based
systems. Other tools (Nuclei, ProjectDiscovery httpx, ffuf, Subfinder, Katana)
are optional; install their official Linux releases separately and put them
on PATH. For `httpx`, PenX verifies the executable is the ProjectDiscovery
scanner, not the unrelated Python `httpx` utility. Override with
`PENX_HTTPX_PATH` if needed.

The Linux package includes an example configuration. Running `penx --setup` creates a private per-user `.env` file with permissions `0600` without invoking any scanner or package manager. The same sample is bundled with Python-wheel installations.

The shell setup installs Python dependencies into **.venv** only. It does not
perform any security scan and will not modify system packages unless you
explicitly pass `--with-scanners`.

### Install packaged build

A Linux CI build produces `PenX-Linux-x86_64.tar.gz` (or ARM64) and
`penx_<version>_amd64.deb` (or arm64). The latest **published** release
should be consulted for official downloadable assets; development CI artifacts
are not signed releases.

```bash
# After obtaining a release .deb and verifying its SHA-256:
sudo apt install ./penx_*.deb
penx --version
penx --check
```

The Debian installer places binaries in `/opt/penx/PenX` with a launcher
`/usr/bin/penx`. It does not install optional scanners or auto-start any
service. Package upgrades/uninstallation are handled by apt/dpkg rather than
the Windows installer updater.

Portable archive:

```bash
tar -xzf PenX-Linux-x86_64.tar.gz
./PenX/PenX --version
```

### Persistent data and privacy

A Debian-installed PenX or Python wheel installation writes per-user state to
`${XDG_DATA_HOME:-~/.local/share}/PenX` (including the local `.env`,
`data/` and `reports/`). An extracted portable archive uses its own folder,
and a source checkout preserves its local working directory. Avoid running
the main PenX process with sudo; only individual scanner modes may require
additional privileges. Use ordinary user permissions to protect assessment
data; never publish `.env` or reports with secrets.

`penx --setup` copies `.env.example` to a private `.env` when available
and reports missing scanner binaries, without installing any OS packages.
`penx --check` is a non-networking Linux dependency check. Use
`penx --llm-setup` to configure a local API if desired.

### Known limitations and acceptance

- Linux `--update` is **not** a package manager; upgrade via apt/dpkg.
- A passing Ubuntu offline test does **not** prove Nmap raw sockets, all 12
  scanner adapters, sudo, LLM connectivity or Kali-specific integrations work.
- CI runs a Kali rolling container package smoke test without real network target scanning. This does not replace manual acceptance of real scanner workflows.
- Verify the CLI on Kali, Ubuntu and Debian using explicitly authorized test
  targets. Check tool presence, cancellation/timeouts, HTML/PDF/JSON/SARIF
  exports, SQLite recovery and local AI before calling the port production-ready.
- Linux binary builds are host-specific: build separately for amd64 and arm64,
  with a compatible glibc baseline. PyInstaller is not a cross-compiler.
- A Linux installation does not use the Windows Npcap driver.

### Build packages on Linux

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock.txt
.venv/bin/pip install -r requirements-build.txt
.venv/bin/python scripts/build_linux.py
.venv/bin/python packaging/linux/build_packages.py
```

`dpkg-deb` (package `dpkg-dev`) is required for the `.deb` step.
Neither script automatically publishes a GitHub release or uploads packages.
