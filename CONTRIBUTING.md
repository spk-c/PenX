# Contributing to PenX

Thanks for considering a contribution! PenX is a cross-platform, open-source security reconnaissance and local-AI analysis project. Contributions that improve reliability, documentation, test coverage, and user experience are particularly welcome.

## Before you start

- Open a [feature request](https://github.com/spk-c/PenX/issues/new/choose) to discuss substantial behavior changes before investing in a large patch. Check for duplicates first.
- Only test PenX against systems you own or have explicit permission to assess.
- Do not include scan output from third-party hosts, secret keys, .env files, local databases, or compiled scanner binaries in your contribution.
- Keep original upstream license notices intact; do not vendor third-party scanners into the repository.

## Local development

1. Clone the repository and install Python **3.13**.
2. On Windows, run `install-windows.bat`; on Kali/Debian/Ubuntu, run `bash ./install-linux.sh` to create a local virtual environment. Neither command performs an external security scan.
3. Run `run-tests.bat` on Windows or use the same test entrypoint as CI and releases:

   ~~~powershell
   python offline_tests.py
   ~~~

   `python offline_tests.py --list` shows every detected `tests/test_*.py` suite. The runner uses an isolated Python process for each test module; no remote hosts are scanned.

4. Keep UI strings, comments, documentation, and new features **in English**.
5. Update documentation and tests when changing behavior. Preserve explicit reporting for missing scanners or restricted fallbacks.

## Pull requests

- Complete the pull request description: explain the problem, the change, how it was tested, and whether scanner scope, permissions, or external downloads changed.
- For platform-specific installation fixes, include your Windows/Linux distribution and version, architecture, Python version, relevant command output, and sanitized error messages.
- Keep pull requests focused and avoid unrelated formatting changes.
- Use GitHub Actions and the offline test suite as a baseline; green CI is not a substitute for authorized Windows/Npcap or Kali/Linux scanner field checks.
- For scanner adapter changes, add bounded loopback fixtures and verify evidence, partial/failed outcomes, and JSON/SARIF exports without scanning unrelated hosts.

For sensitive security issues, follow [SECURITY.md](SECURITY.md) rather than posting exploit details in a public issue.
