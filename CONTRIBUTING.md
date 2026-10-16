# Contributing to PenX

Thanks for considering a contribution! PenX is a Windows-focused, open-source security reconnaissance and local-AI analysis project. Contributions that improve reliability, documentation, test coverage, and user experience are particularly welcome.

## Before you start

- Open a [feature request](https://github.com/SLP-DEV1/PenX/issues/new/choose) to discuss substantial behavior changes before investing in a large patch. Check for duplicates first.
- Only test PenX against systems you own or have explicit permission to assess.
- Do not include scan output from third-party hosts, secret keys, .env files, local databases, or compiled scanner binaries in your contribution.
- Keep original upstream license notices intact; do not vendor third-party scanners into the repository.

## Local development

1. Clone the repository and install Python **3.13**.
2. On Windows, run install-windows.bat to configure the virtual environment. You can run the offline tests without scanning any outside targets.
3. Run `run-tests.bat` on Windows or use the same test entrypoint as CI and releases:

   ~~~powershell
   python offline_tests.py
   ~~~

   `python offline_tests.py --list` shows every detected `tests/test_*.py` suite. The runner uses an isolated Python process for each test module; no remote hosts are scanned.

4. Keep UI strings, comments, documentation, and new features **in English**.
5. Update documentation and tests when changing behavior. Preserve explicit reporting for missing scanners or restricted fallbacks.

## Pull requests

- Complete the pull request template: explain the problem, the change, how it was tested, and whether scanner scope, permissions, or external downloads changed.
- For Windows-specific installation fixes, include the Windows version, Python version, relevant command output, and sanitized error messages.
- Keep PRs focused and avoid unrelated formatting changes.
- Use the existing GitHub Actions checks as a baseline; a green offline test suite is not a substitute for verifying scanner behavior on Windows.

For sensitive security issues, follow [SECURITY.md](SECURITY.md) rather than posting exploit details in a public issue.
