# Windows installer field acceptance: what CI proves and what it does not

The GitHub Actions Windows packaging job compiles Inno Setup on an ephemeral
Windows runner, silently installs to an isolated folder in `RUNNER_TEMP`,
invokes `PenX.exe --version` and `--setup-status` (no scans or installs),
then **runs the generated uninstaller**. It checks that the executable is
removed and that a unique marker in the current runner user's
`%LOCALAPPDATA%\PenX` user-data folder survives. Only the test marker
is deleted during cleanup. No production devices, credentials, settings,
databases or scan targets are modified by this CI verification.

This is repeatable, automated **install/uninstall** evidence for the build
tested in the PR. It is *not* evidence of:

- A full first interactive run with user-approved Npcap driver elevation
  and separately installed third-party scanners.
- An upgrade from a previous signed/unsigned PenX installation, preservation
  of actual historical sessions, rollback after interrupted upgrades, or
  repair/reinstall behavior.
- Successful execution on a physical user's Windows installation, Authenticode
  signing, or Windows SmartScreen reputation.
- An actual power failure or MariaDB/SQLite production-shaped backup restore.

For final Pk11 sign-off, a maintainer must run those scenarios on a dedicated
Windows VM with a disposable account, authorized scanner targets and a
*restorable sanitized copy* of all fixtures. Record immutable build SHA,
`PenX-Setup-x64.exe` SHA256, Windows build, Npcap version, commands,
screenshots/logs, expected/actual behavior and maintainer/date in the
[field acceptance checklist](FIELD_ACCEPTANCE.md). Do not use
production/customer data or claim CI passed those physical tests.
