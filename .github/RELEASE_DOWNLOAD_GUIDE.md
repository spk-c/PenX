<!-- penx-download-options-v1 -->

> **Availability:** Download the current Windows installer or portable ZIP from the [latest official PenX release](https://github.com/spk-c/PenX/releases/latest), together with its SHA-256 checksums. GitHub-generated source archives are not ready-to-run Windows applications.

## Which Windows download should I choose?

### ✅ Recommended: Windows Installer
**`PenX-Setup-x64.exe`** — best for most Windows 10/11 (64-bit) users.

- Installs PenX with a Start menu entry and an uninstall option.
- Saves your configuration, scan history and reports separately in `%LOCALAPPDATA%\PenX` so app updates do not overwrite them.
- Supports **Check for Updates** inside PenX. Installing an update always requires your confirmation.

### 📦 Alternative: Portable (no installation)
**`PenX-Windows-x64.zip`** — for users who prefer a portable folder.

- Download and **extract the entire ZIP**, then run `PenX\PenX.exe`.
- Keep the `_internal` folder and other extracted files with the executable.
- No Windows installer needed; you update manually by downloading a newer ZIP.
- Existing portable configuration and reports remain in your portable directory.

**Not sure? Choose `PenX-Setup-x64.exe`.** Both downloads contain the same PenX app version.

> **Important:** Do not choose GitHub's automatically generated **Source code (zip)** if you want a ready-to-run Windows app. Neither download bundles third-party scanners (such as Nmap/Npcap) or a local AI model; PenX can guide scanner setup with your consent.

You can verify either download using **`SHA256SUMS.txt`** from the same release. See the [Windows installation and migration guide](https://github.com/spk-c/PenX/blob/main/WINDOWS.md) before switching from the portable version to the installer.

> **Independent field acceptance: NOT SIGNED OFF.** Green CI checks validate automated contracts and packaged application smoke tests; they do **not** establish real Windows/Npcap behavior for all 12 scanners, installer upgrade/rollback, restored SQLite/MariaDB backups, or visual report quality. These checks remain tracked by [#81](https://github.com/spk-c/PenX/issues/81) and [#82](https://github.com/spk-c/PenX/issues/82). PHP2Shell version/header findings are not proof of RCE exploitation.

---
