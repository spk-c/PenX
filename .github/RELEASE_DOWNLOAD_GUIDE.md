<!-- penx-download-options-v1 -->

## Download PenX

Choose the package for your platform from the [latest official GitHub Release](https://github.com/spk-c/PenX/releases/latest). Use the **release Assets**, not the automatically generated **Source code (zip)** or source tarball, if you need a ready-to-run executable.

| Platform | Edition | Download |
| --- | --- | --- |
| **Windows 10/11 (x64)** | **Installer — recommended** | [PenX-Setup-x64.exe](https://github.com/spk-c/PenX/releases/latest/download/PenX-Setup-x64.exe) |
| Windows (x64) | **Portable (no installation)** | [PenX-Windows-x64.zip](https://github.com/spk-c/PenX/releases/latest/download/PenX-Windows-x64.zip) |
| **Kali / Debian / Ubuntu (amd64)** | Debian package | Find `penx_<version>_amd64.deb` under [release assets](https://github.com/spk-c/PenX/releases/latest) |
| Linux (x86-64) | Portable archive | [PenX-Linux-x86_64.tar.gz](https://github.com/spk-c/PenX/releases/latest/download/PenX-Linux-x86_64.tar.gz) |

**Verify your download:** use `SHA256SUMS.txt` for Windows, or `SHA256SUMS-Linux.txt` for Linux, from the **same release**.

**Getting started:** Windows installer creates Start menu and uninstall entries, and saves user data under `%LOCALAPPDATA%\PenX`. For portable Windows, extract the **entire ZIP** and run `PenX\PenX.exe`, keeping `_internal` beside it. For Linux Debian packages, see [LINUX.md](https://github.com/spk-c/PenX/blob/main/LINUX.md); portable users extract the TAR.GZ and run `./PenX/PenX`. Third-party scanners, Npcap and AI model weights are **not bundled**.

> **Independent field acceptance: NOT SIGNED OFF.** Passing CI and packaged-app tests does not prove all real Windows/Npcap scanners, Linux distributions, database recovery, report layouts, upgrades or model/provider integrations. The Windows installer is not Authenticode-signed. Assess only authorized systems, and verify scanner/AI findings. See the [Linux acceptance record](https://github.com/spk-c/PenX/blob/main/docs/LINUX_ACCEPTANCE_2026-11-02.md), [Windows guide](https://github.com/spk-c/PenX/blob/main/WINDOWS.md) and [security policy](https://github.com/spk-c/PenX/blob/main/SECURITY.md).

---
