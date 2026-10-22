# PenX v0.4.11 — release highlights

This release packages changes merged after the [v0.4.10](https://github.com/spk-c/PenX/releases/tag/v0.4.10) Windows build.

## Highlights

- **Scan evidence and comparisons:** Improved traceability from scanner observations to findings, more careful treatment of incomplete coverage and stronger endpoint-scoped finding identity.
- **Headless scanning and CI:** Non-interactive authorized collection with bounded execution, structured JSON/SARIF output and explicit exit codes for partial results, scanner errors and finding thresholds.
- **Flexible scanner configuration:** Typed profiles, independent scan preflight, bounded scheduling and configuration validation. Existing scanner consent requirements remain in place.
- **Guided beginner scanning:** A simpler flow for choosing explicitly authorized scopes and suitable scan profiles.
- **Local AI review:** Optional bounded local-model review of previously collected evidence with stronger input validation; review suggestions are not vulnerability confirmations.
- **PHP2Shell checks:** Offline review of configuration and log indicators plus a **non-exploiting** live HTTP header/version assessment. The live check **does not execute an exploit** and cannot confirm remote code execution or patch state by itself.
- **Stability and repository security:** Additional safeguards for metadata parsing, scan result integrity, artifact recovery, reporting, database edge cases and CI checks on main. Stale topic branches were cleaned up and `main` protection enabled.

## Packaging and limitations

Windows downloads are published only after the immutable `v0.4.11` tag triggers a successful Windows Release workflow, including the packaged EXE/installer smoke tests and SHA-256 generation. Do not treat a version bump or draft manifest as a published binary.

Independent field acceptance remains **NOT SIGNED OFF**. The Windows/Npcap/12-scanner matrix ([#81](https://github.com/spk-c/PenX/issues/81)), database restore / Windows upgrade / report recovery scenarios ([#82](https://github.com/spk-c/PenX/issues/82)) and some manual hardware/visual scenarios remain outstanding. The installer is not Authenticode-signed. External scanners and local AI models are not bundled.

Use PenX only with explicit target authorization; scanner output and model suggestions require independent validation.
