# PenX v0.5.0 — release highlights

This release packages the optimization work merged after the
[v0.4.11](https://github.com/spk-c/PenX/releases/tag/v0.4.11) Windows build
(Phases 7–9 of the post-v0.4.11 optimization roadmap).

## Highlights

- **Faster CVE enrichment:** Product and package CVE lookups (NVD, OSV,
  GitHub Advisory) now run in a bounded worker pool with a dedicated
  NVD rate-limit queue and per-source error isolation. Result ordering
  is deterministic and covered by regression tests.
- **NVD disk cache on by default:** Upstream-public NVD records are
  cached locally for 24 hours (CPE-keyed, capped, opt-out via
  `PENX_NVD_DISK_CACHE=0`), reducing repeat-scan latency and NVD load.
- **Bounded local-AI usage:** The LLM call budget per scan is now
  verified by a dedicated regression suite, keeping model usage
  predictable on large finding sets.
- **Much faster test runs:** The offline test runner executes suites
  in parallel (4 workers locally, 2 on CI) with a per-suite 300 s
  timeout, `--workers` control and unchanged `--list` / `--keep-going`
  behavior. Measured locally: the full 223-suite run dropped from
  ~89 s to ~25 s (3.56x) with no suite behavior change.
- **Broader Python compatibility confidence:** The compatibility
  matrix now covers Python 3.10–3.13 and runs on a weekly schedule in
  addition to manual dispatch.
- **Stricter quality gates:** Ruff now enforces `W` and `B` (bugbear)
  on top of the existing rule set, and the mypy gate passes on
  Windows and Linux with identical results (121 files, no issues).
- **Cleaner module layout:** The legacy top-level shims `llm` and
  `app_paths` were retired after a documented import inventory; all
  consumers use the canonical `penx_app.*` paths. The `penx` module
  entrypoint (`python -m penx`, root `penx.py`) remains public API
  until v1 and is pinned by contract tests.

## Packaging and limitations

Windows downloads are published only after the immutable `v0.5.0` tag
triggers a successful Windows Release workflow, including the packaged
EXE/installer smoke tests and SHA-256 generation. Do not treat a version
bump or draft manifest as a published binary.

Independent field acceptance remains **NOT SIGNED OFF**. The
Windows/Npcap/12-scanner matrix
([#81](https://github.com/spk-c/PenX/issues/81)), database restore /
Windows upgrade / report recovery scenarios
([#82](https://github.com/spk-c/PenX/issues/82)) and some manual
hardware/visual scenarios remain outstanding. The installer is not
Authenticode-signed. External scanners and local AI models are not
bundled.

Use PenX only with explicit target authorization; scanner output and
model suggestions require independent validation.
