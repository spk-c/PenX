# PenX Deep Bug Audit — 2026-11-04

Audit-Objekt: Branch `fix/px003-retention-readonly-verification` @ `d87e75f`
(enthält die beiden Fixes aus PR #155: `8547d64` stdout-Retention, `d87e75f` read-only-Fallback)
Audit-Modus: **read-only** — keine Programmcode-Änderungen, kein Commit/Push.

## Executive Summary

Der vollständige erste Partei-Quellbaum (`src/penx_app`, 139 `.py`-Dateien) wurde durch einen
kombinierten Ansatz geprüft: (1) detaillierter manueller Review der kernelnahen Module
(Subprocess-Lifecycle, Storage/SQLite, Atomic-I/O, Schema-Migration, Backup/Restore,
Reporting, Domain-Verträge, LLM-Client, CVE-Engine, passive Recon, Setup/Installer),
(2) systematische Pattern-Scans über den gesamten Baum, (3) ruff-Lint und (4) der
komplette Offline-Testlauf.

**Ergebnis: keine neuen P0/P1/P2-Befunde.** Vier neue P3-Befunde (alle SUSPECTED/latent)
wurden dokumentiert. Die zwei vor diesem Audit behobenen P3-Fehler (read-only-Fallback
und stdout-Retention) sind im Audit-Ziel enthalten, haben deterministische
Regressionstests und laufen im Volltest grün.

| Kennzahl | Wert |
|---|---|
| P0 (kritisch, bestätigt) | 0 |
| P1 (hoch, bestätigt) | 0 |
| P2 (mittel, bestätigt) | 0 |
| P3 (niedrig) | 4 (alle SUSPECTED/latent) + 2 behobene (verifiziert) |
| ruff `src tests offline_tests.py` | All checks passed |
| Offline-Suiten auf `d87e75f` | **258 / 258 PASS** |

## Findings Summary

Status-Stand: 2026-11-04, Branch `fix/p3-audit-hardening` — **N1–N4 alle behoben**
(jeweils mit Regressionstest, s. Detailabschnitte).

| ID | Schwere | Konfidenz | Modul | Kurzbeschreibung | Status |
|----|---------|-----------|-------|------------------|--------|
| N1 | P3 | Mechanik: HIGH CONFIDENCE / Auswirkung: SUSPECTED (latent) | `intelligence/cve_engine.py:191-204` | `time.sleep()` innerhalb von `with _NVD_RATE_LOCK:` (sleep-while-holding-lock) | **behoben** + Test |
| N2 | P3 | SUSPECTED (latent) | `intelligence/source_verification.py:20-23` | Module-Global Caches (`_nvd_cache`, `_kev_cache`) ohne Lock | **behoben** + Test |
| N3 | P3 | SUSPECTED (by design) | `updates.py:195` | `subprocess.Popen`-Installer wird nie gewartet, Exit-Code nie gelesen | **behoben** + Test |
| N4 | P3 | SUSPECTED | `storage/backup.py:94,172,207,280` | `?mode=ro`-Öffnungen ohne Plain-Connect-Fallback (gleiche Robustheits-Klasse wie behobener F1) | **behoben** + Test |
| F1 (behoben) | P3 | CONFIRMED fix, verifiziert | `application/evidence_verification.py` | read-only Factory mit Fallback bei striktem `?mode=ro`-Ablehnung | verifiziert |
| F2 (behoben) | P3 | CONFIRMED fix, verifiziert | `application/scanner_execution.py` | Retention-Fehler (`OSError`/`ValueError`) → Zeile bleibt COMPLETE mit Diagnose | verifiziert |

## Detailed Findings

### N1 — Sleep unter Lock im NVD-Rate-Limiter (P3, SUSPECTED/latent)

- **Pfad + Zeilen:** `src/penx_app/intelligence/cve_engine.py:191-204`
  (`def _nvd_before_request`, Line 194 `with _NVD_RATE_LOCK:`, Line 203 `time.sleep(...)`).
- **Ursache:** Der Sliding-Window-Rate-Limiter hält `_NVD_RATE_LOCK`
  (Line 42: `_NVD_RATE_LOCK = threading.Lock()`) über die gesamte `time.sleep()`-Aufrufdauer (max. `NVD_WINDOW_SECONDS` = 30 s).
- **Trigger:** Zwei Threads, die gleichzeitig ein NVD-Budget-Réservierung versuchen, während das Budget erschöpft ist.
- **Erwartet vs. aktuell:** Erwartet: Lock nur für die Deque-Mutation (Mikrosekunden), Sleep außerhalb des Locks. Aktuell: Ein zweiter Thread blockiert am Lock für die volle Sleep-Dauer des ersten Threads.
- **Impact:** In der aktuellen Architektur **latent**: Der Kommentar auf Line 589-591 belegt, dass NVD-Queries bewusst serial auf dem Aufrufer-Thread bleiben (nur OSV/GitHub laufen im `ThreadPoolExecutor(max_workers=3)` auf Line 596). Beide NVD-Call-Stellen (Discovery via `_get(..., before_request=...)` und `source_verification.lookup_nvd`) laufen auf demselben Evaluation-Thread. In der Praxis: kein beobachtbarer Effekt. Bei zukünftiger Parallelisierung: serielle Wartezeiten bis 3 × 30 s.
- **Repro (statisch):** Code-Lektüre Lines 191-204; kein Test übt die Funktion mit zwei Threads.
- **Code-Evidenz:**
  ```python
  with _NVD_RATE_LOCK:
      history = _NVD_REQUESTS[has_key]
      while True:
          now = time.monotonic()
          while history and now - history[0] >= NVD_WINDOW_SECONDS:
              history.popleft()
          if len(history) < budget:
              history.append(now)
              return
          time.sleep(max(0.001, NVD_WINDOW_SECONDS - (now - history[0])))
  ```
- **Empfohlener Fix:** Wartezeit innerhalb des Locks berechnen, Lock freigeben, schlafen, dann neu prüfen und re-loopen (klassisches double-check nach Lock-Release).
- **Regressionstest (empfohlen):** Unit-Test mit zwei Threads und kleinem Fenster/Budget; Assert, dass die Gesamtdauer kleiner ist als `2 × window`.
- **Fix-Status (2026-11-04, `fix/p3-audit-hardening`):** Behoben — Wartezeit wird jetzt im Lock berechnet, `time.sleep` läuft außerhalb; Loop prüft nach dem Sleep neu. Deterministischer zwei-Thread-Test `tests/test_cve_reliability_20261101.py::test_rate_wait_does_not_hold_the_lock` (synthetische Uhr; der Worker schläft, während der Main-Thread den Lock erfolgreich übernimmt). Test schlägt am alten Code fehl (`AssertionError: False is not true`), neu grün.

### N2 — Ungelockte Module-Global-Caches (P3, SUSPECTED/latent)

- **Pfad + Zeilen:** `src/penx_app/intelligence/source_verification.py:20-23`
  (`_nvd_cache`, `_nvd_cache_time`, `_kev_cache`, `_kev_cache_time`), Schreibzugriffe Line 101-102 und 168-169.
- **Ursache:** Mutable module-level dicts/set werden ohne Lock gelesen und geschrieben.
- **Trigger:** Koncurrente Aufrufe von `lookup_nvd`/`load_cisa_kev`/`verify_findings`.
- **Erwartet vs. aktuell:** Erwartet: entweder Lock oder explizite Single-Thread-Garantie. Aktuell: GIL-basierte Atomizität pro Einzeloperation; KEV-Reads geben defensive `.copy()` (Line 146) zurück, daher keine Mutation durch Caller.
- **Impact:** Latent (gleiche Single-Thread-Begründung wie N1). Schlimmster Fall unter Parallelität: doppelte HTTP-Requests (benign, Rate-Limit wird via N1-Mechanik trotzdem eingehalten), last-writer-wins bei Cache-Write. Keine Datenkorruption möglich: alle Values pro Key sind konsistent.
- **Repro (statisch):** Lektüre der Cache-Read/Write-Paare (Lines 83-85 vs. 101-102; Lines 143-146 vs. 168-169).
- **Empfohlener Fix:** Dokumentieren (Single-Thread-Kontrakt), oder bei Parallelisierungsabsicht einen gemeinsamen Lock mit N1 einführen.
- **Regressionstest:** Optional; Concurrency-Smoke-Test mit gepatchter `time` und zwei Threads.
- **Fix-Status (2026-11-04, `fix/p3-audit-hardening`):** Behoben — `_source_cache_lock` (`threading.Lock`) schützt beide Cache-Paare; Status und Zeitstempel werden zusammen geschrieben, KEV-Cache wird nur ersetzt (nie in-place mutiert), Reads geben weiterhin defensive Kopien zurück. Concurrency-Smoke-Tests `tests/test_repeated_source_verification.py::test_concurrent_first_lookups_leave_a_consistent_cache` und `::test_concurrent_kev_loads_return_identical_membership` (je 8 Threads, gepatchtes `requests.get`, synthetische NVD-Uhr). Die Smoke-Tests pinnen den Konsistenz-Vertrag; am alten Code sind sie grün (latent), da der Race unter der GIL nicht deterministisch abbricht.

### N3 — Installer-Popen ohne Warten (P3, SUSPECTED/by design)

- **Pfad + Zeilen:** `src/penx_app/updates.py:195`
  (`subprocess.Popen([str(installer)], shell=False, cwd=str(installer.parent))` in `update_interactive`).
- **Ursache:** Das `Popen`-Objekt wird verworfen; weder `wait()` noch Join; Exit-Code wird nie inspiziert.
- **Trigger:** Nutzer bestätigt das Update; der GUI-Installer wird gestartet und beendet sich (Erfolg oder Fehlschlag).
- **Erwartet vs. aktuell:** Erwartet: Installer-Fehlschlag wird dem Nutzer gemeldet. Aktuell: `update_interactive` gibt `True` direkt nach dem Start zurück; der Fortschritt liegt beim GUI-Installer.
- **Impact:** Best-effort-UX. Der Installer ist checksummen-verifiziert (Lines 147-150), und die alte Version bleibt bis zum Abschluss des Installers intakt — keine Daten-/Versions-Korruption. Bewusstes Design ("Starting interactive setup...").
- **Repro (statisch):** Code-Lektüre; Runtime: Stub-Installer mit Exit-Code 1 starten.
- **Empfohlener Fix:** Entweder dokumentieren (fire-and-forget ist beabsichtigt) oder ein `proc.wait()` in einem Daemon-Thread mit Ergebnis-Ausgabe.
- **Regressionstest:** Optional; gepatchtes `Popen`, Assert auf dokumentiertes Verhalten.
- **Fix-Status (2026-11-04, `fix/p3-audit-hardening`):** Behoben — `update_interactive` wartet jetzt synchron auf den Installer (`process.wait()`) und meldet das Ergebnis: Exit 0 → `[OK] ... successfully`, Exit 2/5 → Abbruch (Warnung, `False`), Exit 8 → Neustart vor erneutem Versuch nötig (`False`), alle übrigen Nonzero-Codes → Fehler und `False` (damit liefert `--update` per `bootstrap.py` den korrekten Prozess-Exit-Code). Regressionstest `tests/test_installer_updates.py::test_installer_exit_code_is_waited_and_reported` (Exit 0/1/2/3/4/5/8/999; assertet `wait()`-Aufruf und Rückgabewert; ohne globale `os.name`-Manipulation). Test schlägt am alten Code fehl (`Expected 'wait' to be called once. Called 0 times.` / `True != False`), neu grün.

### N4 — `?mode=ro`-Öffnungen in backup.py ohne Fallback (P3, SUSPECTED)

- **Pfad + Zeilen:** `src/penx_app/storage/backup.py:94` (`create_backup`), `172` (`verify_backup`), `207` (`preview_restore`), `280` (`_restore_unlocked`).
- **Ursache:** Strenge read-only-URI-Öffnung (`sqlite3.connect(uri + "?mode=ro", uri=True)`) ohne Fallback auf einen normalen `sqlite3.connect`. Gleiche Robustheits-Klasse wie der vor diesem Audit behobene F1 in `evidence_verification.py`.
- **Trigger:** (a) DB-Datei auf read-only Media (SQLITE_CANTOPEN, kein Journal erstellbar), (b) DB-Datei in WAL-Mode mit unzugänglichen `-wal`/`-shm`. Der Live-DB liegt der Default `delete`-Journal-Mode zu (`journal_mode` wird nirgendwo anders gesetzt — per grep bestätigt, nur `backup.py:282,294`), daher betrifft dies nur Sonderzustände.
- **Erwartet vs. aktuell:** Erwartet: Fallback wie in F1 (Plain-Connect bei `OperationalError`). Aktuell: `OperationalError` → in `create_backup`/`restore` als `BackupError`/`OperationalError` fail-closed (Live-DB byte-identisch), in `verify_backup`/`preview_restore` als "database unreadable" (gültiges Backup kann abgelehnt werden).
- **Impact:** Fail-closed, keine Datenverluste. Nur Grenzfälle (RO-Volumen, WAL-Datei) betroffen.
- **Repro (statisch + empirisch):** Wie bei F1: auf dieser Windows-Plattform öffnet `?mode=ro` in allen getesteten Crash-Zuständen erfolgreich; der RO-Media-Fall benötigt ein read-only Volume bzw. eine künstliche WAL-Datei.
- **Empfohlener Fix:** Gemeinsamer Helper `_open_ro(path)` mit dem F1-Muster (`try: ro-URI / except sqlite3.OperationalError: plain connect`) für alle vier Stellen; `PRAGMA query_only` bleibt an den reinen Lese-Stellen.
- **Regressionstest:** Analog `test_read_only_factory_falls_back_when_strict_open_rejected`: `sqlite3.connect` patchen, ro-URI wirft `OperationalError`, plain gelingt → Backup/Verify/Restore müssen weiterlaufen.
- **Fix-Status (2026-11-04, `fix/p3-audit-hardening`):** Behoben — `_open_ro(path)` in `backup.py` (F1-Muster: ro-URI, bei `OperationalError` plain `connect` + `PRAGMA query_only=ON`), alle vier Call-Sites umgestellt (`create_backup`, `verify_backup`, `preview_restore`, `_restore_unlocked`). `src.backup(dst)` nutzt die Backup-API (keine SQL-Statements) und funktioniert auf `query_only`-Verbindungen. Regressionstests `tests/test_backup_service.py::ReadOnlyOpenFallbackTests` (3 Tests: `_open_ro`-Fallback mit `query_only`=1-Assert, create+verify unter striktem Ablehnen, full restore unter striktem Ablehnen). Alle drei schlagen am alten Code fehl (`AttributeError: ... no attribute '_open_ro'` bzw. `BackupError`), neu grün.

### F1 — read-only Factory-Fallback (P3, behoben, verifiziert)

- **Pfad:** `src/penx_app/application/evidence_verification.py` (`_read_only_sqlite_factory`, ~Lines 175-189).
- **Status:** Behoben in `d87e75f`. `sqlite3.OperationalError` bei `?mode=ro` → Fallback auf plain `connect` + `PRAGMA query_only=ON`.
- **Verifikation:** Deterministischer Regressionstest `tests/test_px003_interactive_session_provenance.py::test_read_only_factory_falls_back_when_strict_open_rejected` (patcht `sqlite3.connect`, zählt ro- vs. plain-Versuche, assertet `query_only` und History-Count). Im Volltest auf `d87e75f` grün.

### F2 — stdout-Retention-Fehler bleibt COMPLETE (P3, behoben, verifiziert)

- **Pfad:** `src/penx_app/application/scanner_execution.py` (`_run_adapter`).
- **Status:** Behoben in `8547d64`. `retain_stdout_bytes`-Aufruf ist in `try/except (OSError, ValueError)`; auf Fehlschlag bleibt die Zeile COMPLETE mit Evidenz, `stdout_capture=None`, Diagnose `stdout-byte-retention-skipped (<Exc>)`.
- **Verifikation:** Regressionstest `tests/test_px003_session_byte_binding.py::test_retention_failure_keeps_completed_row_evidenced` (seit `FileExistsError`/`PermissionError`/`ValueError`; assertet COMPLETE, evidence=True, stdout_capture=None, reason ≠ "error"). Im Volltest auf `d87e75f` grün.

## Feature-Verification Matrix

| Feature | Status | Verifiziert durch |
|---|---|---|
| Bounded Subprocess-Lifecycle (Capture-Limits, Process-Tree-Termination, Cooperative Cancel) | OK | Review `scanners/process_runner.py` (vollständig) + `test_scanner_process_tree.py` u. a. |
| Read-only Session-Verification mit Fallback (F1) | OK (fixiert) | Review + deterministischer Regressionstest, Volltest grün |
| stdout-Byte-Provenance bei Retention-Fehler (F2) | OK (fixiert) | Review + Regressionstest, Volltest grün |
| Metadata v3 / reason taxonomy / Legacy-Reader | OK | Review `domain/scan_models.py` + PR-#147-Regressionstests, Volltest grün |
| SQLite-Use-Lock (Windows LockFileEx / POSIX flock) | OK | Review `storage/sqlite_use_lock.py` (vollständig) + Test-Suiten |
| Schema-Migration v4 (transactional, fail-closed) | OK | Review `storage/schema_migrations.py` + Migration-Tests |
| Backup/Verify/Preview/Restore (PX-004) | OK (N4: Grenzfall-RO-Fallback fehlt) | Review `storage/backup.py` (vollständig) + `test_px004_*`-Suiten |
| Atomic Publication (os.link/replace, UUID-Suffix) | OK | Review `file_output.py`, `report_batch.py`, `evaluation_packages.py` |
| Reporting HTML/PDF/JSON/SARIF/Redacted | OK | Review `reporting/*` + `test_report_crash_atomic.py` u. a. |
| Evidence-Provenance (Quote-Matching, Range-Validierung) | OK | Review `domain/evidence.py`, `reporting/finding_trace.py` |
| Passive Recon (bounded 200 KB, keine Ziel-Requests) | OK | Review `scanners/passive_recon.py` (vollständig) + Tests |
| Native Web-Scanner / ffuf-Endpoint-Mapping | OK | Review `scanners/tools.py:1001-1080` (Budget, Cancel-Gaps) + Korpus-Tests |
| LLM-Client (Streaming SSE, Strict-Payload, Incomplete-Response) | OK | Review `analysis/llm_client.py:331-450` + `test_model_failure_contracts.py` u. a. |
| Structured Output (Schema, Bounded 1 Mio. Chars) | OK | Review `analysis/structured_output.py` (vollständig) + Tests |
| CVE-Engine (Rate-Limit, 429-Retry, Bounded JSON, Disk-Cache) | OK (N1/N2 latent) | Review `intelligence/cve_engine.py:151-280,560-640`, `nvd_disk_cache.py` (vollständig) + Tests |
| Source-Verification (NVD/KEV, Strict-Validierung) | OK (N2 latent) | Review `intelligence/source_verification.py` (vollständig) + Tests |
| PHP2Shell-Posture (Version-Beobachtung nur) | OK | Review `intelligence/php2shell_audit.py` (vollständig) + Tests |
| Updates (SHA-256-Verifikation, Bounded Download) | OK (N3: Installer-Exit-Codes geprüft) | Review `updates.py:120-232` + `test_updates.py` |
| Setup (Native-Scanner atomares Install, Nuclei-Templates) | OK | Review `setup/native_scanner_setup.py:101-210` + Setup-Tests |
| CLI (Signal-Scoping, Navigation, Cancellation) | OK | Review `cli/scanner_cancellation.py` (vollständig) + `test_scanner_cancellation.py` |
| Scan-Planner (Topologie, Deadlines, CancellingPool) | OK | Review `application/scan_planner.py` + Plan-Tests |

## Memory & Thread-Safety Report

- **`process_runner.py`:** Zwei Daemon-Drain-Threads (`Lines 180-181`), in `finally` joined und Pipes geschlossen; bounded Capture (`MAX_CAPTURE_BYTES`); keine Leaks erkannt.
- **`scan_planner.py`:** `CancellingPool(ThreadPoolExecutor)` mit `NodeCancellation`-Events; Deadlines via `enforce_deadline`; Review: korrekt.
- **`cve_engine.py`:** NVD serial auf Aufrufer-Thread (dokumentiert, Line 589-591), OSV/GitHub im 3-Worker-Pool. Ergebnislisten sind pro Index adressiert (`nvd_results[index]`), keine Shared-Mutation im Pool. N1 (sleep unter Lock) ist latent, s. o.
- **`sqlite_use_lock.py`:** Cross-Prozess-OS-Lock (LockFileEx/flock), `acquire` mit Deadline, idempotent release; Review: korrekt.
- **`report_batch.py`:** Publication-Lock via `msvcrt.locking(fd, LK_NBLCK, 1)`/`flock` auf Byte 0 — deterministisch exklusiv; Symlink-Guards (`O_NOFOLLOW`, fstat/lstat-Vergleich) vollständig.
- **GIL-Atomizität:** Alle ohne Lock gelesenen/wiedergegebenen Globalen (`config._settings`) sind pro Operation atomar; `_nvd_cache`/`_kev_cache` werden seit dem N2-Fix (2026-11-04) durch `_source_cache_lock` geschützt (ersetzen statt mutieren, defensive Kopien bei Reads).
- **Kein Data-Race mit Korruptionspotenzial** gefunden. Alle Shared-Mutable-State-Stellen wurden inventarisiert (8 `global`/`nonlocal`-Match im Baum, alle geprüfst).

## SDK-Kompatibilität

- **Public API:** `penx`-Modul-Eintragspunkt bleibt (bis v1) unverändert; `penx_app`-Pakete intern.
- **Metadata-Vertrag:** v1/v2/v3 additiv; `from_metadata` strict (unique keys, `parse_constant`-Reject, pro-Version-Allowlists). Reason-Vokabular bleibt CLOSED (REASON_VERSION=1).
- **DB-Schema:** v4 additiv (`projects`, `project_assets`, uq-Index); ältere Reader ignorieren neue Tabellen; Downgrades werden abgelehnt (PR #147).
- **Berichtsformate:** HTML/PDF/JSON/SARIF 2.1.0 unverändert.
- **CLI-Flags:** Bootstrap-Dispatch unverändert.
- **Dieses Audit:** read-only — keine neue Kompatibilitäts-Fläche, kein Diff.

## Build & Test Results

| Check | Befehl | Ergebnis |
|---|---|---|
| Lint (Audit-Zustand) | `python -m ruff check src tests offline_tests.py` | **All checks passed** (Exit 0) |
| Volltest (Audit-Zustand) | `python offline_tests.py` auf `d87e75f` | **258 / 258 PASS** (4 Worker, per-suite timeout 300 s, Log: `.qwen/fulltest.log`) |
| Lint (Fix-Zweig) | `ruff check` über alle 8 geänderten Dateien, `fix/p3-audit-hardening` | **All checks passed** (Exit 0) |
| Volltest (Fix-Zweig) | `python offline_tests.py` auf `fix/p3-audit-hardening` (2026-11-04) | **258 / 258 PASS** (4 Worker, per-suite timeout 300 s, Log: `.qwen/fulltest-p3fix.log`) |
| Regressionstests vs. altem Code | einzelne Tests gegen ge-stash-te Src-Dateien | N1-Test: FAIL (`AssertionError`), N3-Test: 4× FAIL (`wait` not called / `True != False`), N4-Tests: 3× ERROR (`AttributeError`/`BackupError`), N2-Smoke-Tests: PASS (latent, Vertrag gepinnt) |
| MariaDB-Integration | gated `PENX_MARIADB_TEST=1` (CI-only) | NOT RUN (lokal) |
| EXE-Build | `build-exe.bat` | NOT RUN (keine Binary-/Build-Änderung) |

## Performance

- Keine Code-Änderung in diesem Audit → keine neuen Messwerte, keine Regression möglich.
- Beobachtungen (statisch): alle I/O-Pfade bounded (passive Recon 200 KB, Process-Capture 1 MiB, NVD-Cache 4 MB/Datei, 64 MB Gesamt, Structured-Response 1 Mio. Chars); Rate-Limits (NVD 5/30 s ohne Key, Retry-After ≤ 30 s); keine unbounded-Loops in Review-Modulen.
- Einzige potenzielle Latenz-Quelle unter künftiger Parallelisierung: N1 (sleep unter Lock), s. o.

## Empfohlene Fix-Order

Alle vier Fixes wurden am 2026-11-04 auf Branch `fix/p3-audit-hardening` umgesetzt
(jeweils mit Regressionstest; Details in den Detailabschnitten N1–N4):

1. **N4** — `_open_ro`-Helper mit F1-Fallback in `backup.py` (4 Stellen). Kleinstes Risiko, wiederverwendetes, getestetes Muster. ✅ behoben
2. **N1** — Sleep aus dem Lock in `cve_engine.py:191-204` + zwei-Thread-Regressionstest. ✅ behoben
3. **N3** — `proc.wait()` + Ergebnis-Ausgabe in `updates.py` (synchron, kein Daemon nötig — der interaktive Flow blockiert ohnehin bis zum nächsten Prompt). ✅ behoben
4. **N2** — Gemeinsamer Lock für beide Cache-Paare (statt nur Dokumentation, da die Locks mit N1 ohnehin eingeführt werden). ✅ behoben

## Review Coverage

**Vollständig manuell gelesen (dieses + vorangegangene Audit-Segmente):**
`scanners/process_runner.py`, `application/scanner_execution.py`, `application/scan_recovery.py`,
`application/scan_planner.py`, `application/assessment_service.py`, `domain/scan_plan.py`,
`storage/db_backend.py`, `storage/sqlite_use_lock.py`, `storage/session_repository.py`,
`storage/raw_artifacts.py`, `storage/stdout_bytes.py`, `storage/backup.py`,
`storage/schema_migrations.py`, `storage/db.py`, `storage/db_evals.py` (Auszug),
`file_output.py`, `reporting/machine_reports.py`, `reporting/report_view.py`,
`reporting/export.py`, `reporting/evaluation_packages.py`, `reporting/finding_trace.py`,
`reporting/scan_coverage.py`, `reporting/report_batch.py` (Auszug),
`domain/scan_models.py`, `domain/evidence.py`, `domain/scan_diagnostics.py`,
`domain/finding_policy.py`, `intelligence/php2shell_audit.py`,
`intelligence/source_verification.py`, `intelligence/cve_engine.py` (Auszug),
`intelligence/nvd_disk_cache.py`, `analysis/llm_client.py` (Auszug),
`analysis/structured_output.py`, `scanners/passive_recon.py`, `scanners/tools.py` (Auszug),
`setup/native_scanner_setup.py` (Auszug), `cli/scanner_cancellation.py`,
`cli/assessment_ui.py` (Auszug), `updates.py` (Auszug), `config.py`.

**Pattern-Scans (ganzer Baum):**
- Bare `except:` — 0 Treffer
- Top-level `assert` — 0 Treffer
- `open()` außerhalb von `with` — 0 Treffer
- `time.sleep` — 7 Treffer, alle bounded/geprüft
- `input()` — 15 Treffer, alle in `cli/`
- `subprocess.*` — 4 in `scanners/` (2× `process_runner`, 1× version check `native_web_scanners.py:53`), 1× `updates.py:195`
- `global`/`nonlocal` — 8 Treffer, alle geprüfst (s. Memory Report)
- File-Deletion — 82 Treffer, alle atomare Muster (unlink missing_ok, os.replace, temp-cleanup)
- Index-Zugriffe `row[n]` — 49 Treffer, guardiert (z. B. `len(matches) != 1` in `db_evals.py:126-129`, `len(matches) < 2` in `assessment_ui.py:37`)
- `requests.*` in `scanners/` — 4 Treffer, alle mit Timeout + Bounded-Reads

**Nicht-vertiefte, aber inventarisierte Module:** `cli/`-Menüs/Dienste, `setup/first_run_setup.py`,
`setup/llm_setup.py`, `setup/windows_python_setup.py`, `scripts/*`, `penx/`-Shim,
`intelligence/shodan_enrichment.py`, `intelligence/wordpress_advisories.py`,
`intelligence/exploitdb_references.py`, `intelligence/package_inventory.py`,
`intelligence/search.py`, `intelligence/cve_priority.py`, `intelligence/vendor_status.py`,
`scanners/registry.py`, `scanners/scanner_targets.py`, `scanners/endpoint_inventory.py`,
`analysis/prompts.py`, `analysis/parsers.py`, `analysis/assessment_quality.py`,
`reporting/report_design.py`, `reporting/report_management.py`, `reporting/terminal_pdf.py`,
`storage/project_repository.py`, `storage/evaluation_repository.py`,
`storage/db_training.py`, `application/mariadb_backup.py`, `application/scan_trends.py`,
`application/project_service.py`, `application/risk_assessment.py` — abgedeckt durch
Pattern-Scans und die 258 grünen Test-Suiten.

## Offene Fragen / nicht verifizierbare Runtime-Annahmen

1. **WAL-Grenzfall (N4):** Live-DB liegt im Default `delete`-Mode; der WAL-Fall für `?mode=ro`
   ist eine Sonderkonstellation (manuell gesetzter WAL-Mode oder geerbte Datei). Empirisch
   auf dieser Windows-Plattform reproduzierbar nur mit read-only Media oder künstlicher
   WAL-Datei — daher N4 als SUSPECTED und nicht CONFIRMED.
2. **NVD-Parallelität (N1/N2):** Die Serialität der NVD-Pfade ist durch Code-Kommentar
   (Line 589-591) und Call-Graph belegt. Seit 2026-11-04 decken `test_rate_wait_does_not_hold_the_lock`
   (N1) und die beiden Concurrency-Smoke-Tests (N2) die Limiter-/Cache-Seite ab; ein
   Thread-Leak-Test gegen `verify_findings` als Ganzes existiert weiterhin nicht.
3. **MariaDB-Pfad:** Lokal nicht verifiziert (CI-gated); SQLite-Pfad vollständig geprüft.
