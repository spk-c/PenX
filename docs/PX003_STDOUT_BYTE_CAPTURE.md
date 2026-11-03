# PX-003: Exact pre-decoding subprocess stdout capture (focused API slice)

PenX already offers **opt-in retained UTF-8 scanner text**, with
`python penx.py evidence verify --metadata ... --artifacts ...`. That is
not equivalent to proving the original bytes the operating system delivered
over a scanner's stdout pipe. This additional, opt-in low-level interface
records those bytes **before decoding, trimming and report formatting**.

## Operator/developer use on owner-controlled fixtures

```python
import sys
from penx_app.scanners.process_runner import run_tool_with_stdout_capture
from penx_app.storage.stdout_bytes import verify_stdout_capture

# An owned, local, non-network command. Explicit opt-in to raw file retention.
outcome, reference = run_tool_with_stdout_capture(
    [sys.executable, "-c", "print('offline fixture')"],
    "./capture-output",
)
if reference is not None:
    original_stdout = verify_stdout_capture(
        reference, "./capture-output", text=str(outcome))
```

`reference` is a separately validated `StdoutByteCapture` object containing
the **SHA-256 and length of the exact stdout bytes**, a SHA-256 of the
strictly decoded/truncated presentation text, a bounded filename and a
`sha256-predecode-stdout-v1` validator identifier. The files have
the suffix `.bin`, so they cannot be confused with the existing UTF-8
`.txt` artifacts. File publication is exclusive/atomic; existing evidence
is never overwritten.

A capture is published only if **all** of the following hold:
the subprocess completed successfully, retained output did not exceed
1 MiB on either stream, stdout contains usable evidence, bytes are valid
UTF-8, and there is no stderr content to complicate the relationship
between stdout and the displayed output. Cancellation, failure, timeout,
truncation, invalid decoding and mixed stdout+stderr produce **no verified
stdout artifact**. A failed opt-in file publication raises rather than
claiming successful evidence retention. Quiet and live subprocess modes
use the same byte buffer, with no behavior change for existing callers.

The verifier rejects missing/corrupt/oversized, linked, non-regular or
relocated files, and checks byte hash, length, strict UTF-8 re-decoding,
and exact text equality. It does not execute a process, send requests,
modify a database or print raw stdout.

## Safety, compatibility and limitations

Raw stdout can contain secrets, scanned hostnames or tokens. **Opt-in
only**; operators should explicitly select a private, access-controlled
directory and apply an appropriate retention policy.

The standalone low-level function remains independently available.
The headless scan now has an opt-in one-to-one scanner-result binding,
described below. The default no-capture mode is unchanged.

**Remaining PX-003 acceptance:** the headless report/metadata adapter
binding is implemented for untransformed one-process output. Interactive SQLite history now has an opt-in retained-proof path and read-only session verifier (see `PX003_INTERACTIVE_SESSION_PROVENANCE.md`). Independent MariaDB, composite/multi-process cases, remaining third-party negatives and real Windows/Kali/PDF field review are still open. No
live external-target tests, database migrations or release publication
are part of this slice. Rollback: revert this PR.

## Headless per-adapter provenance (PX-003 follow-up)

The headless `scan` command now links eligible original subprocess stdout
bytes to the exact result row and to a saved version-3 metadata manifest.
The existing `--raw-artifacts` flag remains opt-in. No extra files are
written by ordinary scans.

```text
python penx.py scan --target example.test --authorized --scanners 1 --raw-artifacts ./private-captures --output ./reports
```

Use only owned or expressly authorized scan targets. A successful eligible
one-process adapter writes a bounded hash-named `.bin` file alongside the
existing `.txt` capture. The report contains `adapters[].stdout_capture`;
its optional `provenance_manifest` identifies the actual saved metadata
file by name and SHA-256. The metadata file preserves the scanner ID,
status, evidence anchors, and original-byte reference.

Verify this headless report without launching any scanners:

```text
python penx.py evidence verify --metadata ./reports/penx_scan_metadata.json --artifacts ./private-captures --report ./reports/penx_scan.json
```

Both filename and hash are checked, as well as ordered adapter IDs,
status, evidence flags, references, original text hashes, quote offsets
and original stdout bytes. Duplicate-safe metadata suffixes (such as
`penx_scan_metadata_001.json`) are supported: use the exact filename
from `provenance_manifest.metadata_file`, not a guessed path.

The JSON result distinguishes `raw_sources_verified`,
`stdout_byte_sources_verified` and `report_binding_verified`. Missing,
mismatched, duplicated, corrupted or unsafe files fail closed without
printing the stored scanner text.

### Provenance limits

- Headless reports continue to have `session: null`: the manifest binds
  one headless report to its result metadata but does not create a history
  database session or prove actual scanner/target identity.
- The reference is emitted only when one completed, bounded subprocess
  produces exactly the unchanged adapter text. Multiple calls, stderr
  combination, transformed scanner summaries, invalid UTF-8, timeouts
  and non-subprocess Python adapters are not falsely marked as proven.
- These hashes detect corruption and mistaken associations, **not**
  independent authenticity. The report and metadata are not digitally
  signed. A malicious party who controls both can replace both.
- The binary output may contain private data. Store it in an appropriately
  restricted folder, and apply explicit deletion/retention policies.
- Independent interactive Windows/Kali/SQLite/MariaDB field sign-off,
  other third-party negative fixtures and visual PDF review remain open;
  the existing release version is unchanged.
