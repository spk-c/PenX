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

The function is a **low-level API only**. It is not automatically enabled
by `scan --raw-artifacts`, does not alter `ScanResult` metadata
v1/v2/v3, the existing headless JSON/SARIF schema, or the user-facing
`evidence verify` command. It cannot authenticate which binary produced
the text or establish vulnerability applicability. Native Python HTTP
adapters have no subprocess stdout and are unaffected.

**Remaining PX-003 acceptance:** safely wire byte references to the
specific scanner process/adapter/saved session where possible, handle
composite and transformed tool output without falsely binding it to
stdout alone, extend negative corpus for the remaining third-party
adapters, and complete independent Windows/Kali/PDF field review. No
live external-target tests, database migrations or release publication
are part of this slice. Rollback: revert this PR.
