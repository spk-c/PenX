"""Bounded, shell-free subprocess lifecycle shared by native scanner adapters.

Both quiet and live modes drain pipes continuously with bounded capture.
Truncated or timed-out output is diagnostic, never full scanner evidence.
"""
from __future__ import annotations

from pathlib import Path
import codecs
import os
import sys
import signal
import subprocess
import threading
import time

from penx_app.domain.scan_models import ScannerOutput
from penx_app.domain.stdout_bytes import StdoutByteCapture
from penx_app.runtime_options import live_output

MAX_CAPTURE_BYTES = 1024 * 1024
_CHUNK_BYTES = 8192


def _process_group_options() -> dict:
    # Each child scanner starts in its own process group.
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    """Stop descendants as well as the scanner process on timeout/cancellation."""
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                shell=False, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # type: ignore[attr-defined]
        except (ProcessLookupError, PermissionError):
            pass
    if proc.poll() is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass



class _BoundedBytes:
    """Keep only the first bounded bytes while continuing to drain the pipe."""

    def __init__(self, limit: int = MAX_CAPTURE_BYTES):
        self.buffer = bytearray()
        self.limit = limit
        self.truncated = False
        self.decode_errors = False

    def add(self, part: bytes) -> bytes:
        room = self.limit - len(self.buffer)
        if len(part) > room:
            self.truncated = True
        if room > 0:
            retained = part[:room]
            self.buffer.extend(retained)
            return retained
        return b""

    def decode(self) -> str:
        try:
            return self.buffer.decode("utf-8").strip()
        except UnicodeDecodeError:
            self.decode_errors = True
            return self.buffer.decode("utf-8", errors="replace").strip()


def _drain_pipe(pipe, sink: _BoundedBytes, stream: bool = False, prefix: str = "") -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace") if stream else None

    def emit(part: bytes, *, final: bool = False) -> None:
        if decoder is not None:
            text = decoder.decode(part, final=final)
            for line in text.split("\n"):
                if line:
                    _emit_line("  [SCAN] " + prefix + _terminal_safe_text(line.rstrip("\r")))

    try:
        while True:
            chunk = pipe.read(_CHUNK_BYTES)
            if not chunk:
                return
            retained = sink.add(chunk)
            if stream:
                emit(retained)
    except (OSError, ValueError):
        # A caller cancelled the process and closed the read side.
        return
    finally:
        if stream:
            emit(b"", final=True)


def _emit_line(text: str) -> None:
    """Live progress line for untrusted scanner output; a non-UTF-8 caller
    stream must never abort the scan run over a cosmetic print."""
    try:
        print(text, flush=True)
    except (OSError, ValueError):
        try:
            print(text.encode("ascii", "replace").decode("ascii"), flush=True)
        except (OSError, ValueError):
            pass


def _terminal_safe_text(value: str) -> str:
    """Render untrusted scanner output without terminal escapes or line rewrites.

    Keep the original captured data unchanged for parsing/reporting. Replacing
    controls with visible escape text prevents ANSI/OSC and carriage-return
    sequences from altering the terminal, even when split across pipe reads.
    """
    return "".join(
        f"\\x{ord(ch):02x}" if (ord(ch) < 32 or 0x7f <= ord(ch) <= 0x9f)
        else f"\\u{ord(ch):04x}" if (0x202a <= ord(ch) <= 0x202e
                                     or 0x2066 <= ord(ch) <= 0x2069)
        else ch
        for ch in value
    )


def _cancelled_result(command: list[str], exit_code: int | None = None) -> ScannerOutput:
    """Cancellation is a partial, untrusted outcome, never scanner evidence."""
    return ScannerOutput(
        f"[!] Scanner cancelled by caller: {Path(command[0]).name}",
        status="PARTIAL", evidence=False, exit_code=exit_code,
        diagnostics="Caller requested scanner cancellation",
        reason="cancelled",
    )


def _run_tool_quiet(command: list[str], timeout: int, cwd: str | None,
                    env: dict[str, str] | None,
                    cancel_event: threading.Event | None = None, *,
                    stream: bool = False,
                    stdout_capture: list[bytes] | None = None) -> ScannerOutput:
    """Common byte capture/lifecycle; optional rendering never changes evidence."""
    proc = subprocess.Popen(
        command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, cwd=cwd, env=env, **_process_group_options(),
    )
    stdout = _BoundedBytes()
    stderr = _BoundedBytes()
    workers = [
        threading.Thread(target=_drain_pipe, args=(proc.stdout, stdout, stream), daemon=True),
        threading.Thread(target=_drain_pipe, args=(proc.stderr, stderr, stream, "[STDERR] "), daemon=True),
    ]
    for worker in workers:
        worker.start()
    timed_out = False
    cancelled = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                _terminate_process_tree(proc)
                proc.wait(timeout=5)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_tree(proc)
                proc.wait(timeout=5)
                break
            try:
                proc.wait(timeout=min(0.2, remaining))
                if all(not worker.is_alive() for worker in workers):
                    break
                # Process exit and pipe EOF are separate events. Drain both
                # readers within the same deadline, never trust a read race.
                for worker in workers:
                    worker.join(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        _terminate_process_tree(proc)
        proc.wait()
        raise
    finally:
        for worker in workers:
            worker.join(timeout=3)
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()

    out = stdout.decode()
    err = stderr.decode()
    truncated = stdout.truncated or stderr.truncated
    if cancelled:
        return _cancelled_result(command, proc.returncode)
    if timed_out:
        return ScannerOutput(
            f"[!] Timed out after {timeout}s: {command[0]}"
            + ("\n[PARTIAL OUTPUT]\n" + out if out else "")
            + ("\n[STDERR]\n" + err if err else ""),
            status="PARTIAL", evidence=False,
            exit_code=proc.returncode,
            reason="timeout",
        )
    sections = [text for text in (out, "[STDERR]\n" + err if err else "") if text]
    combined = "\n".join(sections)
    if truncated:
        return ScannerOutput(
            f"[!] OUTPUT TRUNCATED: scanner output exceeded {MAX_CAPTURE_BYTES} bytes "
            f"per stream; collected results are incomplete.\n{combined}",
            status="PARTIAL", evidence=False,
            exit_code=proc.returncode,
            reason="truncated",
        )
    if proc.returncode:
        return ScannerOutput(
            f"[EXIT CODE {proc.returncode}]\n{combined}".strip(),
            status="FAILED", evidence=False,
            exit_code=proc.returncode,
            reason="error",
        )
    if stdout.decode_errors or stderr.decode_errors:
        return ScannerOutput(
            "[!] INVALID UTF-8: scanner output required replacement; "
            "collected results are incomplete.\n" + combined,
            status="PARTIAL", evidence=False, exit_code=proc.returncode,
            diagnostics="Scanner output contains invalid UTF-8",
            reason="parse_invalid",
        )
    # Preserve the actual pipe buffer *before* conversion to text. Keep
    # opt-in byte provenance only for a complete, unambiguous stdout-only
    # execution. Stderr is part of the combined presentation, not stdout.
    if stdout_capture is not None and out and not err:
        stdout_capture.append(bytes(stdout.buffer))
    return ScannerOutput(
        combined or "[!] Tool returned no output.",
        status="COMPLETE" if out else "FAILED",
        evidence=bool(out), exit_code=proc.returncode,
    )


def _run_tool_live(command: list[str], timeout: int, cwd: str | None,
                   env: dict[str, str] | None,
                   cancel_event: threading.Event | None = None, *,
                   stdout_capture: list[bytes] | None = None) -> ScannerOutput:
    """Render the same bounded per-stream bytes used by quiet capture."""
    _emit_line(f"  [LIVE] {Path(command[0]).name} started...")
    return _run_tool_quiet(command, timeout, cwd, env, cancel_event,
                           stream=True, stdout_capture=stdout_capture)



def _child_env(env: dict[str, str] | None) -> dict[str, str]:
    """Prepare the environment for a child process.

    On Windows the default console/ANSI codepage (cp1252) cannot represent
    non-ASCII scanner output. Helper processes that write UTF-8 text would
    otherwise crash with UnicodeEncodeError, which run_tool would surface as a
    spurious "tool failed". Pinning the Python I/O encoding keeps output
    decodable and does not affect native tools, which ignore the PYTHON*
    variables. Explicit user settings win (setdefault), so tests and
    operators can still override.
    """
    base = dict(os.environ) if env is None else dict(env)
    # PyInstaller prepends its bundled shared libraries to LD_LIBRARY_PATH.
    # Inheriting that path when launching distro-provided Kali binaries can
    # load incompatible libcrypto/libssl/libstdc++ and cause immediate failures.
    # Restore the operator's original loader path for external child scanners.
    if os.name != "nt" and getattr(sys, "frozen", False):
        original = base.get("LD_LIBRARY_PATH_ORIG")
        if original is None:
            base.pop("LD_LIBRARY_PATH", None)
        else:
            base["LD_LIBRARY_PATH"] = original
    base.setdefault("PYTHONUTF8", "1")
    base.setdefault("PYTHONIOENCODING", "utf-8")
    return base


def run_tool(command: list[str], timeout: int = 120, *, cwd: str | None = None,
             env: dict[str, str] | None = None,
             cancel_event: threading.Event | None = None,
             _stdout_capture: list[bytes] | None = None) -> ScannerOutput:
    """Run shell-free scanner with bounded memory and cooperative cancellation.

    An opt-in caller-owned threading.Event aborts the whole process group.
    A pre-cancelled request never starts a scanner process.
    """
    if (not isinstance(command, (list, tuple)) or not command
            or any(not isinstance(arg, str) or not arg or "\x00" in arg
                   for arg in command) or not command[0].strip()):
        return ScannerOutput("[!] Invalid scanner command arguments.",
                             status="FAILED", evidence=False,
                             reason="error")
    if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
            or not 0 < timeout <= 86400):
        return ScannerOutput("[!] Invalid scanner timeout.",
                             status="FAILED", evidence=False,
                             reason="error")
    if cancel_event is not None and cancel_event.is_set():
        return _cancelled_result(command)
    child_env = _child_env(env)
    try:
        if live_output():
            return _run_tool_live(command, timeout, cwd, child_env, cancel_event,
                                  stdout_capture=_stdout_capture)
        return _run_tool_quiet(command, timeout, cwd, child_env, cancel_event,
                               stdout_capture=_stdout_capture)
    except FileNotFoundError:
        return ScannerOutput(f"[!] Executable not found: {command[0]}",
                             status="FAILED", evidence=False,
                             reason="missing_dependency")
    except OSError as exc:
        return ScannerOutput(f"[!] Could not start {command[0]}: {exc}",
                             status="FAILED", evidence=False,
                             reason="error")



def run_tool_with_stdout_capture(
    command: list[str], directory: str | Path, timeout: int = 120, *,
    cwd: str | None = None, env: dict[str, str] | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[ScannerOutput, StdoutByteCapture | None]:
    """Opt-in original stdout byte capture for an *explicitly run* subprocess.

    This low-level API does not enable capture in scan profiles, nor does it
    attach proof to an adapter's transformed/combined output. It returns no
    provenance for timeout, truncation, cancellation, decode errors, empty
    stdout or stderr mixed into the displayed output. Recording bytes is a
    privacy-sensitive, operator-controlled operation.
    """
    from penx_app.storage.stdout_bytes import retain_stdout_bytes

    captured: list[bytes] = []
    result = run_tool(command, timeout, cwd=cwd, env=env,
                      cancel_event=cancel_event, _stdout_capture=captured)
    if result.status != "COMPLETE" or not result.evidence or len(captured) != 1:
        return result, None
    ref: StdoutByteCapture = retain_stdout_bytes(
        captured[0], directory, decoded_text=str(result))
    return result, ref
