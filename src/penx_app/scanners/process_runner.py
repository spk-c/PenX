"""Bounded, shell-free subprocess lifecycle shared by native scanner adapters.

Both quiet and live modes drain pipes continuously with bounded capture.
Truncated or timed-out output is diagnostic, never full scanner evidence.
"""
from __future__ import annotations

from pathlib import Path
import os
import queue
import signal
import subprocess
import threading
import time

from penx_app.domain.scan_models import ScannerOutput
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
            os.killpg(proc.pid, signal.SIGKILL)
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

    def add(self, part: bytes) -> None:
        room = self.limit - len(self.buffer)
        if len(part) > room:
            self.truncated = True
        if room > 0:
            self.buffer.extend(part[:room])

    def decode(self) -> str:
        return self.buffer.decode("utf-8", errors="replace").strip()


def _drain_pipe(pipe, sink: _BoundedBytes) -> None:
    try:
        while True:
            chunk = pipe.read(_CHUNK_BYTES)
            if not chunk:
                return
            sink.add(chunk)
    except (OSError, ValueError):
        # A caller cancelled the process and closed the read side.
        return


def _cancelled_result(command: list[str], exit_code: int | None = None) -> ScannerOutput:
    """Cancellation is a partial, untrusted outcome, never scanner evidence."""
    return ScannerOutput(
        f"[!] Scanner cancelled by caller: {Path(command[0]).name}",
        status="PARTIAL", evidence=False, exit_code=exit_code,
        diagnostics="Caller requested scanner cancellation",
    )


def _run_tool_quiet(command: list[str], timeout: int, cwd: str | None,
                    env: dict[str, str] | None,
                    cancel_event: threading.Event | None = None) -> ScannerOutput:
    """Drain both pipes in small blocks; never call communicate() unbounded."""
    proc = subprocess.Popen(
        command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, cwd=cwd, env=env, **_process_group_options(),
    )
    stdout = _BoundedBytes()
    stderr = _BoundedBytes()
    workers = [
        threading.Thread(target=_drain_pipe, args=(proc.stdout, stdout), daemon=True),
        threading.Thread(target=_drain_pipe, args=(proc.stderr, stderr), daemon=True),
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
                break
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
        )
    sections = [text for text in (out, "[STDERR]\n" + err if err else "") if text]
    combined = "\n".join(sections)
    if truncated:
        return ScannerOutput(
            f"[!] OUTPUT TRUNCATED: scanner output exceeded {MAX_CAPTURE_BYTES} bytes "
            f"per stream; collected results are incomplete.\n{combined}",
            status="PARTIAL", evidence=False,
            exit_code=proc.returncode,
        )
    if proc.returncode:
        return ScannerOutput(
            f"[EXIT CODE {proc.returncode}]\n{combined}".strip(),
            status="FAILED", evidence=False,
            exit_code=proc.returncode,
        )
    return ScannerOutput(
        combined or "[!] Tool returned no output.",
        status="COMPLETE" if out else "FAILED",
        evidence=bool(out), exit_code=proc.returncode,
    )


def _run_tool_live(command: list[str], timeout: int, cwd: str | None,
                   env: dict[str, str] | None,
                   cancel_event: threading.Event | None = None) -> ScannerOutput:
    """Stream bounded line chunks without an unbounded producer queue."""
    print(f"  [LIVE] {Path(command[0]).name} started...", flush=True)
    proc = subprocess.Popen(
        command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1, cwd=cwd, env=env,
        **_process_group_options(),
    )
    messages = queue.Queue(maxsize=64)
    stop = threading.Event()

    def read() -> None:
        try:
            while True:
                # readline(size) bounds a single unterminated scanner line.
                chunk = proc.stdout.readline(4096)
                if not chunk:
                    break
                while not stop.is_set():
                    try:
                        messages.put(chunk, timeout=0.1)
                        break
                    except queue.Full:
                        continue
        finally:
            while not stop.is_set():
                try:
                    messages.put(None, timeout=0.1)
                    break
                except queue.Full:
                    continue

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    output = []
    used = 0
    truncated = False
    timed_out = False
    cancelled = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                _terminate_process_tree(proc)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_tree(proc)
                break
            try:
                chunk = messages.get(timeout=min(0.2, remaining))
            except queue.Empty:
                if proc.poll() is not None and not worker.is_alive() and messages.empty():
                    break
                continue
            if chunk is None:
                break
            room = MAX_CAPTURE_BYTES - used
            # Count the same encoded UTF-8 bytes as the quiet runner.
            # Character counts understate memory consumption for Unicode text.
            encoded = chunk.encode("utf-8")
            if len(encoded) > room:
                truncated = True
            if room > 0:
                retained = encoded[:room]
                output.append(retained)
                used += len(retained)
                print("  [SCAN] " + retained.decode("utf-8", errors="replace").rstrip("\r\n"), flush=True)
        proc.wait(timeout=5 if (timed_out or cancelled)
                  else max(0.1, deadline - time.monotonic()))
    except BaseException:
        _terminate_process_tree(proc)
        proc.wait()
        raise
    finally:
        stop.set()
        worker.join(timeout=2)
        if proc.stdout is not None:
            proc.stdout.close()

    text = b"".join(output).decode("utf-8", errors="replace").strip()
    if cancelled:
        return _cancelled_result(command, proc.returncode)
    if timed_out:
        return ScannerOutput(
            f"[!] Timed out after {timeout}s: {command[0]}\n[PARTIAL OUTPUT]\n{text}",
            status="PARTIAL", evidence=False,
            exit_code=proc.returncode,
        )
    if truncated:
        return ScannerOutput(
            f"[!] OUTPUT TRUNCATED: streamed scanner output exceeded "
            f"{MAX_CAPTURE_BYTES} bytes; collected results are incomplete.\n{text}",
            status="PARTIAL", evidence=False,
            exit_code=proc.returncode,
        )
    if proc.returncode:
        return ScannerOutput(
            f"[EXIT CODE {proc.returncode}]\n{text}",
            status="FAILED", evidence=False,
            exit_code=proc.returncode,
        )
    return ScannerOutput(
        text or "[!] Tool returned no output.",
        status="COMPLETE" if text else "FAILED",
        evidence=bool(text), exit_code=proc.returncode,
    )


def run_tool(command: list[str], timeout: int = 120, *, cwd: str | None = None,
             env: dict[str, str] | None = None,
             cancel_event: threading.Event | None = None) -> ScannerOutput:
    """Run shell-free scanner with bounded memory and cooperative cancellation.

    An opt-in caller-owned threading.Event aborts the whole process group.
    A pre-cancelled request never starts a scanner process.
    """
    if cancel_event is not None and cancel_event.is_set():
        return _cancelled_result(command)
    try:
        if live_output():
            return _run_tool_live(command, timeout, cwd, env, cancel_event)
        return _run_tool_quiet(command, timeout, cwd, env, cancel_event)
    except FileNotFoundError:
        return ScannerOutput(f"[!] Executable not found: {command[0]}",
                             status="FAILED", evidence=False)
    except OSError as exc:
        return ScannerOutput(f"[!] Could not start {command[0]}: {exc}",
                             status="FAILED", evidence=False)
