"""Cooperative cross-process SQLite lifetime lock for safe restores.

PenX-managed SQLite connections hold a shared OS lock; restore requires an
exclusive OS lock before replacing the database or touching WAL/SHM files.
External tools that bypass PenX must be stopped separately by the operator.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import time
from typing import Any, BinaryIO

if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _win_ctypes: Any = ctypes
    _win_msvcrt: Any = msvcrt

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    _kernel32 = _win_ctypes.WinDLL("kernel32", use_last_error=True)
    _lock_file = _kernel32.LockFileEx
    _lock_file.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_OVERLAPPED),
    )
    _lock_file.restype = wintypes.BOOL
    _unlock_file = _kernel32.UnlockFileEx
    _unlock_file.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(_OVERLAPPED),
    )
    _unlock_file.restype = wintypes.BOOL
else:
    import fcntl

    _posix_fcntl: Any = fcntl


class SQLiteDatabaseInUse(RuntimeError):
    """A managed PenX SQLite connection is still active."""


class SQLiteUseLock:
    """Shared/exclusive one-byte cross-process OS lock for the DB lifetime."""

    def __init__(self, db_path: Path, *, exclusive: bool, timeout: float = 0):
        self.path = Path(str(Path(db_path).expanduser().resolve()) + ".restore.lock")
        self.exclusive = exclusive
        self.timeout = max(0.0, timeout)
        self._file: BinaryIO | None = None
        self._overlapped: Any = None

    def _try_lock(self) -> None:
        handle_file = self._file
        if handle_file is None:
            raise RuntimeError("SQLiteUseLock file is not open")
        if os.name == "nt":
            self._overlapped = _OVERLAPPED()
            handle = _win_msvcrt.get_osfhandle(handle_file.fileno())
            flags = 0x1 | (0x2 if self.exclusive else 0)
            if not _lock_file(handle, flags, 0, 1, 0,
                              ctypes.byref(self._overlapped)):
                code = _win_ctypes.get_last_error()
                if code in (32, 33):
                    raise BlockingIOError(errno.EAGAIN, "Database in use")
                raise OSError(code, "LockFileEx failed")
        else:
            mode = _posix_fcntl.LOCK_EX if self.exclusive else _posix_fcntl.LOCK_SH
            _posix_fcntl.flock(handle_file.fileno(), mode | _posix_fcntl.LOCK_NB)

    def acquire(self) -> "SQLiteUseLock":
        if self._file is not None:
            raise RuntimeError("SQLiteUseLock already acquired")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle_file = self.path.open("a+b")
        self._file = handle_file
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                try:
                    self._try_lock()
                    return self
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise SQLiteDatabaseInUse(
                            "Database is in use; close all PenX connections "
                            "and retry the restore."
                        ) from exc
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        except BaseException:
            handle_file.close()
            self._file = None
            raise

    def release(self) -> None:
        handle = self._file
        if handle is None:
            return
        try:
            if os.name == "nt":
                if not _unlock_file(_win_msvcrt.get_osfhandle(handle.fileno()),
                                    0, 1, 0, ctypes.byref(self._overlapped)):
                    raise OSError(_win_ctypes.get_last_error(), "UnlockFileEx failed")
            else:
                _posix_fcntl.flock(handle.fileno(), _posix_fcntl.LOCK_UN)
        finally:
            handle.close()
            self._file = None
            self._overlapped = None

    def __enter__(self) -> "SQLiteUseLock":
        return self.acquire()

    def __exit__(self, _type, _value, _traceback) -> None:
        self.release()
