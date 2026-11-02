"""Resolve source, installed and portable paths without creating directories."""
from pathlib import Path
import os
import sys


def installed_mode() -> bool:
    """Only Inno-installed EXEs use a separate writable per-user data root."""
    return bool(
        getattr(sys, "frozen", False)
        and (Path(sys.executable).resolve().parent / ".penx-installed").is_file()
    )


def user_data_base() -> Path:
    """Keep Windows LocalAppData; on POSIX honor XDG_DATA_HOME."""
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg and Path(xdg).is_absolute():
        return Path(xdg)
    return Path.home() / ".local" / "share"


def application_root() -> Path:
    if getattr(sys, 'frozen', False):
        if installed_mode():
            return user_data_base() / 'PenX'
        return Path(sys.executable).resolve().parent
    checkout = Path(__file__).resolve().parents[2]
    if (checkout / 'penx.py').is_file() and (checkout / 'src' / 'penx_app').is_dir():
        return checkout
    return user_data_base() / 'PenX'


APP_ROOT = application_root()
