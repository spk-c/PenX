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


def application_root() -> Path:
    if getattr(sys, 'frozen', False):
        if installed_mode():
            base = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData' / 'Local')))
            return base / 'PenX'
        return Path(sys.executable).resolve().parent
    checkout = Path(__file__).resolve().parents[2]
    if (checkout / 'penx.py').is_file() and (checkout / 'src' / 'penx_app').is_dir():
        return checkout
    base = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local' / 'share')))
    return base / 'PenX'


APP_ROOT = application_root()
