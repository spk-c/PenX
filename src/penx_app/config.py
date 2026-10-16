"""Legacy constant access to an explicitly loadable configuration snapshot."""
import os
from penx_app.app_paths import APP_ROOT
from penx_app.settings import Settings, load_settings

_settings: Settings | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def setting(name: str, default: str) -> str:
    return os.getenv(f'PENX_{name}', os.getenv(f'METATRON_{name}', default))


def __getattr__(name: str):
    global _settings
    if not name.isupper():
        raise AttributeError(name)
    if _settings is None:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=APP_ROOT / '.env')
        _settings = load_settings(root=APP_ROOT)
    return getattr(_settings, name)
