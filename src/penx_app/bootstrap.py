"""Command dispatch before importing components with configuration dependencies."""
from __future__ import annotations
import sys
from penx_app.version import VERSION

USAGE = ('Usage: PenX.exe [--version | --check | --setup-status | --setup | '
         '--setup-native | --llm-setup | --check-update | --update | '
         '--export-session SL --format json|sarif [--redact]]')


def main() -> int:
    args = sys.argv[1:]
    if args:
        command = args[0]
        if command in ('--version', '-V'):
            print(f'PenX Windows {VERSION}')
            return 0
        if command == '--check-update':
            from penx_app.updates import check_update
            check_update()
            return 0
        if command == '--update':
            from penx_app.updates import update_interactive
            return 0 if update_interactive() else 1
        if command == '--setup-status':
            from penx_app.setup.first_run_setup import print_status
            print_status()
            return 0
        if command == '--llm-setup':
            from penx_app.setup.llm_setup import maybe_configure_llm
            return 0 if maybe_configure_llm(force=True) else 1
        if command == '--check':
            from penx_app.setup.windows_check import main as check
            return check()
        if command == '--setup-native':
            from penx_app.setup.native_scanner_setup import main as setup
            return setup()
        if command == '--setup':
            from penx_app.setup.first_run_setup import run_setup
            return run_setup(force=True)
        if command == '--export-session':
            from penx_app.reporting.machine_reports import export_cli
            return export_cli(args[1:])
        print(USAGE)
        return 2

    from penx_app.setup.llm_setup import maybe_configure_llm
    maybe_configure_llm()
    from penx_app.app_paths import APP_ROOT
    from penx_app.config import configure
    from penx_app.settings import load_settings
    from dotenv import load_dotenv
    load_dotenv(APP_ROOT / '.env')  # Legacy optional providers still read env.
    try:
        configure(load_settings(root=APP_ROOT))
    except ValueError as exc:
        print(f'[!] Configuration: {exc}')
        return 2
    from penx_app.cli.app import main as run
    run()
    return 0
