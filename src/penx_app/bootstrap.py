"""Command dispatch before importing components with configuration dependencies."""
from __future__ import annotations
import sys
from penx_app.version import VERSION

USAGE = ('Usage: PenX.exe [--version | --check | --setup-status | --setup | '
         '--setup-native | --llm-setup | --check-update | --update | '
         '--export-session SL --format json|sarif [--redact] | '
         '--php2shell-audit [--scan-file FILE] [--php-ini FILE] '
         '[--access-log FILE] [--error-log FILE] | '
         'preflight --target HOST [--profile ID] [--scanners KEYS] '
         '[--consent] | scan --target HOST --authorized [--profile ID] '
         '[--output DIR] [--format json|sarif|both] | '
         'profiles --validate FILE | profiles --export ID | '
         'guided [--target HOST] [--output DIR] | review-scan FILE --model ID]')


def _force_utf8_text_streams(streams) -> None:
    """Redirected output on a non-UTF-8 locale (German Windows: cp1252) crashes
    on non-Latin characters in scanner or model output, so every dispatch path
    needs the same protection the interactive app applies to its console."""
    for stream in streams:
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def main() -> int:
    _force_utf8_text_streams((sys.stdout, sys.stderr))
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
        if command == '--php2shell-audit':
            from penx_app.cli.php2shell_audit_cli import audit_cli
            return audit_cli(args[1:])
        if command == 'preflight':
            from penx_app.application.preflight import main as preflight_main
            return preflight_main(args[1:])
        if command == 'scan':
            from penx_app.application.headless_scan import main as scan_main
            return scan_main(args[1:])
        if command == 'profiles':
            from penx_app.application.profile_documents import main as profiles_main
            return profiles_main(args[1:])
        if command == 'guided':
            from penx_app.cli.guided_scan import main as guided_main
            return guided_main(args[1:])
        if command == 'review-scan':
            from penx_app.application.local_review import main as review_main
            return review_main(args[1:])
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
