"""Terminal-only scanner selection and explicit consent."""
from penx_app.scanners.registry import CONSENT_KEYS
from penx_app.application.scanner_selection import resolve_scanner_selection
from penx_app.domain.scan_models import ReconChoice, ScannerOutput

def interactive_tool_run(target: str, *, menu: dict, formatter) -> str | ReconChoice | None:
    """Choose bounded scanner presets; obtain consent before active discovery."""
    from penx_app.cli.cli_navigation import is_back, show_back, navigation_input
    print('\n[ SELECT TOOLS TO RUN ]')
    print('  [0] Passive-Only Recon (no active scans)')
    for key, (name, _) in menu.items():
        print(f'  [{key}] {name}')
    print('  [a] Standard Scan (1-5)')
    print('  [n] Standard Scan + Nikto (1-6)')
    print('  [x] Full Scan (all 12 including Subfinder, Katana and TLS; confirmation)')
    show_back()
    choice = navigation_input('\nChoice(s), e.g. 0, 1 2 4, a, n, x: ').strip().lower()
    if any(is_back(item) and item != "0" for item in choice.replace(",", " ").split()):
        return None
    selected_keys = resolve_scanner_selection(choice, menu)
    if selected_keys is ReconChoice.PASSIVE_ONLY:
        return selected_keys
    if selected_keys is None:
        keys = choice.replace(",", " ").split()
        if "0" in keys:
            print('[!] Passive-Only Recon must be selected alone. No scanners started.')
        else:
            print('[!] Invalid scanner selection. No scanners started.')
        return None
    if CONSENT_KEYS.intersection(selected_keys):
        print('[!] Nuclei, ffuf and Katana generate additional HTTP requests.')
        print(f'[!] Only scan systems you are authorized to assess: {target}')
        consent = navigation_input('Run these bounded active checks? [y/N]: ').strip().lower()
        if consent not in ('y', 'yes', 'j', 'ja'):
            print('[*] Active web checks cancelled; no scanner was started.')
            return None
    from penx_app.application.scanner_execution import run_selected_structured
    from penx_app.domain.scan_models import ScanRequest
    request = ScanRequest(target, tuple(dict.fromkeys(selected_keys)), active_consent=True)
    results = run_selected_structured(request, menu=menu, emit=print)
    # Preserve the injected formatter's historical dict/ScannerOutput API.
    # Structured adapter status remains authoritative through this boundary.
    legacy_view = {
        row.display_name: ScannerOutput(
            row.text, status=row.status, evidence=row.evidence,
            scanner_id=row.scanner_id,
            duration_seconds=row.duration_seconds,
            exit_code=row.exit_code,
            diagnostics=row.diagnostics,
            evidence_records=row.evidence_records,
        )
        for row in results.results
    }
    return formatter(legacy_view)

