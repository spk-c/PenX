"""Terminal-only scanner selection and explicit consent."""
from penx_app.scanners.registry import CONSENT_KEYS
from penx_app.application.scanner_selection import resolve_scanner_selection
from penx_app.cli.scanner_cancellation import scanner_cancellation
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
    print('  [x] Full Scan (original 12 tools; endpoint mapping requires explicit [e])')
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
        print('[!] Nuclei, ffuf, Katana and endpoint mapping generate additional HTTP requests.')
        print(f'[!] Only scan systems you are authorized to assess: {target}')
        if "e" in selected_keys:
            print('[!] [e] runs a same-origin Katana crawl and multiple bounded ffuf directory probes.')
            print('[!] Estimated budget: 24 crawler pages + <= 56 ffuf URLs at <= 2 requests/s.')
            print('[!] Page count is not a strict wire-level request cap; redirects and server effects must be reviewed.')
        consent = navigation_input('Run these bounded active checks? [y/N]: ').strip().lower()
        if consent not in ('y', 'yes', 'j', 'ja'):
            print('[*] Active web checks cancelled; no scanner was started.')
            return None
    from penx_app.application.scanner_execution import run_selected_structured
    from penx_app.domain.scan_models import ScanRequest
    request = ScanRequest(target, tuple(dict.fromkeys(selected_keys)), active_consent=True)
    print('[*] Scanning: press Ctrl+C once to cancel the remaining tools.')
    with scanner_cancellation() as cancel_event:
        results = run_selected_structured(
            request, menu=menu, emit=print, cancel_event=cancel_event,
        )
    if cancel_event.is_set():
        # Even if earlier adapters returned valid evidence, cancellation is
        # not consent to save a partial assessment or continue to local AI.
        print('[*] Scanner run cancelled. No assessment will be created.')
        return None
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

