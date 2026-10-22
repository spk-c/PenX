"""Plain-language scan guidance, independent of terminal input and execution."""
from penx_app.application.scan_profiles import get_profile

SCANNER_GUIDANCE = {
    '1': 'Nmap: contacts the target to identify open ports and service versions.',
    '2': 'WHOIS: asks public registration services for domain ownership records.',
    '3': 'Web fingerprint: sends web requests to identify visible technologies.',
    '4': 'HTTP headers: reads web response headers; may retry with a GET request.',
    '5': 'DNS: queries domain records such as addresses and mail configuration.',
    '6': 'Nikto: actively checks common web configuration weaknesses; can be noisy.',
    '7': 'Nuclei: sends template-based web checks; matches require applicability review.',
    '8': 'httpx: probes the supplied web endpoint for status and technology information.',
    '9': 'ffuf: requests a bounded set of paths to discover exposed web resources.',
    'e': 'Endpoint mapping: crawls same-origin pages and tries bounded GET paths.',
    's': 'Subfinder: queries passive sources for subdomains; discoveries are not scanned automatically.',
    'c': 'Katana: follows bounded same-host links; crawling generates web requests.',
    'd': 'TLS: contacts the endpoint to inspect its certificate and handshake.',
}

GOALS = {
    '1': ('standard', 'A first inventory of a system you administer; active service and web checks.'),
    '2': ('passive', 'Historical/public-provider information without direct target probing; providers receive queries.'),
    '3': ('web_audit', 'A deliberate web audit with additional active requests and explicit consent.'),
    '4': ('full_assessment', 'Broad coverage for experienced operators with explicit authorization and consent.'),
}

RESULT_GUIDANCE = (
    'Severity describes potential impact; it does not prove exploitability. '
    'Confidence describes how well a claim is supported. A scanner quote is an '
    'observation, not independent vulnerability verification. Missing evidence '
    'needs review. A failed or partial scan cannot show that a weakness is fixed. '
    'Headless severity policy currently rates only Nuclei matches; other tools '
    'supply collection coverage. An empty findings list does not mean secure.'
)


def recommend_profile(goal: str):
    if goal not in GOALS:
        raise ValueError('Choose a listed scan goal')
    return get_profile(GOALS[goal][0])


def explain_profile(profile) -> str:
    lines = [f'Recommended profile: {profile.id} v{profile.version}', profile.description]
    if profile.passive_only:
        lines.append('Passive queries contact third-party providers. Historical data can be incomplete or stale.')
    else:
        lines.append('Active collection contacts this target. Schedule it within your authorized window.')
        lines.extend(SCANNER_GUIDANCE[key] for key in profile.scanner_keys)
    lines.append('Discovered hosts are not automatically added to scope.')
    return '\n'.join(lines)
