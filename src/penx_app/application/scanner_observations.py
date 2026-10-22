"""Conservative deterministic observations from completed non-Nuclei adapters."""
import re


def observations(adapter):
    if adapter.status != 'COMPLETE' or not adapter.evidence:
        return []
    text = adapter.text[:1_048_576]
    found = []
    if adapter.scanner_id == 'tls' and text.startswith('[VERIFIED TLS HANDSHAKE]'):
        match = re.search(r'(?m)^Days remaining: (-?\d+)\s*$', text)
        if match and 0 <= int(match.group(1)) <= 30:
            found.append(('tls-certificate-expiring', 'TLS certificate expires within 30 days',
                          'low', match.group(0), 'tls'))
    elif adapter.scanner_id == 'http_headers':
        match = re.search(r'(?im)^Strict-Transport-Security:[ \t]*max-age[ \t]*=[ \t]*0[ \t]*(?:;[^\r\n]*)?$', text)
        if match:
            found.append(('http-hsts-disabled', 'Response explicitly disables HSTS',
                          'low', match.group(0), 'http'))
        values = re.findall(r'(?im)^X-Powered-By:\s*(PHP/[^\r\n]+)$', text)
        if values:
            from penx_app.intelligence.php2shell_audit import classify_live_php2shell_headers
            if classify_live_php2shell_headers(values)['status'] == 'POTENTIALLY_VULNERABLE':
                quote = next(line for line in text.splitlines() if re.match(r'(?i)^X-Powered-By:\s*PHP/', line))
                found.append(('php-version-review', 'Reported PHP release requires patch verification',
                              'medium', quote, 'http'))
    elif adapter.scanner_id == 'nmap':
        # Open services are inventory only, never automatically vulnerabilities.
        for match in re.finditer(r'(?m)^\d{1,5}/(?:tcp|udp)\s+open\s+[^\r\n]{1,200}$', text):
            port, protocol = match.group(0).split()[0].split('/')
            if 1 <= int(port) <= 65535:
                found.append(('open-service', 'Observed open network service', 'info', match.group(0), str(int(port)) + '/' + protocol))
    elif adapter.scanner_id == 'nikto':
        for match in re.finditer(r'(?m)^\+ (?:OSVDB-\d+|/[^\s:]{0,100}): [^\r\n]{12,500}$', text):
            found.append(('nikto-observation', 'Nikto observation requires applicability review',
                          'info', match.group(0), match.group(0).split(': ', 1)[0]))
    # The report builder applies its global finding cap and records truncation.
    # A second silent cap here would make omitted observations invisible to it.
    return found
