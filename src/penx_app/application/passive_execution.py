"""Typed passive providers with cooperative cancellation and shared budget."""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from urllib.parse import quote

from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.domain.scan_plan import assert_valid_plan
from penx_app.scanners.passive_recon import _query_json


class PassiveStopped(RuntimeError):
    pass


def run_passive_plan(plan, *, cancel_event=None, clock=time.monotonic) -> ScanResult:
    assert_valid_plan(plan)
    if not plan.passive_only:
        raise ValueError('Passive execution requires a passive-only plan')
    if plan.max_parallelism != 1:
        raise ValueError('Passive providers run sequentially')
    from penx_app.scanners.scanner_targets import normalize_host
    host = normalize_host(plan.target)
    if '/' in host:
        raise ValueError('Passive execution requires a single host')
    event = cancel_event if cancel_event is not None else threading.Event()
    deadline = clock() + plan.global_budget_seconds if plan.global_budget_seconds is not None else None
    provider_deadline = clock() + 15

    def check():
        if event.is_set():
            raise PassiveStopped('Caller cancelled passive collection')
        remaining = provider_deadline - clock()
        if deadline is not None:
            remaining = min(remaining, deadline - clock())
        if remaining <= 0:
            raise PassiveStopped('Passive provider/global budget exhausted')
        return remaining

    def query(url, **kwargs):
        check()
        value = _query_json(url, control=check, **kwargs)
        check()
        return value

    def dns_records():
        import dns.resolver
        result = {}
        for kind in ('A', 'AAAA', 'MX', 'NS', 'TXT'):
            check()
            try:
                answer = dns.resolver.resolve(host, kind, lifetime=min(1, check()))
                result[kind] = [str(item)[:350] for item in list(answer)[:15]]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                result[kind] = []
            check()
        return result

    def ct_records():
        value = query('https://crt.sh/', params={'q': '%.' + host, 'output': 'json'})
        if not isinstance(value, list):
            raise ValueError('Invalid CT response')
        return [str(item.get('name_value', ''))[:500] for item in value[:30] if isinstance(item, dict)]

    def rdap_records():
        kind = 'ip' if address is not None else 'domain'
        value = query('https://rdap.org/' + kind + '/' + quote(host, safe=''))
        if not isinstance(value, dict):
            raise ValueError('Invalid RDAP response')
        return {key: value[key] for key in ('name', 'handle', 'status', 'events', 'nameservers',
                                           'startAddress', 'endAddress') if key in value}

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    providers = [('passive_rdap', 'RDAP registry', rdap_records)]
    if address is None:
        providers = [('passive_dns', 'DNS via resolver', dns_records),
                     ('passive_ct', 'Certificate transparency', ct_records)] + providers
    elif (address.version == 4 and address.is_global
          and os.environ.get('PENX_SHODAN_INTERNETDB', 'on').casefold() not in ('off', 'false', 'no', '0')):
        def internetdb():
            from penx_app.intelligence.shodan_enrichment import normalize_internetdb
            return normalize_internetdb(query('https://internetdb.shodan.io/' + str(address)), str(address))
        providers.append(('passive_internetdb', 'Historical InternetDB', internetdb))
    results = []
    for index, (identity, name, collect) in enumerate(providers):
        provider_deadline = clock() + 15
        started = clock()
        try:
            check()
            if index and plan.dispatch_interval_seconds is not None:
                event.wait(min(plan.dispatch_interval_seconds, check()))
                check()
            value = collect()
            check()
            text = json.dumps(value, ensure_ascii=True, sort_keys=True)
            clipped = len(text) > 6000
            results.append(ScannerResult(identity, text[:6000], 'PARTIAL' if clipped else 'COMPLETE', bool(value), name,
                                         duration_seconds=max(0, clock() - started),
                                         diagnostics='Provider response truncated' if clipped else ''))
        except PassiveStopped as exc:
            results.append(ScannerResult(identity, '', 'PARTIAL', False, name, diagnostics=str(exc)))
        except Exception as exc:
            # Provider failures do not stop independent providers, and no
            # exception body/URL/key is echoed into diagnostics.
            try:
                check()
            except PassiveStopped as stopped:
                results.append(ScannerResult(identity, '', 'PARTIAL', False, name, diagnostics=str(stopped)))
            else:
                results.append(ScannerResult(identity, '', 'FAILED', False, name,
                                             diagnostics='Passive provider unavailable: ' + type(exc).__name__))
    return ScanResult(tuple(results))
