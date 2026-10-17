"""Historic Shodan comparisons must not accept impossible or private IPs.

Synthetic scan-session fixtures only; no DNS, Shodan account, or HTTP calls.
"""
from __future__ import annotations

import json
import unittest

from penx_app.application.scan_trends import _shodan_snapshots, compare_sessions


def scan(session_id: int, ip: str, ports=(443,)):
    record = {
        "ip": ip, "source": "Shodan InternetDB",
        "ports": list(ports), "vulns": ["CVE-2026-12345"],
    }
    return {
        "history": (session_id, "example.test", "2026-10-17", "active"),
        "summary": (session_id, session_id,
                    "[PASSIVE-ONLY RECON]\n\n[SHODAN INTERNETDB RECORD]\n"
                    + json.dumps(record), "synthetic", "LOW"),
        "vulns": [],
    }


class ShodanSnapshotAddressContracts(unittest.TestCase):
    def test_invalid_and_non_public_ips_do_not_become_history_snapshots(self):
        invalid = (
            "999.999.999.999", "256.1.2.3", "127.0.0.1", "10.2.3.4",
            "192.168.1.2", "169.254.169.254", "0.0.0.0",
            "224.0.0.1", "192.0.2.1", "2001:4860:4860::8888",
            "001.002.003.004",
        )
        for ip in invalid:
            with self.subTest(ip=ip):
                self.assertEqual(_shodan_snapshots(scan(1, ip)), {})
                compared = compare_sessions(scan(1, ip, (80,)),
                                            scan(2, ip, (443,)))
                self.assertEqual(compared["shodan_internetdb"]["comparable_ips"], [])
                self.assertEqual(compared["shodan_internetdb"]["new_indexed_ports"], [])
                self.assertEqual(compared["shodan_internetdb"]["no_longer_indexed_ports"], [])

    def test_real_public_ipv4_still_compares_historical_index(self):
        diff = compare_sessions(scan(1, "8.8.8.8", (80,)),
                                scan(2, "8.8.8.8", (443,)))
        indexed = diff["shodan_internetdb"]
        self.assertEqual(indexed["comparable_ips"], ["8.8.8.8"])
        self.assertEqual(indexed["new_indexed_ports"], [
            {"ip": "8.8.8.8", "port": 443}
        ])
        self.assertEqual(indexed["no_longer_indexed_ports"], [
            {"ip": "8.8.8.8", "port": 80}
        ])

    def test_different_valid_ips_remain_incomparable(self):
        diff = compare_sessions(scan(1, "8.8.8.8"),
                                scan(2, "1.1.1.1"))
        self.assertEqual(diff["shodan_internetdb"]["comparable_ips"], [])


if __name__ == "__main__":
    unittest.main()
