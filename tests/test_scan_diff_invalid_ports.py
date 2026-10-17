"""Reject impossible Nmap ports and compare equivalent port number spellings.

All fixtures are synthetic; no scanner processes or network operations.
"""
from __future__ import annotations

import unittest

from penx_app.application.scan_trends import _ports, compare_sessions


def session(number: int, raw: str) -> dict:
    return {
        "history": (number, "example.test", "2026-10-17", "active"),
        "summary": (number, number, raw, "synthetic", "LOW"),
        "vulns": [], "corrections": [],
    }


def nmap_xml(port_ids: tuple[str, ...]) -> str:
    entries = "".join(
        '<port protocol="tcp" portid="' + value +
        '"><state state="open"/><service name="http"/></port>'
        for value in port_ids
    )
    return (
        "[ NMAP OUTPUT ]\n[NMAP STRUCTURED XML]\n"
        '<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/>'
        '<ports>' + entries + '</ports></host>'
        '<runstats><finished exit="success"/></runstats></nmaprun>\n'
    )


class NmapPortDiffContracts(unittest.TestCase):
    def test_invalid_xml_ports_do_not_become_scan_observations(self):
        ports, complete = _ports(session(1, nmap_xml(
            ("0", "65536", "99999", "abc", "80"))))
        self.assertTrue(complete)
        self.assertEqual(set(ports), {"80/tcp"})

    def test_xml_port_spelling_is_canonical(self):
        ports, complete = _ports(session(1, nmap_xml(("080", "00080", "80"))))
        self.assertTrue(complete)
        self.assertEqual(set(ports), {"80/tcp"})

    def test_invalid_text_ports_do_not_become_scan_observations(self):
        raw = (
            "[ NMAP OUTPUT ]\n0/tcp open http\n65536/tcp open http\n"
            "80/tcp open http\nNmap done: 1 IP address scanned\n"
        )
        ports, complete = _ports(session(1, raw))
        self.assertTrue(complete)
        self.assertEqual(set(ports), {"80/tcp"})

    def test_equivalent_text_and_xml_ports_do_not_create_false_changes(self):
        old = session(1, "[ NMAP OUTPUT ]\n80/tcp open http\n"
                         "Nmap done: 1 IP address scanned\n")
        new = session(2, nmap_xml(("080", "0", "65536")))
        diff = compare_sessions(old, new)
        self.assertTrue(diff["port_comparison_reliable"])
        self.assertEqual(diff["new_ports"], {})
        self.assertEqual(diff["missing_ports"], {})


if __name__ == "__main__":
    unittest.main()
