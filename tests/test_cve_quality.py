"""Offline quality gate using cited, curated public advisory version boundaries.

Never scans a target or claims the CVE is exploitable on a real host.
"""
from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.intelligence import cve_engine
import cve_quality
from penx_app.intelligence import vendor_status
from penx_app.intelligence.package_inventory import load_inventory, InventoryError, compare_installed, package_status
from penx_app.intelligence.cve_observations import parse_nmap_services

FIXTURE = Path(__file__).parent / "fixtures" / "cve_quality_cases.json"

class CveQualityTests(unittest.TestCase):
    def test_fixture_boundary_quality_gate(self):
        info = json.loads(FIXTURE.read_text(encoding="utf-8"))
        result = cve_quality.evaluate_cases(info["cases"])
        self.assertEqual(result["failed"], 0, result["details"])
        self.assertGreaterEqual(result["passed"], 10)
        self.assertGreaterEqual(result["confusion"]["tp"], 2)
        self.assertGreaterEqual(result["confusion"]["tn"], 2)
        self.assertEqual(result["confusion"]["fp"], 0)
        self.assertEqual(result["confusion"]["fn"], 0)

    def test_inventory_validates_exact_source_package_and_distro(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "inventory.json"
            file.write_text(json.dumps({"distro":"debian","release":"bookworm","packages":[
                {"source":"openssh","version":"1:9.2p1-2+deb12u2"}]}),encoding="utf-8")
            inventory = load_inventory(str(file))
            self.assertEqual(inventory["packages"]["openssh"],"1:9.2p1-2+deb12u2")
            self.assertEqual(package_status("openssh","1:9.2p1-2+deb12u3",inventory)["installed_status"],
                             "below-published-fix")
            self.assertEqual(package_status("openssl","1:9.2p1-2+deb12u3",inventory)["installed_status"],
                             "no-exact-package-match")
            file.write_text(json.dumps({"distro":"debian","release":"bookworm","packages":[
                {"source":"openssh","version":"9.0-1"},{"source":"openssh","version":"9.0-2"}]}))
            with self.assertRaises(InventoryError):
                load_inventory(str(file))

    def test_ubuntu_published_fix_boundary(self):
        advisory = {"packages":[{"name":"openssh","statuses":[
            {"release_codename":"jammy","status":"released","description":"1:8.9p1-3ubuntu0.10"},
            {"release_codename":"noble","status":"released","description":"1:9.6p1-3ubuntu13.3"}]},
            {"name":"unrelated-lib","statuses":[{"release_codename":"jammy",
                                                   "status":"released","description":"1.0-1"}]}]}
        inventory = {"distro":"ubuntu","release":"jammy",
                     "packages":{"openssh":"1:8.9p1-3ubuntu0.9"}}
        with patch("penx_app.intelligence.vendor_status.ubuntu_data",return_value=advisory):
            rows=vendor_status.vendor_guidance({"id":"CVE-2024-6387"},
                                               distro_hint="ubuntu:jammy",inventory=inventory)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["installed_status"],"below-published-fix")
        self.assertEqual(rows[0]["package"],"openssh")
        self.assertNotIn("installed_status",vendor_status.vendor_guidance({"id":"not-a-cve"},
                                                                         inventory=inventory)[0] if vendor_status.vendor_guidance({"id":"not-a-cve"}, inventory=inventory) else {})

    def test_debian_local_snapshot_and_special_not_affected_marker(self):
        fixture={"openssh":{"CVE-2024-6387":{"releases":{
            "bookworm":{"status":"resolved","fixed_version":"1:9.2p1-2+deb12u3"},
            "bullseye":{"status":"resolved","fixed_version":"0"}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/"tracker.json"
            file.write_text(json.dumps(fixture), encoding="utf-8")
            book={"distro":"debian","release":"bookworm",
                  "packages":{"openssh":"1:9.2p1-2+deb12u2"}}
            rows=vendor_status.vendor_guidance(
                {"id":"CVE-2024-6387"},inventory=book,debian_tracker_file=str(file))
            self.assertEqual(rows[0]["installed_status"],"below-published-fix")
            patched={"distro":"debian","release":"bookworm",
                     "packages":{"openssh":"1:9.2p1-2+deb12u3"}}
            rows=vendor_status.vendor_guidance(
                {"id":"CVE-2024-6387"},inventory=patched,debian_tracker_file=str(file))
            self.assertEqual(rows[0]["installed_status"],"at-or-above-published-fix")
            other={"distro":"debian","release":"bullseye","packages":{"openssh":"1:8.4p1-5"}}
            rows=vendor_status.vendor_guidance(
                {"id":"CVE-2024-6387"},inventory=other,debian_tracker_file=str(file))
            self.assertEqual(rows[0]["installed_status"],"vendor-says-not-affected")

    def test_conflicting_distro_hint_is_not_used_for_matching(self):
        inventory={"distro":"debian","release":"bookworm","packages":{"openssh":"1:9.2p1-2"}}
        rows=vendor_status.vendor_guidance({"id":"CVE-2024-6387"},
                                           distro_hint="ubuntu:jammy",inventory=inventory)
        self.assertEqual(rows[0]["status"],"inventory-release-conflict")

    def test_red_hat_only_compares_matching_source_and_release(self):
        advisory={"affected_release":[
            {"product_name":"Red Hat Enterprise Linux 9","package":"openssh-9.2p1-6.el9.src.rpm",
             "advisory":"https://access.redhat.com/errata/RHSA-2024-0000"},
            {"product_name":"Red Hat Enterprise Linux 8","package":"openssh-9.2p1-8.el8.src.rpm"}]}
        inv={"distro":"rhel","release":"9","packages":{"openssh":"9.2p1-5.el9"}}
        with patch("penx_app.intelligence.vendor_status.redhat_data",return_value=advisory):
            rows=vendor_status.vendor_guidance({"id":"CVE-2024-6387"},inventory=inv)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["installed_status"],"below-published-fix")
        self.assertEqual(rows[0]["package"],"openssh")

    def test_discovery_propagates_exact_inventory_status(self):
        xml='<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"><cpe>cpe:/a:openbsd:openssh:9.2</cpe></service></port></ports></host></nmaprun>'
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/"inv.json"
            f.write_text(json.dumps({"distro":"debian","release":"bookworm",
                                     "packages":[{"source":"openssh","version":"1:9.2p1-2+deb12u2"}]}))
            candidates=[{"id":"CVE-2024-6387","product":"OpenSSH","version":"9.2","port":"22/tcp",
                         "source":"NVD","status":"version-match-needs-vendor-review",
                         "evidence":"Nmap cpe","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
                         "vendor_advisories":[]}]
            status=[{"source":"Debian Security Tracker","package":"openssh",
                     "release":"bookworm","status":"resolved","url":"https://security-tracker.debian.org/tracker/CVE-2024-6387",
                     "fixed_version":"1:9.2p1-2+deb12u3","installed_status":"below-published-fix",
                     "installed_version":"1:9.2p1-2+deb12u2"}]
            with patch("penx_app.intelligence.cve_engine.nvd_candidates",return_value=(candidates,"")), \
                 patch("penx_app.intelligence.cve_engine.vendor_guidance",return_value=status) as vendor:
                report=cve_engine.discover(xml,priority=False,inventory_file=str(f))
            self.assertIn("installed",cve_engine.format_report(report))
            self.assertIn("below-published-fix",cve_engine.format_report(report))
            self.assertEqual(vendor.call_args.kwargs["inventory"]["release"],"bookworm")
            self.assertEqual(len(report["candidates"]),1)

if __name__=="__main__":
    unittest.main(verbosity=2)
