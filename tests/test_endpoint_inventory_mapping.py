"""Offline end-to-end tests for consented Katana -> ffuf endpoint mapping."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from penx_app.application.scanner_selection import resolve_scanner_selection
from penx_app.domain.scan_models import ScannerOutput
from penx_app.scanners import tools
from penx_app.scanners.endpoint_inventory import (
    EndpointInventory, load_inventory, normalize_discovery, save_inventory,
)
from penx_app.scanners.registry import CONSENT_KEYS

ORIGIN = "https://example.test"


def katana_row(url: str) -> str:
    return json.dumps({"request": {"endpoint": url}})


def ffuf_row(url: str, status: int = 200) -> str:
    return json.dumps({"url": url, "status": status})


class EndpointInventoryContracts(unittest.TestCase):
    def test_same_origin_not_related_hosts_ports_or_schemes(self):
        allow = (
            "https://example.test/start?a=secret",
            "https://example.test:443/api/users?id=99",
        )
        for url in allow:
            with self.subTest(url=url):
                self.assertIsNotNone(normalize_discovery(url, ORIGIN))
        bad = (
            "http://example.test/a", "https://other.example.test/a",
            "https://example.test:8443/a", "https://evil.test@example.test/a",
            "https://example.test@evil.test/a", "https://example.test.evil.test/a",
            "https://example.test/a/../admin", "https://example.test/%2e%2e/admin",
            "https://example.test/%2fadmin", "https://example.test/a\\b",
            "https://example.test/a\ninjected", "https://example.test//admin",
            "https://example.test/a?x=y z",
        )
        for url in bad:
            with self.subTest(url=url):
                self.assertIsNone(normalize_discovery(url, ORIGIN))

    def test_deduplicate_paths_and_keep_only_parameter_names(self):
        inv = EndpointInventory(ORIGIN)
        self.assertTrue(inv.add(ORIGIN + "/api/users?token=SUPER_SECRET&page=1", "katana"))
        self.assertTrue(inv.add(ORIGIN + "/api/users?page=2&flag", "ffuf"))
        self.assertEqual(list(inv.entries), [ORIGIN + "/api/users"])
        self.assertEqual(inv.entries[ORIGIN + "/api/users"]["parameters"],
                         {"token", "page", "flag"})
        assert "SUPER_SECRET" not in json.dumps(inv.public_json())
        self.assertNotIn("SUPER_SECRET", inv.summary())
        self.assertEqual(inv.paths_for_fuzz(), [ORIGIN + "/api/"])

    def test_rejects_failed_crawls_and_out_of_scope_ffuf_rows(self):
        inv = EndpointInventory(ORIGIN)
        raw = "\n".join([
            katana_row(ORIGIN + "/api/a?id=123"),
            json.dumps({"request": {"endpoint": ORIGIN + "/api/fail"}, "error": "timeout"}),
            katana_row("https://other.test/"),
            "not json",
        ])
        self.assertEqual(inv.collect_jsonl(raw, "katana"), (1, 3))
        self.assertEqual(inv.collect_jsonl(
            ffuf_row(ORIGIN + "/api/health") + "\n" +
            ffuf_row("https://other.test/login"),
            "ffuf",
        ), (1, 1))
        self.assertEqual(set(inv.entries),
                         {ORIGIN + "/api/a", ORIGIN + "/api/health"})

    def test_safe_direct_get_paths_keep_methods_and_never_replay_queries(self):
        inv = EndpointInventory(ORIGIN)
        raw = "\n".join([
            katana_row(ORIGIN + "/api/users?session=CONFIDENTIAL"),
            katana_row(ORIGIN + "/api/items?page=2"),
            json.dumps({"request": {"method": "POST", "endpoint":
                                    ORIGIN + "/api/create?key=SENSITIVE"}}),
            katana_row(ORIGIN + "/api/delete-user?id=3"),
            katana_row(ORIGIN + "/logout.php?token=4"),
            katana_row(ORIGIN + "/v1/%2fprivate"),
        ])
        accepted, rejected = inv.collect_jsonl(raw, "katana")
        self.assertEqual((accepted, rejected), (5, 1))
        self.assertEqual(inv.entries[ORIGIN + "/api/create"]["methods"], {"POST"})
        paths = inv.paths_for_probe(max_paths=24)
        self.assertEqual(paths, ["api/items", "api/users"])
        self.assertNotIn("CONFIDENTIAL", json.dumps(inv.public_json()))
        self.assertNotIn("SENSITIVE", inv.summary())
        self.assertNotIn("logout.php", "\n".join(paths))
        self.assertEqual(inv.paths_for_probe(max_paths=1), ["api/items"])
        self.assertEqual(inv.paths_for_probe(max_paths=0), [])

    def test_ffuf_rows_require_real_http_status(self):
        inv = EndpointInventory(ORIGIN)
        raw = "\n".join([
            ffuf_row(ORIGIN + "/missing", 0),
            ffuf_row(ORIGIN + "/error", 700),
            json.dumps({"url": ORIGIN + "/fake", "status": True}),
            ffuf_row(ORIGIN + "/good", 403),
        ])
        self.assertEqual(inv.collect_jsonl(raw, "ffuf"), (1, 3))
        self.assertEqual(list(inv.entries), [ORIGIN + "/good"])

    def test_bounded_atomic_persistence_and_invalid_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            first = EndpointInventory(ORIGIN)
            first.add(ORIGIN + "/api?a=SECRET", "katana")
            first.add(ORIGIN + "/api?b=OTHER_SECRET", "katana", method="POST")
            saved = save_inventory(first, directory=path)
            self.assertTrue(saved.exists())
            self.assertNotIn(b"SECRET", saved.read_bytes())
            got = load_inventory(ORIGIN, directory=path)
            self.assertEqual(first.public_json(), got.public_json())
            self.assertEqual(got.entries[ORIGIN + "/api"]["methods"], {"GET", "POST"})
            self.assertEqual(len(load_inventory("https://other.test", directory=path).entries), 0)
            saved.write_bytes(b"X" * 96001)
            self.assertFalse(load_inventory(ORIGIN, directory=path).entries)

    def test_symlink_inventory_is_not_read(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            inv = EndpointInventory(ORIGIN)
            outside = base / "outside.json"
            outside.write_text(json.dumps(inv.public_json()), encoding="utf-8")
            from penx_app.scanners.endpoint_inventory import inventory_path
            link = inventory_path(ORIGIN, directory=base)
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable")
            self.assertEqual(load_inventory(ORIGIN, directory=base).entries, {})


class EndpointMappingExecutionContracts(unittest.TestCase):
    def run_mapping(self, raw, ffuf_output=None, *, cancel_event=None):
        calls = []
        katana = ScannerOutput(raw, status="COMPLETE", evidence=True)
        ffuf = ScannerOutput(
            ffuf_output if ffuf_output is not None else ffuf_row(ORIGIN + "/api/health"),
            status="COMPLETE", evidence=True,
        )

        def execute(argv, **kwargs):
            selected = (Path(argv[argv.index("-w") + 1]).read_text().splitlines()
                        if "-w" in argv else [])
            calls.append((argv, {**kwargs, "words_used": len(selected), "words": selected}))
            return katana if "-mdp" in argv else ffuf

        with tempfile.TemporaryDirectory() as folder, \
             patch.object(tools, "find_native", side_effect=lambda name: name + ".exe"), \
             patch.object(tools, "_run_external", side_effect=execute), \
             patch.object(tools, "load_inventory", side_effect=lambda origin: EndpointInventory(origin)), \
             patch.object(tools, "save_inventory", side_effect=lambda inv: save_inventory(inv, directory=Path(folder))), \
             patch.object(tools.time, "sleep", return_value=None):
            output = tools.run_endpoint_mapping(ORIGIN, cancel_event=cancel_event)
        return output, calls

    def test_opt_in_pipeline_scopes_both_tools_and_reserves_global_budget(self):
        raw = "\n".join([
            katana_row(ORIGIN + "/api/users?token=SENSITIVE&id=2"),
            katana_row(ORIGIN + "/users"),
            katana_row("https://outside.test/admin"),
        ])
        output, calls = self.run_mapping(raw)
        self.assertEqual(len(calls), 3)  # Katana then root + discovered /api/
        self.assertIn("SAME-ORIGIN ENDPOINT INVENTORY", str(output))
        self.assertNotIn("SENSITIVE", str(output))
        self.assertTrue(output.evidence)
        katana_argv = calls[0][0]
        self.assertEqual(katana_argv[katana_argv.index("-mdp") + 1], "24")
        self.assertIn("-cs", katana_argv)
        self.assertIn("-ct", katana_argv)
        self.assertEqual(katana_argv[katana_argv.index("-rl") + 1], "2")
        ffuf_argv = calls[1][0]
        self.assertEqual(ffuf_argv[ffuf_argv.index("-rate") + 1], "2")
        self.assertIn("-p", ffuf_argv)
        self.assertLessEqual(sum(c[1]["words_used"] for c in calls[1:]), 56)

    def test_direct_endpoint_probes_share_budget_and_exclude_state_changes(self):
        raw = "\n".join([
            katana_row(ORIGIN + "/api/item" + str(i) + "?secret=NEVER_SEND")
            for i in range(35)
        ] + [
            katana_row(ORIGIN + "/api/logout.php"),
            katana_row(ORIGIN + "/api/delete-account?id=1"),
            json.dumps({"request": {"method": "POST", "endpoint":
                                    ORIGIN + "/api/transfer?amount=10"}}),
        ])
        output, calls = self.run_mapping(raw)
        self.assertEqual(len(calls), 3)
        words = [row[1]["words"] for row in calls[1:]]
        self.assertIn("api/item0", words[0])
        self.assertNotIn("api/logout.php", words[0])
        self.assertNotIn("api/delete-account", words[0])
        self.assertNotIn("api/transfer", words[0])
        self.assertLessEqual(sum(len(w) for w in words), 56)
        self.assertNotIn("NEVER_SEND", str(output))
        self.assertIn("parameter name(s)", str(output))
        self.assertIn("api/transfer [POST]", str(output))

    def test_different_origin_discoveries_never_become_ffuf_targets(self):
        raw = katana_row(ORIGIN + "/api/users") + "\n" + katana_row("https://outside.test/a")
        output, calls = self.run_mapping(raw)
        self.assertNotIn("https://outside.test/a", str(output))
        for args, _kwargs in calls:
            self.assertNotIn("https://outside.test", " ".join(args))
        self.assertIn("https://example.test/api", str(output))

    def test_precancelled_mapping_starts_no_external_io(self):
        token = threading.Event()
        token.set()
        with patch.object(tools, "find_native", side_effect=AssertionError("unwanted lookup")), \
             patch.object(tools, "_run_external", side_effect=AssertionError("unwanted request")):
            out = tools.run_endpoint_mapping(ORIGIN, cancel_event=token)
        self.assertEqual(out.status, "PARTIAL")
        self.assertFalse(out.evidence)

    def test_cancelled_katana_never_starts_followup_ffuf(self):
        token = threading.Event()
        calls = []
        def exec_fn(args, **kwargs):
            calls.append(args)
            token.set()
            return ScannerOutput(katana_row(ORIGIN + "/api/users"), evidence=True)
        with patch.object(tools, "find_native", return_value="binary.exe"), \
             patch.object(tools, "_run_external", side_effect=exec_fn):
            out = tools.run_endpoint_mapping(ORIGIN, cancel_event=token)
        self.assertEqual(len(calls), 1)
        self.assertEqual(out.status, "PARTIAL")
        self.assertFalse(out.evidence)

    def test_cancellation_during_ffuf_stops_all_remaining_passes(self):
        token = threading.Event()
        calls = []

        def execute(argv, **kwargs):
            calls.append(argv)
            if "-mdp" in argv:
                return ScannerOutput(katana_row(ORIGIN + "/api/users"),
                                     status="COMPLETE", evidence=True)
            token.set()
            return ScannerOutput(ffuf_row(ORIGIN + "/api/health"),
                                 status="COMPLETE", evidence=True)

        with patch.object(tools, "find_native", return_value="scanner.exe"), \\
             patch.object(tools, "_run_external", side_effect=execute):
            output = tools.run_endpoint_mapping(ORIGIN, cancel_event=token)
        self.assertEqual(output.status, "PARTIAL")
        self.assertFalse(output.evidence)
        self.assertEqual(len(calls), 2)

    def test_no_authorized_discoveries_means_no_followup_ffuf(self):
        result, calls = self.run_mapping(katana_row("https://evil.test/"))
        self.assertEqual(len(calls), 1)
        self.assertFalse(result.evidence)
        self.assertIn("no follow-on ffuf", result)

    def test_mapping_is_separate_choice_and_requires_consent(self):
        self.assertIn("e", CONSENT_KEYS)
        self.assertIn("e", tools.TOOLS_MENU)
        self.assertEqual(resolve_scanner_selection("e", tools.TOOLS_MENU), ("e",))
        self.assertNotIn("e", resolve_scanner_selection("x", tools.TOOLS_MENU))


if __name__ == "__main__":
    unittest.main()
