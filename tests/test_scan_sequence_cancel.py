"""Cancellation dispatch contracts: never widen scope or start queued scanners."""
from __future__ import annotations

import threading
import unittest
from unittest.mock import Mock

from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest, ScannerOutput


class ScanSequenceCancellationTests(unittest.TestCase):
    def test_precancelled_scan_does_not_start_any_scanner(self):
        event = threading.Event()
        event.set()
        nmap, nuclei = Mock(), Mock()
        result = run_selected_structured(
            ScanRequest("fixture.invalid", ("1", "7"), active_consent=True),
            menu={"1": ("Nmap", nmap), "7": ("Nuclei", nuclei)},
            cancel_event=event,
        )
        nmap.assert_not_called()
        nuclei.assert_not_called()
        self.assertEqual([row.scanner_id for row in result.results],
                         ["nmap", "nuclei"])
        self.assertTrue(all(row.status == "PARTIAL" for row in result.results))
        self.assertFalse(result.has_evidence)
        self.assertTrue(all(not row.evidence_records for row in result.results))
        self.assertTrue(all("Not started" in row.diagnostics
                            for row in result.results))

    def test_cancelling_after_first_scanner_preserves_earlier_evidence(self):
        event = threading.Event()
        called = []
        def first(_target):
            called.append("first")
            event.set()
            return ScannerOutput("Observed 443/tcp open",
                                 status="COMPLETE", evidence=True)
        second = Mock(side_effect=AssertionError("queued scanner should not start"))
        third = Mock(side_effect=AssertionError("queued scanner should not start"))
        result = run_selected_structured(
            ScanRequest("fixture.invalid", ("1", "6", "7"), active_consent=True),
            menu={"1": ("Nmap", first), "6": ("Nikto", second),
                  "7": ("Nuclei", third)},
            cancel_event=event,
        )
        self.assertEqual(called, ["first"])
        second.assert_not_called()
        third.assert_not_called()
        self.assertEqual([row.status for row in result.results],
                         ["COMPLETE", "PARTIAL", "PARTIAL"])
        self.assertEqual([row.evidence for row in result.results],
                         [True, False, False])
        self.assertEqual(len(result.results[0].evidence_records), 1)
        self.assertEqual(result.results[1].evidence_records, ())
        self.assertEqual(result.coverage()["status"], "PARTIAL")

    def test_unset_token_leaves_execution_unchanged(self):
        event = threading.Event()
        runner = Mock(return_value=ScannerOutput("observed", evidence=True))
        result = run_selected_structured(
            ScanRequest("fixture.invalid", ("1",)),
            menu={"1": ("Nmap", runner)}, cancel_event=event,
        )
        runner.assert_called_once_with("fixture.invalid")
        self.assertEqual(result.results[0].status, "COMPLETE")
        self.assertTrue(result.has_evidence)

    def test_cancellation_never_bypasses_active_consent(self):
        event = threading.Event()
        event.set()
        runner = Mock()
        with self.assertRaisesRegex(ValueError, "consent"):
            run_selected_structured(
                ScanRequest("fixture.invalid", ("7",), active_consent=False),
                menu={"7": ("Nuclei", runner)},
                cancel_event=event,
            )
        runner.assert_not_called()

    def test_cancellation_never_bypasses_passive_policy(self):
        event = threading.Event()
        event.set()
        runner = Mock()
        with self.assertRaisesRegex(ValueError, "Passive"):
            run_selected_structured(
                ScanRequest("fixture.invalid", ("1",), passive_only=True),
                menu={"1": ("Nmap", runner)},
                cancel_event=event,
            )
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
