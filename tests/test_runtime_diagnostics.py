"""P1-5: bounded structured runtime diagnostics (scanner metadata v3)."""
import json
import unittest
from dataclasses import replace

from penx_app.application.scan_planner import _terminal_event, run_plan
from penx_app.domain.evidence import capture_evidence
from penx_app.domain.scan_diagnostics import (
    MAX_EVENTS_PER_ADAPTER,
    PlanSummary,
    ScannerRunEvent,
)
from penx_app.domain.scan_models import ScannerOutput, ScannerResult, ScanResult
from penx_app.domain.scan_plan import ScanPlan

# Stored fixtures: byte-identical to the pre-v3 writer output.
V1_FIXTURE = ('{"version": 1, "adapters": [{"id": "nmap", "name": "Nmap", '
              '"status": "COMPLETE", "evidence": true}]}')

V2_FIXTURE = ('{"version": 2, "adapters": [{"id": "nmap", "name": "Nmap", '
              '"status": "COMPLETE", "evidence": true, "records": ['
              '{"scanner_id": "nmap", "kind": "adapter_output", '
              '"parser_version": 1, "raw_start": 0, "raw_end": 4, '
              '"quote": "port", "host": null, "port": null}]}]}')

_CYCLE = [('started', None, None), ('completed', 1.5, 0),
          ('failed', 2.0, 1), ('skipped', None, None),
          ('cancelled', None, None)]


def make_events(count: int, scanner_id: str = 'nmap'):
    return tuple(
        ScannerRunEvent(scanner_id, _CYCLE[i % len(_CYCLE)][0],
                        _CYCLE[i % len(_CYCLE)][1], _CYCLE[i % len(_CYCLE)][2],
                        f'note {i}')
        for i in range(count))


def make_plan(keys, *, parallelism=1, **overrides) -> ScanPlan:
    base = dict(
        profile_id='diagnostics', profile_version=1, target='example.com',
        scanner_keys=tuple(keys), passive_only=False, active_consent=True,
        per_scanner_timeouts={}, max_parallelism=parallelism,
        global_budget_seconds=None, dispatch_interval_seconds=None)
    base.update(overrides)
    return ScanPlan(**base)


def make_adapter(text='[OK] fixture output'):
    def run(target):
        return text

    return run


def _v3_text(events: list, row_id='nmap', plan=None):
    row = {'id': row_id, 'name': 'Nmap', 'status': 'COMPLETE',
           'evidence': True, 'events': events}
    payload = {'version': 3, 'adapters': [row]}
    if plan is not None:
        payload['plan'] = plan
    return json.dumps(payload)


class ScannerRunEventValidationTests(unittest.TestCase):
    def test_valid_event_round_trips_through_dict(self):
        event = ScannerRunEvent('nmap', 'started', 0.5, 0, 'ok')
        self.assertEqual(ScannerRunEvent.from_dict(event.to_dict()), event)

    def test_unknown_event_name_rejected(self):
        with self.assertRaises(ValueError):
            ScannerRunEvent('nmap', 'exploded', None, None, '')

    def test_note_longer_than_200_rejected(self):
        with self.assertRaises(ValueError):
            ScannerRunEvent('nmap', 'started', None, None, 'x' * 201)

    def test_invalid_durations_rejected(self):
        for duration in (True, -1.0, float('inf'), '1.0', [1]):
            with self.subTest(duration=duration):
                with self.assertRaises(ValueError):
                    ScannerRunEvent('nmap', 'started', duration, None, '')

    def test_exit_code_must_be_strict_int(self):
        for exit_code in (True, '0', 0.0, [0]):
            with self.subTest(exit_code=exit_code):
                with self.assertRaises(ValueError):
                    ScannerRunEvent('nmap', 'started', None, exit_code, '')

    def test_from_dict_requires_exact_fields(self):
        value = ScannerRunEvent('nmap', 'started', None, None, '').to_dict()
        value['extra'] = 1
        with self.assertRaises(ValueError):
            ScannerRunEvent.from_dict(value)


class PlanSummaryValidationTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(PlanSummary('standard', 1, 2, 30).max_parallelism, 2)

    def test_invalid_values_rejected(self):
        bad = [('', 1, 1, None), ('p', 0, 1, None), ('p', 1, 0, None),
               ('p', 1, True, None), ('p', 1, 1, 0), ('p', 1, 1, -5),
               ('p', 1, 1, '30'), ('p', 1, 1, True)]
        for values in bad:
            with self.subTest(values=values):
                if values == ('p', 1, 1, None):
                    continue  # valid case; sanity anchor
                with self.assertRaises(ValueError):
                    PlanSummary(*values)


class ByteIdenticalBackwardCompatTests(unittest.TestCase):
    def test_event_free_v1_is_byte_identical(self):
        row = ScannerResult('nmap', 'port 22 open', 'COMPLETE', True, 'Nmap')
        self.assertEqual(ScanResult((row,)).metadata(), V1_FIXTURE)

    def test_event_free_v2_is_byte_identical(self):
        row = ScannerResult('nmap', 'port 22 open', 'COMPLETE', True, 'Nmap')
        record = capture_evidence(row, 0, 4,
                                  kind='adapter_output', parser_version=1)
        row = replace(row, evidence_records=(record,))
        self.assertEqual(ScanResult((row,)).metadata(), V2_FIXTURE)

    def test_stored_v1_fixture_parses_unchanged(self):
        parsed = ScanResult.from_metadata(V1_FIXTURE)
        row = parsed.results[0]
        self.assertEqual(row.scanner_id, 'nmap')
        self.assertEqual(row.status, 'COMPLETE')
        self.assertTrue(row.evidence)
        self.assertEqual(row.run_events, ())
        self.assertIsNone(parsed.plan_summary)

    def test_stored_v2_fixture_parses_unchanged(self):
        parsed = ScanResult.from_metadata(V2_FIXTURE)
        row = parsed.results[0]
        self.assertEqual(len(row.evidence_records), 1)
        self.assertEqual(row.evidence_records[0].quote, 'port')
        self.assertEqual(row.run_events, ())
        self.assertIsNone(parsed.plan_summary)

    def test_v1_with_events_key_rejected(self):
        text = _v3_text([make_events(1)[0].to_dict()])
        text = text.replace('"version": 3', '"version": 1')
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(text)

    def test_v2_with_events_key_rejected(self):
        text = _v3_text([make_events(1)[0].to_dict()])
        text = text.replace('"version": 3', '"version": 2')
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(text)


class MetadataV3RoundTripTests(unittest.TestCase):
    def _build(self):
        row = ScannerResult('nmap', 'port 22 open', 'COMPLETE', True, 'Nmap')
        record = capture_evidence(row, 0, 4,
                                  kind='adapter_output', parser_version=1)
        row = replace(row, evidence_records=(record,))
        row = replace(row, run_events=(
            ScannerRunEvent('nmap', 'started', None, None,
                            'dispatched as node 1/2'),
            ScannerRunEvent('nmap', 'completed', 1.5, 0, '')))
        second = ScannerResult('whois', 'registrar ok', 'COMPLETE', True,
                               'WHOIS', run_events=(
                                   ScannerRunEvent('whois', 'started', None,
                                                   None,
                                                   'dispatched as node 2/2'),
                                   ScannerRunEvent('whois', 'failed', 2.25,
                                                  1, 'boom')))
        return ScanResult((row, second),
                          plan_summary=PlanSummary('standard', 1, 2, 120))

    def test_round_trip_preserves_events_statuses_and_evidence(self):
        original = self._build()
        parsed = ScanResult.from_metadata(original.metadata())
        self.assertEqual(parsed.plan_summary, original.plan_summary)
        self.assertEqual(len(parsed.results), len(original.results))
        for orig, got in zip(original.results, parsed.results, strict=True):
            self.assertEqual(got.scanner_id, orig.scanner_id)
            self.assertEqual(got.status, orig.status)
            self.assertEqual(got.evidence, orig.evidence)
            self.assertEqual(got.run_events, orig.run_events)
            self.assertEqual(len(got.evidence_records),
                             len(orig.evidence_records))

    def test_v3_payload_shape(self):
        payload = json.loads(self._build().metadata())
        self.assertEqual(payload['version'], 3)
        self.assertEqual(payload['plan'],
                         {'profile_id': 'standard', 'profile_version': 1,
                          'max_parallelism': 2, 'global_budget_seconds': 120})
        for row in payload['adapters']:
            self.assertIn('events', row)
            self.assertEqual(len(row['events']), 2)

    def test_round_trip_is_idempotent(self):
        # Event-only rows (no anchors): parsed rows have empty text, so
        # anchored rows cannot re-serialize — same contract as v2 today.
        row = ScannerResult(
            'nmap', 't', 'COMPLETE', True, 'Nmap',
            run_events=(ScannerRunEvent('nmap', 'started', None, None,
                                        'node 1/1'),
                        ScannerRunEvent('nmap', 'completed', 1.5, 0, '')))
        result = ScanResult((row,),
                            plan_summary=PlanSummary('standard', 1, 1, None))
        once = result.metadata()
        again = ScanResult.from_metadata(once).metadata()
        self.assertEqual(once, again)

    def test_deterministic_json_for_same_transcript(self):
        def build():
            row = ScannerResult(
                'nmap', 't', 'COMPLETE', True, 'Nmap',
                run_events=(ScannerRunEvent('nmap', 'started', None, None,
                                            'node 1/1'),
                            ScannerRunEvent('nmap', 'completed', 1.5, 0, '')))
            return ScanResult((row,),
                              plan_summary=PlanSummary('standard', 1, 1, None))

        self.assertEqual(build().metadata(), build().metadata())


class MetadataCapsTests(unittest.TestCase):
    def test_eighth_event_allowed(self):
        row = ScannerResult('nmap', 't', 'COMPLETE', True, 'Nmap',
                            run_events=make_events(8))
        self.assertEqual(len(row.run_events), 8)

    def test_ninth_event_rejected(self):
        with self.assertRaises(ValueError):
            ScannerResult('nmap', 't', 'COMPLETE', True, 'Nmap',
                          run_events=make_events(9))

    def test_101_adapters_rejected_on_write(self):
        rows = tuple(ScannerResult(f'adapter-{i}', 't', 'COMPLETE', True, '')
                     for i in range(101))
        with self.assertRaises(ValueError):
            ScanResult(rows).metadata()

    def test_101_adapters_rejected_on_parse(self):
        rows = [{'id': f'adapter-{i}', 'name': '', 'status': 'COMPLETE',
                 'evidence': True, 'events': []} for i in range(101)]
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(
                json.dumps({'version': 3, 'adapters': rows}))

    def test_ninth_event_rejected_on_parse(self):
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(_v3_text(
                [event.to_dict() for event in make_events(9)]))

    def test_unknown_event_name_rejected_on_parse(self):
        event = make_events(1)[0].to_dict()
        event['event'] = 'exploded'
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(_v3_text([event]))

    def test_long_note_rejected_on_parse(self):
        event = make_events(1)[0].to_dict()
        event['note'] = 'x' * 201
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(_v3_text([event]))

    def test_event_scanner_id_mismatch_rejected(self):
        event = make_events(1)[0].to_dict()
        event['scanner_id'] = 'whois'
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(_v3_text([event]))

    def test_plan_block_validation(self):
        rows = [{'id': 'nmap', 'name': 'Nmap', 'status': 'COMPLETE',
                 'evidence': True, 'events': []}]
        good = json.dumps({
            'version': 3, 'adapters': rows,
            'plan': {'profile_id': 'standard', 'profile_version': 1,
                     'max_parallelism': 1, 'global_budget_seconds': None}})
        parsed = ScanResult.from_metadata(good)
        self.assertEqual(parsed.plan_summary.profile_id, 'standard')
        bad = json.loads(good)
        bad['plan']['max_parallelism'] = '1'
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(json.dumps(bad))


class TerminalEventMappingTests(unittest.TestCase):
    def _row(self, status, diagnostics):
        return ScannerOutput('[!] note', status=status,
                             scanner_id='nmap', diagnostics=diagnostics)

    def test_ran_to_completion_or_partial(self):
        self.assertEqual(_terminal_event(self._row('COMPLETE', '')),
                         'completed')
        self.assertEqual(_terminal_event(self._row('PARTIAL', '')),
                         'partial')

    def test_failed_and_timeout(self):
        self.assertEqual(_terminal_event(self._row('FAILED', 'boom')),
                         'failed')
        self.assertEqual(_terminal_event(self._row(
            'PARTIAL',
            'Timed out after 300 seconds (cooperative stop requested)')),
            'partial')

    def test_cancelled(self):
        self.assertEqual(_terminal_event(self._row(
            'PARTIAL', 'Not started: caller cancelled scan sequence')),
            'cancelled')

    def test_skipped_budget_and_508(self):
        self.assertEqual(_terminal_event(self._row(
            'PARTIAL', 'Not started: global budget exhausted')), 'skipped')
        self.assertEqual(_terminal_event(self._row(
            'PARTIAL',
            'Skipped after HTTP 508 from a previous selected scanner')),
            'skipped')


class ExecutorDiagnosticsTests(unittest.TestCase):
    def test_scheduled_plan_records_lifecycle_events_and_plan_block(self):
        menu = {'1': ('Nmap', make_adapter()),
                '2': ('Whois', make_adapter())}
        plan = make_plan(('1', '2'), parallelism=2)
        result = run_plan(plan, menu=menu)
        self.assertEqual(result.plan_summary,
                         PlanSummary('diagnostics', 1, 2, None))
        payload = json.loads(result.metadata())
        self.assertEqual(payload['version'], 3)
        self.assertEqual(payload['plan']['max_parallelism'], 2)
        for row in result.results:
            self.assertLessEqual(len(row.run_events),
                                 MAX_EVENTS_PER_ADAPTER)
            self.assertGreaterEqual(len(row.run_events), 1)
            self.assertEqual(row.run_events[0].event, 'started')
            self.assertIn(row.run_events[-1].event,
                          ('completed', 'failed', 'skipped', 'cancelled'))
            for event in row.run_events:
                self.assertEqual(event.scanner_id, row.scanner_id)

    def test_scheduled_508_skip_is_recorded_as_skipped_event(self):
        menu = {
            '4': ('HTTP headers',
                  lambda target: 'Server: nginx\n'
                                 'HTTP 508 Resource Limit Is Reached\n'),
            '7': ('Nuclei', make_adapter()),
        }
        plan = make_plan(('4', '7'), parallelism=1, global_budget_seconds=30)
        result = run_plan(plan, menu=menu)
        rows = {row.scanner_id: row for row in result.results}
        self.assertEqual(rows['http_headers'].status, 'COMPLETE')
        self.assertEqual(rows['nuclei'].status, 'PARTIAL')
        self.assertEqual(rows['nuclei'].run_events[0].event, 'skipped')

    def test_sequential_delegation_stays_event_free(self):
        menu = {'1': ('Nmap', make_adapter())}
        plan = make_plan(('1',))
        result = run_plan(plan, menu=menu)
        self.assertIsNone(result.plan_summary)
        for row in result.results:
            self.assertEqual(row.run_events, ())
        self.assertEqual(json.loads(result.metadata())['version'], 2)


if __name__ == '__main__':
    unittest.main()
