"""PX-003: synthetic discovery limits must not fabricate complete coverage."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest, ScannerOutput
from penx_app.reporting.machine_reports import sarif_from_report
from penx_app.scanners import tools
from penx_app.scanners.endpoint_inventory import EndpointInventory

PACK = ROOT / 'tests/fixtures/scanner_corpus/discovery_limits_v1.json'


class DiscoveryLimitsCorpusTests(unittest.TestCase):
    def setUp(self):
        self.pack = json.loads(PACK.read_text(encoding='utf-8'))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.guards = [self.stack.enter_context(patch(name, side_effect=AssertionError('No corpus I/O')))
                       for name in ('socket.socket.connect', 'socket.socket.sendto',
                                    'socket.getaddrinfo', 'subprocess.Popen', 'requests.Session.request')]

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def source(self, case):
        recipe = case['input']
        count = recipe.get('count', 0)
        self.assertIs(type(count), int)
        self.assertTrue(0 <= count <= 3001)
        lines = [recipe['line_template'].replace('{index}', f'{i:04d}') for i in range(count)]
        if recipe.get('reverse'):
            lines.reverse()
        lines.extend(recipe.get('tail', []))
        raw = '\n'.join(lines)
        self.assertLess(len(raw.encode('utf-8')), 1024 * 1024)
        self.assertEqual(hashlib.sha256(raw.encode('utf-8')).hexdigest(), case['sha256'])
        return raw, [json.loads(line) for line in lines]

    def mapping(self, raw, expected):
        origin = 'https://example.test'
        inventory = EndpointInventory(origin)
        self.assertEqual(inventory.collect_jsonl(raw, 'katana'),
                         (expected['accepted_rows'], expected['rejected_rows']))
        words = []

        def execute(argv, **_kwargs):
            if '-mdp' in argv:
                return ScannerOutput(raw)
            words.extend(Path(argv[argv.index('-w') + 1]).read_text(encoding='utf-8').splitlines())
            return ScannerOutput('[!] Tool returned no output.', status='FAILED', evidence=False)

        with patch.object(tools, 'find_native', return_value='fixture-scanner'), \
             patch.object(tools, '_run_external', side_effect=execute) as executor, \
             patch.object(tools, 'ffuf_words', return_value=['health']), \
             patch.object(tools.time, 'sleep'), \
             patch.object(tools, 'load_inventory', return_value=EndpointInventory(origin)), \
             patch.object(tools, 'save_inventory', return_value=Path('fixture.json')) as save:
            output = tools.run_endpoint_mapping(origin)
        self.assertEqual(executor.call_count, 2)  # One crawl and root-only ffuf.
        self.assertNotIn('tail/admin', words)
        self.assertEqual(set(save.call_args.args[0].entries), {origin + '/safe'})
        return output, list(inventory.entries)

    def test_limits_and_export_parity(self):
        self.assertEqual(self.pack['schema'], 'penx-discovery-limits-v1')
        self.assertEqual(self.pack['provenance']['kind'], 'hand-authored-synthetic')
        self.assertEqual(len({case['id'] for case in self.pack['cases']}), len(self.pack['cases']))
        for case in self.pack['cases']:
            with self.subTest(case=case['id']):
                raw, rows = self.source(case)
                expected, scanner = case['expected'], case['scanner']
                target = case.get('target', 'example.test')
                origin = 'https://' + target
                if scanner == 'endpoint_mapping':
                    output, entries = self.mapping(raw, expected)
                    key = 'e'
                else:
                    with patch.object(tools, 'find_native', return_value='fixture-scanner'), \
                         patch.object(tools, '_run_external', return_value=ScannerOutput(raw)) as execute:
                        output = getattr(tools, 'run_' + scanner)(origin)
                    execute.assert_called_once()
                    key = 's' if scanner == 'subfinder' else 'c'
                    entries = [line for line in str(output).splitlines() if line and not line.startswith('[')]
                self.assertEqual(output.status, expected['status'])
                self.assertEqual(output.evidence, expected['evidence'])
                self.assertEqual(output.diagnostics, expected['diagnostics'])
                self.assertEqual(len(entries), expected['retained'])
                allowed = set()
                for row in rows:
                    if scanner == 'subfinder':
                        allowed.add(row['host'])
                    else:
                        url = urlsplit(row['request']['endpoint'])
                        allowed.add(urlunsplit((url.scheme, url.netloc, url.path, '', '')))
                self.assertTrue(set(entries).issubset(allowed), 'A retained identity was fabricated/clipped')
                self.assertEqual(entries, sorted(entries))
                if expected.get('sorted_preview'):
                    self.assertEqual(entries, sorted(allowed)[:100])
                for entry in entries:
                    if scanner == 'subfinder':
                        self.assertTrue(entry == target or entry.endswith('.' + target))
                    else:
                        self.assertEqual(urlsplit(entry).netloc, target)
                self.assertNotIn('CORPUS_SECRET', str(output) + output.diagnostics)
                typed = run_selected_structured(
                    ScanRequest(target, (key,), active_consent=True),
                    menu={key: (scanner, lambda _target, result=output: result)})
                report = scan_report(build_custom_plan(target, (key,), active_consent=True), typed)
                run = sarif_from_report(report)['runs'][0]
                self.assertEqual(report['coverage']['status'], expected['coverage'])
                self.assertEqual(run['properties']['coverage'], report['coverage'])
                self.assertEqual(run['invocations'][0]['executionSuccessful'],
                                 expected['status'] == 'COMPLETE')
                self.assertEqual(report['findings'], [])
                self.assertEqual(run['results'], [])
                self.assertEqual(bool(typed.results[0].evidence_records), expected['evidence'])
                for record in typed.results[0].evidence_records:
                    self.assertTrue(record.matches(typed.results[0]))


if __name__ == '__main__':
    unittest.main()
