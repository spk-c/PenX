"""PenX evaluations/feedback regression tests (portable Python, no old DB required).

Creates a disposable SQLite database with deterministic fixture records. Run as:
    python test_updates.py
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

_TEMP = tempfile.TemporaryDirectory(prefix='penx-legacy-test-')
os.environ['PENX_DB_ENGINE'] = 'sqlite'
os.environ['PENX_DB_PATH'] = str(Path(_TEMP.name) / 'fixture.db')

from penx_app.config import DB_ENGINE, DB_PATH, MODEL_NAME
from penx_app.storage import db
from penx_app.storage.db_backend import get_connection
from penx_app.storage.db_evals import (save_evaluation, get_evaluations, delete_evaluation,
                      parse_evaluation_response, export_eval_package, save_learned_rule)
from penx_app.storage.db_training import export_training_data
from penx_app.cli.db_display import print_session
from penx_app.reporting.export import fetch_session
from penx_app.analysis.llm import load_correction_rules, build_system_prompt
from penx_app.analysis.prompts import SYSTEM_PROMPT


class FeatureRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sl = db.create_session('example.test')
        cls.apache = db.save_vulnerability(cls.sl, 'Apache HTTP Server', 'medium',
                                           '80', 'HTTP', 'Test header identifies Apache')
        cls.log4j = db.save_vulnerability(cls.sl, 'Apache Log4j Library', 'high',
                                          '80', 'HTTP', 'Fictitious finding')
        cls.reviewed = db.save_vulnerability(
            cls.sl, 'Individually reviewed observation', 'low',
            '443', 'HTTPS', 'Manually verified fixture', confidence='confirmed')
        db.save_correction(cls.sl, cls.reviewed, 'verified', 'reviewed original',
                           'reviewed finding', 'fixture review')
        db.save_summary(cls.sl, 'HTTP Server: Apache', 'Two candidate findings', 'MEDIUM', 'unit-test')
        db.save_fix(cls.sl, cls.apache, 'Update Apache HTTP Server')
        db.save_exploit(cls.sl, 'No activity', 'none', 'none', 'not executed', 'Offline fixture')
        for n, status in enumerate(('verified', 'corrected', 'downgraded', 'reclassified', 'hallucination')):
            vuln = cls.log4j if status == 'hallucination' else cls.apache
            db.save_correction(cls.sl, vuln, status, 'old claim', 'corrected evidence-based claim', f'fixture {n}')
        cls.rule = save_learned_rule('Only claim findings clearly supported by observed scan output.', 'fixture')

    def test_01_sqlite_connection(self):
        with contextlib.closing(get_connection()) as conn:
            self.assertEqual(conn.cursor().execute('SELECT 1').fetchone()[0], 1)

    def test_02_schema_tables(self):
        with contextlib.closing(get_connection()) as conn:
            names = {r[0] for r in conn.cursor().execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        self.assertTrue({'history', 'vulnerabilities', 'fixes', 'exploits_attempted',
                         'summary', 'corrections', 'evaluations', 'learned_rules'} <= names)

    def test_03_schema_model_name(self):
        with contextlib.closing(get_connection()) as conn:
            names = {r[1] for r in conn.cursor().execute('PRAGMA table_info(summary)').fetchall()}
        self.assertIn('model_name', names)

    def test_04_evaluations_schema(self):
        with contextlib.closing(get_connection()) as conn:
            names = {r[1] for r in conn.cursor().execute('PRAGMA table_info(evaluations)').fetchall()}
        self.assertTrue({'id', 'sl_no', 'vuln_id', 'evaluator', 'evidence_cited', 'verdict',
                         'confidence', 'severity_correct', 'cve_correct', 'software_correct',
                         'fix_correct', 'notes', 'evaluated_at'} <= names)

    def test_05_correction_seed(self):
        self.assertGreaterEqual(len(db.get_corrections(self.sl)), 5)

    def test_06_session_contains_all_sections(self):
        data = db.get_session(self.sl)
        self.assertTrue({'history', 'vulns', 'fixes', 'exploits', 'summary',
                         'corrections', 'evaluations'} <= data.keys())
        self.assertIsNotNone(data['history'])

    def test_07_add_delete_correction(self):
        cid = db.save_correction(self.sl, self.apache, 'verified', 'old', 'new', 'reason')
        self.assertTrue(any(r[0] == cid for r in db.get_corrections(self.sl)))
        db.delete_correction(cid, sl_no=self.sl)
        self.assertFalse(any(r[0] == cid for r in db.get_corrections(self.sl)))

    def test_08_edit_correction(self):
        cid = db.save_correction(self.sl, self.apache, 'corrected', 'old', 'new', 'before')
        db.edit_correction(cid, 'reason', 'after', sl_no=self.sl)
        with contextlib.closing(get_connection()) as conn:
            row = conn.cursor().execute('SELECT reason FROM corrections WHERE id=%s', (cid,)).fetchone()
        self.assertEqual(row[0], 'after')
        db.delete_correction(cid, sl_no=self.sl)

    def test_09_eval_crud(self):
        eid = save_evaluation(self.sl, self.apache, 'offline test', 'server header', 'valid', 'high',
                              True, True, True, False, 'test')
        try:
            ev = next(r for r in get_evaluations(self.sl) if r[0] == eid)
            self.assertEqual(ev[5], 'valid')
            self.assertEqual(ev[7], 1)
            self.assertEqual(ev[10], 0)
        finally:
            delete_evaluation(eid, sl_no=self.sl)

    def test_10_eval_package(self):
        with tempfile.TemporaryDirectory() as out:
            path = export_eval_package(self.sl, output_dir=out)
            text = Path(path).read_text(encoding='utf-8')
            for label in ('RAW SCAN DATA', 'AI VULNERABILITY FINDINGS',
                          'Evaluation Instructions', 'EXISTING CORRECTIONS', f'SL#{self.sl}'):
                self.assertIn(label, text)

    def test_11_evaluation_parser(self):
        response = '''EVAL: Apache HTTP Server
VERDICT: valid
CONFIDENCE: high
EVIDENCE: Server header
SEVERITY_CORRECT: yes
CVE_CORRECT: yes
SOFTWARE_CORRECT: yes
FIX_CORRECT: yes
NOTES: Evidence confirmed

EVAL: Apache Log4j Library
VERDICT: hallucination
CONFIDENCE: high
EVIDENCE: none
SEVERITY_CORRECT: no
CVE_CORRECT: no
SOFTWARE_CORRECT: no
FIX_CORRECT: no
NOTES: Not supported

OVERALL_RISK_LEVEL: LOW
'''
        ids = parse_evaluation_response(self.sl, 'parser-fixture', response)
        try:
            self.assertEqual(len(ids), 2)
            verdicts = {r[5] for r in get_evaluations(self.sl) if r[0] in ids}
            self.assertEqual(verdicts, {'valid', 'hallucination'})
        finally:
            for eid in ids:
                delete_evaluation(eid, sl_no=self.sl)

    def test_12_training_data(self):
        with tempfile.TemporaryDirectory() as out:
            path = export_training_data(out)
            rows = [json.loads(l) for l in Path(path).read_text(encoding='utf-8').splitlines()]
            self.assertTrue(rows)
            # Scope to this test's own session: with other test files sharing
            # the same in-process DB, rows[0] may belong to a foreign session.
            own = next(r for r in rows if r['metadata']['sl_no'] == self.sl)
            self.assertEqual(own['metadata']['target'], 'example.test')
            self.assertTrue(Path(path.replace('.jsonl', '_stats.json')).is_file())

    def test_13_learned_rules(self):
        loaded = load_correction_rules()
        self.assertIn('LEARNED RULES', loaded)

    def test_14_prompt_injection(self):
        final = build_system_prompt()
        self.assertGreater(len(final), len(SYSTEM_PROMPT))
        self.assertIn('PenX', final)

    def test_15_print_session(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            print_session(db.get_session(self.sl))
        self.assertIn('CORRECTIONS', buf.getvalue())
        self.assertIn('EVALUATIONS', buf.getvalue())
        self.assertIn('SUMMARY', buf.getvalue())

    def test_16_export_fetch(self):
        data = fetch_session(self.sl)
        self.assertGreaterEqual(len(data['corrections']), 5)
        self.assertIsNotNone(data['summary'])

    def test_17_saved_summary_model(self):
        data = db.get_session(self.sl)
        self.assertEqual(data['summary'][5], 'unit-test')

    def test_18_self_review_format(self):
        import re
        source = 'REVIEW: Apache Log4j Library | VERDICT: hallucination\nEVIDENCE: none\nISSUE: unsupported\nCORRECTED: remove'
        match = re.search(r'REVIEW:\s*(.+?)\s*\|\s*VERDICT:\s*(\w+)', source)
        self.assertEqual(match.groups(), ('Apache Log4j Library', 'hallucination'))


if __name__ == '__main__':
    try:
        result = unittest.main(verbosity=2, exit=False).result
    finally:
        _TEMP.cleanup()
    raise SystemExit(0 if result.wasSuccessful() else 1)
