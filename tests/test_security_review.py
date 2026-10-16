"""Regression tests for reported PenX target-scope, export and integrity bugs."""
import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.storage import db
from penx_app.storage import db_backend
import llm
import penx
from penx_app.storage.db_evals import parse_evaluation_response, import_distilled_rules, get_learned_rules
from penx_app.reporting.export import export_html, export_pdf, export_menu
from penx_app.analysis.parsers import parse_vulnerabilities, parse_summary
from penx_app.scanners.tools import run_tool_by_command, _host, run_tool


class SecurityRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patchdb = patch.object(db_backend, 'DB_PATH', str(Path(self.tmp.name)/'test.db'))
        self.patchdb.start()
        self.sl = db.create_session('example.test')

    def tearDown(self):
        self.patchdb.stop()
        self.tmp.cleanup()

    def test_llm_generated_scans_cannot_change_target(self):
        with patch('penx_app.scanners.tools.run_nmap', return_value='safe-run') as nmap:
            self.assertIn('no authorized', run_tool_by_command('nmap example.test').lower())
            self.assertIn('differs', run_tool_by_command('nmap 169.254.169.254', authorized_target='example.test'))
            self.assertIn('differs', run_tool_by_command('nmap 192.168.1.1', authorized_target='example.test'))
            self.assertIn('exactly one', run_tool_by_command('nmap example.test 10.0.0.1', authorized_target='example.test'))
            self.assertIn('not permitted', run_tool_by_command('powershell example.test', authorized_target='example.test'))
            nmap.assert_not_called()
            self.assertEqual(run_tool_by_command('nmap -sV example.test', authorized_target='example.test'), 'safe-run')
            nmap.assert_called_once_with('example.test')
        with patch('llm.run_tool_by_command', return_value='blocked') as dispatched:
            llm.run_tool_calls([('TOOL','nmap example.test')], authorized_target='example.test')
            dispatched.assert_called_once_with('nmap example.test', authorized_target='example.test')

    def test_html_and_pdf_untrusted_text(self):
        db.save_summary(self.sl, 'raw', '<script>alert(1)</script> & <b>X</b>', 'LOW')
        v = db.save_vulnerability(self.sl, '<img src=x onerror=alert(1)>', 'high', '80', 'http', 'A <strong> X & Y', confidence='possible')
        db.save_fix(self.sl, v, '<script>bad</script>')
        db.save_correction(self.sl, v, 'verified', '<svg/onload=alert(1)>', 'ok', 'test < 3 & x')
        report = db.get_session(self.sl)
        html_file = export_html(report, self.tmp.name)
        html = Path(html_file).read_text(encoding='utf8')
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html)
        self.assertIn('&lt;svg/onload=alert(1)&gt;', html)
        pdf_path = export_pdf(report, self.tmp.name)
        self.assertGreater(Path(pdf_path).stat().st_size, 300)

    def test_export_menu_all_formats(self):
        """The history-menu export path must not use an undefined helper."""
        data = db.get_session(self.sl)
        with patch('penx_app.reporting.export.APP_ROOT', Path(self.tmp.name)), \
             patch('builtins.input', side_effect=['1', '2', '3']), \
             patch('penx_app.reporting.export.export_pdf', return_value='fake.pdf') as pdf, \
             patch('penx_app.reporting.export.export_html', return_value='fake.html') as html:
            for _ in range(3):
                export_menu(data)
        self.assertEqual(pdf.call_count, 2)
        self.assertEqual(html.call_count, 2)

    def test_inline_directives_preserve_order_and_ipv6(self):
        answer = (
            'Need more data. [TOOL: nmap -sV 192.0.2.10] Please run this.\n'
            '[SEARCH: CVE-2024-1234] then [tool: dig example.test] to check DNS.\n'
            '[TOOL: nmap [::1]] trailing explanation.\n'
            'Ignore incomplete [TOOL:] and [SEARCH: ].'
        )
        self.assertEqual(llm.extract_tool_calls(answer), [
            ('TOOL', 'nmap -sV 192.0.2.10'),
            ('SEARCH', 'CVE-2024-1234'),
            ('TOOL', 'dig example.test'),
            ('TOOL', 'nmap [::1]'),
        ])
        self.assertEqual(llm.extract_tool_calls('No commands here.'), [])

    def test_session_scoped_changes_and_fk_cleanup(self):
        sl2 = db.create_session('other.example')
        v1 = db.save_vulnerability(self.sl,'one','low','1','tcp','desc')
        v2 = db.save_vulnerability(sl2,'two','high','2','tcp','desc')
        db.save_fix(self.sl,v1,'fix')
        db.save_correction(self.sl,v1,'verified','old','new','reason')
        from penx_app.storage.db_evals import save_evaluation
        save_evaluation(self.sl,v1,'tester','evidence','valid','high',True,True,True,True,'note')
        self.assertFalse(db.edit_vulnerability(v2,'severity','low', sl_no=self.sl))
        self.assertFalse(db.delete_vulnerability(v2, sl_no=self.sl))
        self.assertEqual(db.get_vulnerabilities(sl2)[0][3], 'high')
        with self.assertRaises(ValueError):
            db.edit_vulnerability(v1,'severity','<script>',sl_no=self.sl)
        with contextlib.closing(db.get_connection()) as con:
            self.assertEqual(con.cursor().execute('PRAGMA foreign_keys').fetchone()[0],1)
        self.assertTrue(db.delete_vulnerability(v1, sl_no=self.sl))
        with contextlib.closing(db.get_connection()) as con:
            for table in ('fixes','corrections','evaluations'):
                self.assertEqual(con.cursor().execute(f'SELECT COUNT(*) FROM {table} WHERE vuln_id=%s',(v1,)).fetchone()[0],0)

    def test_ai_failure_discards_session(self):
        with patch('penx.divider'), patch('penx.prompt',return_value='new.example'), \
             patch('penx.interactive_tool_run',return_value='safe test output'), \
             patch('penx.analyse_target',side_effect=RuntimeError('Model unavailable')):
            penx.new_scan()
        self.assertEqual(len(db.get_all_history()), 1)
        with patch('llm.ask_llm',return_value='[!] Cannot connect'):
            with self.assertRaisesRegex(RuntimeError,'failed'):
                llm.analyse_target('example.test','safe output')

    def test_markdown_evaluation_and_rule_import(self):
        vid=db.save_vulnerability(self.sl, 'Real vuln', 'medium', '80', 'http', 'desc')
        other=db.save_vulnerability(self.sl, 'Real vuln extension', 'low', '81', 'http', 'desc')
        text='**EVAL:** Real vuln\n**VERDICT:** hallucination\n**CONFIDENCE:** high\n**EVIDENCE:** line 1\nline 2\n**SEVERITY_CORRECT:** no\n**CVE_CORRECT:** no\n**SOFTWARE_CORRECT:** no\n**FIX_CORRECT:** no\n**NOTES:** first\nsecond'
        saved = parse_evaluation_response(self.sl,'reviewer',text)
        self.assertEqual(len(saved),1)
        c=db.get_corrections(self.sl)[0]
        self.assertEqual(c[2],vid)
        with contextlib.closing(db.get_connection()) as con:
            row=con.cursor().execute('SELECT evidence_cited, notes FROM evaluations WHERE id=%s',(saved[0],)).fetchone()
        self.assertIn('line 2', row[0])
        self.assertIn('second', row[1])
        self.assertEqual(parse_evaluation_response(self.sl,'reviewer','**EVAL:** Real\n**VERDICT:** valid'),[])
        self.assertEqual(import_distilled_rules('human','RULE: This is a previously reviewed rule.'),[1])
        self.assertEqual(import_distilled_rules('human','RULE: x\nNOTRULE: nope'),[])
        self.assertEqual(len(get_learned_rules()),1)

    def test_duplicate_findings_and_recommendation_review_flags(self):
        example = lambda name, flag, port: {
            'vuln_name': name, 'severity': 'low' if port else 'info',
            'port': port, 'service': 'http', 'description': 'Some details',
            'confidence': 'possible' if port else 'recommendation',
            '_review_flag': flag, '_review_evidence': 'review evidence',
        }
        data = {
            'vulnerabilities': [example('Same name','hallucination','80'),
                                example('Same name','downgraded','443')],
            'recommendations': [example('TLS recommendation','corrected','')],
            'exploits': [], 'raw_scan': 'fixture', 'full_response': 'fixture',
            'risk_level': 'LOW',
        }
        with patch('penx.divider'), patch('penx.prompt', return_value='different.example'), \
             patch('penx.interactive_tool_run', return_value='test evidence'), \
             patch('penx.analyse_target', return_value=data), \
             patch('penx.confirm', return_value=False), \
             patch('penx.print_session'):
            penx.new_scan()
        session_id = next(row[0] for row in db.get_all_history() if row[1] == 'different.example')
        found = db.get_session(session_id)
        self.assertEqual(len(found['vulns']),3)
        self.assertEqual(len(found['corrections']),3)
        linked = {r[2] for r in found['corrections']}
        self.assertEqual(linked, {r[0] for r in found['vulns']})

    def test_timeout_retains_partial_output(self):
        import sys
        result = run_tool([sys.executable, '-c',
            "import time;print('PORT 80 open',flush=True);time.sleep(5)"], timeout=1)
        self.assertIn('PARTIAL OUTPUT',result)
        self.assertIn('PORT 80 open',result)

    def test_lexical_edge_cases(self):
        with self.assertRaises(ValueError):
            _host('_dmarc.example.com')
        self.assertEqual(_host('example.com.'), 'example.com')
        self.assertEqual(_host('bücher.de'), 'xn--bcher-kva.de')
        self.assertIn('::1', llm.extract_tool_calls('[TOOL: nmap [::1]]')[0][1])
        result=parse_vulnerabilities('- VULN: issue | SEVERITY: random | PORT: 443\nEVIDENCE: <tag>\nDESC: d\nFIX: f')
        self.assertEqual(result[0]['severity'],'unknown')
        self.assertIn('Evidence: <tag>',result[0]['description'])
        self.assertIn('next line',parse_summary('SUMMARY: first line\nnext line'))

if __name__=='__main__':
    unittest.main(verbosity=2)
