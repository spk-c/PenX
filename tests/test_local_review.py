"""Optional local-AI draft contracts, using fake HTTP sessions only."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from jsonschema import ValidationError

from penx_app.analysis.local_review_client import local_endpoint, request_review
from penx_app.application.local_review import create_review, main
from penx_app.domain.local_review import REVIEW_SCHEMA, review_sources, strict_json, validate_review


def report(count=1):
    return {'schema': 'penx-scan-v1', 'target': 'example.test',
            'adapters': [{'id': 'nuclei', 'status': 'COMPLETE'}],
            'findings': [{'fingerprint': 'penx-finding-v1:' + f'{index:064x}',
                          'name': 'Example finding', 'severity': 'high',
                          'raw_evidence': 'TEMPLATE sample | high | Example observation | https://example.test'}
                         for index in range(count)]}


def review(source=None):
    source = report() if source is None else source
    return {'summary': 'Applicability needs independent review.', 'reviews': [{
        'fingerprint': source['findings'][0]['fingerprint'], 'assessment': 'needs_review',
        'rationale': 'The template observation needs verification.',
        'evidence_quote': 'Example observation', 'suggested_scanner_key': '7'}]}


class Response:
    def __init__(self, content, status=200):
        self.content = content
        self.status_code = status
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def iter_content(self, chunk_size):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start:start + chunk_size]


class Session:
    def __init__(self, response):
        self.response = response
        self.trust_env = True
        self.closed = False
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def post(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))
        return self.response


def envelope(*, finish='stop', content=None, **message_fields):
    message = {'role': 'assistant', 'content': json.dumps(review()) if content is None else content}
    message.update(message_fields)
    return json.dumps({'choices': [{'finish_reason': finish, 'message': message}]}).encode()


class LocalReviewTests(unittest.TestCase):
    def request(self, response):
        session = Session(response)
        result = request_review([], endpoint='http://localhost:1234', model='local-test',
                                schema=REVIEW_SCHEMA, session_factory=lambda: session)
        return result, session

    def test_endpoint_accepts_only_loopback_without_proxy_or_redirect(self):
        self.assertEqual(local_endpoint('http://localhost:1234/v1'), 'http://127.0.0.1:1234/v1/chat/completions')
        self.assertEqual(local_endpoint('http://[::1]:8080'), 'http://[::1]:8080/v1/chat/completions')
        for endpoint in ('https://remote.example', 'http://192.168.1.2:1234',
                         'http://127.0.0.1@remote.example', 'file:///scan',
                         'http://localhost:0', 'http://localhost?token=secret'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                local_endpoint(endpoint)
        response = Response(envelope())
        _, session = self.request(response)
        self.assertFalse(session.trust_env)
        self.assertTrue(session.closed and response.closed)
        self.assertEqual(len(session.calls), 1)
        options = session.calls[0][1]
        self.assertFalse(options['allow_redirects'])
        self.assertEqual(options['timeout'], (5, 60))
        self.assertNotIn('tools', options['json'])

    def test_remote_endpoint_fails_before_client_port(self):
        client = Mock()
        with self.assertRaises(ValueError):
            create_review(report(), endpoint='https://remote.example', model='test', client=client)
        client.assert_not_called()

    def test_no_discovery_for_automatic_or_missing_model(self):
        factory = Mock()
        for model in ('auto', '', ' '):
            with self.subTest(model=model), self.assertRaises(ValueError):
                request_review([], endpoint='http://127.0.0.1', model=model,
                               schema=REVIEW_SCHEMA, session_factory=factory)
        factory.assert_not_called()

    def test_redirect_and_oversized_body_close_resources_and_fail(self):
        for response in (Response(b'', status=302), Response(b'x' * 65537)):
            session = Session(response)
            with self.assertRaises(ValueError):
                request_review([], endpoint='http://127.0.0.1', model='local', schema=REVIEW_SCHEMA,
                               session_factory=lambda: session)
            self.assertTrue(response.closed and session.closed)
            self.assertEqual(len(session.calls), 1)

    def test_truncated_reasoning_tool_and_non_assistant_answers_rejected(self):
        for body in (envelope(finish='length'), envelope(content='', reasoning_content='private reasoning'),
                     envelope(tool_calls=[{'name': 'shell'}]), envelope(role='user')):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.request(Response(body))

    def test_draft_preserves_original_policy_and_has_no_execution_port(self):
        source = report()
        original = deepcopy(source)
        client = Mock(return_value=json.dumps(review()))
        result = create_review(source, endpoint='http://127.0.0.1', model='local', client=client)
        self.assertEqual(result['state'], 'draft-unverified')
        self.assertEqual(source, original)
        self.assertEqual(result['reviewed_findings'], 1)
        client.assert_called_once()

    def test_unknown_id_invented_evidence_and_new_scanner_are_rejected(self):
        sources = review_sources(report())
        for changes in ({'fingerprint': 'penx-finding-v1:' + 'f' * 64},
                        {'evidence_quote': 'Invented evidence not in the source'},
                        {'suggested_scanner_key': '1'}, {'assessment': 'confirmed'},
                        {'command': 'arbitrary shell'}, {'target': 'different.example'}):
            data = review()
            data['reviews'][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises((ValueError, ValidationError)):
                validate_review(json.dumps(data), sources, allowed_scanners={'7'})

    def test_missing_citation_cannot_support_a_positive_claim(self):
        data = review()
        data['reviews'][0]['evidence_quote'] = ''
        with self.assertRaises(ValueError):
            validate_review(json.dumps(data), review_sources(report()), allowed_scanners={'7'})
        data['reviews'][0]['assessment'] = 'insufficient_evidence'
        validate_review(json.dumps(data), review_sources(report()), allowed_scanners={'7'})

    def test_duplicates_and_nonfinite_json_fail_closed(self):
        for text in ('{"summary":"one","summary":"two"}', '{"value":NaN}'):
            with self.assertRaises(ValueError):
                strict_json(text)
        source = report()
        source['findings'] *= 2
        with self.assertRaises(ValueError):
            review_sources(source)
        data = review()
        data['reviews'] *= 2
        with self.assertRaises(ValueError):
            validate_review(json.dumps(data), review_sources(report()), allowed_scanners={'7'})

    def test_review_budget_and_empty_reports(self):
        self.assertEqual(len(review_sources(report(30))), 20)
        self.assertEqual(len(review_sources(report(30), max_findings=3)), 3)
        client = Mock()
        with self.assertRaises(ValueError):
            create_review(report(0), endpoint='http://127.0.0.1', model='local', client=client)
        client.assert_not_called()
        with self.assertRaises(ValueError):
            review_sources(report(1001))

    def test_cli_writes_separate_hash_linked_draft_without_modifying_source(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'scan.json'
            content = json.dumps(report()).encode()
            path.write_bytes(content)
            with patch('penx_app.application.local_review.request_review', return_value=json.dumps(review())):
                self.assertEqual(main([str(path), '--model', 'local', '--output', root]), 0)
                self.assertEqual(main([str(path), '--model', 'local', '--output', root]), 0)
            self.assertEqual(path.read_bytes(), content)
            draft = json.loads((Path(root) / 'penx_review.json').read_text())
            self.assertEqual(draft['source_sha256'], hashlib.sha256(content).hexdigest())
            self.assertTrue((Path(root) / 'penx_review_1.json').is_file())
            self.assertNotIn('PENX_LLM_API_KEY', json.dumps(draft))

    def test_cli_rejection_writes_no_draft(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'scan.json'
            path.write_text(json.dumps(report()))
            with patch('penx_app.application.local_review.request_review', return_value='[TOOL: shell injected]'):
                self.assertEqual(main([str(path), '--model', 'local', '--output', root]), 1)
            self.assertEqual([item.name for item in Path(root).iterdir()], ['scan.json'])


if __name__ == '__main__':
    unittest.main()
