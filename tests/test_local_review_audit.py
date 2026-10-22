"""Local review guard regressions using synthetic sources and fake transport."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

from penx_app.analysis.local_review_client import request_review
from penx_app.application.local_review import create_review, main
from penx_app.domain.local_review import REVIEW_SCHEMA, review_sources, validate_review


def source():
    return {'schema': 'penx-scan-v1', 'target': 'example.test',
            'adapters': [{'id': 'nuclei', 'status': 'COMPLETE'}],
            'findings': [{'fingerprint': 'penx-finding-v1:' + 'a' * 64,
                          'name': 'Example', 'severity': 'high',
                          'raw_evidence': 'Example observation: X          Y'}]}


def answer(quote='Example observation'):
    return json.dumps({'summary': 'Independent review required', 'reviews': [{
        'fingerprint': source()['findings'][0]['fingerprint'], 'assessment': 'needs_review',
        'rationale': 'Applicability is unverified', 'evidence_quote': quote,
        'suggested_scanner_key': None}]})


class LocalReviewAuditTests(unittest.TestCase):
    def test_padded_auto_model_is_rejected_before_transport(self):
        factory = Mock()
        with self.assertRaises(ValueError):
            request_review([], endpoint='http://127.0.0.1', model=' AuTo ',
                           schema=REVIEW_SCHEMA, session_factory=factory)
        factory.assert_not_called()

    def test_injected_review_client_cannot_bypass_option_validation(self):
        for model, timeout in (('auto', 60), (' ', 60), ('local', 1), ('local', 121), ('local', True)):
            client = Mock(return_value=answer())
            with self.subTest(model=model, timeout=timeout):
                with self.assertRaises(ValueError):
                    create_review(source(), endpoint='http://127.0.0.1', model=model,
                                  timeout=timeout, client=client)
                client.assert_not_called()

    def test_normalized_model_matches_client_request_and_saved_draft(self):
        client = Mock(return_value=answer())
        result = create_review(source(), endpoint='http://127.0.0.1',
                               model='  Local-model  ', client=client)
        self.assertEqual(client.call_args.kwargs['model'], 'Local-model')
        self.assertEqual(result['model'], 'Local-model')

    def test_batch_budget_does_not_hide_invalid_timeout(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'source.json'
            path.write_text(json.dumps(source()), encoding='utf-8')
            with patch('penx_app.application.local_review.request_review', return_value=answer()) as ask:
                code = main([str(path), '--model', 'local', '--timeout', '999',
                             '--batch-budget', '5', '--output', root])
            self.assertEqual(code, 1)
            ask.assert_not_called()
            self.assertEqual(list(Path(root).iterdir()), [path])

    def test_whitespace_padding_cannot_satisfy_minimum_citation_length(self):
        with self.assertRaises(ValueError):
            validate_review(answer('X          Y'), review_sources(source()), allowed_scanners={'7'})

    def test_refusal_cannot_publish_stale_assistant_content(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.iter_content.return_value = [json.dumps({'choices': [{
            'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': answer(),
                                               'refusal': 'Request refused'}}]}).encode()]
        session = MagicMock()
        session.__enter__.return_value = session
        session.post.return_value = response
        with self.assertRaises(ValueError):
            request_review([], endpoint='http://127.0.0.1', model='local',
                           schema=REVIEW_SCHEMA, session_factory=lambda: session)
        response.__exit__.assert_called_once()
        session.__exit__.assert_called_once()


if __name__ == '__main__':
    unittest.main()
