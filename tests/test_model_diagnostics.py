"""PX-401 offline no-network model-registry and explicit diagnostic gates."""
import contextlib
import io
import json
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.analysis.model_diagnostics import (
    diagnostic_report, fetch_model_diagnostics, is_loopback_endpoint,
    main, parse_model_registry,
)


SERVER = "http://127.0.0.1:8080"
MODEL = "qwen-local"
CONFIG = {"PENX_LLM_URL": SERVER, "PENX_MODEL": MODEL,
          "PENX_LLM_API_KEY": "test-secret-not-real"}


def response(data=None, *, status=200, body=None):
    obj=Mock()
    obj.status_code=status
    obj.raise_for_status.return_value=None
    payload=json.dumps({"data": [{"id": MODEL, "context_length": 65536}]}
                       if data is None else data).encode() if body is None else body
    obj.raw.read.return_value=payload
    return obj


class ModelRegistryTests(unittest.TestCase):
    def test_context_exact_matching_and_finite_numeric(self):
        raw={"data": [
            {"id":"not-selected", "context_length":1000000},
            {"id":MODEL,"model_info":{"max_model_len":32768}},
        ]}
        self.assertEqual(parse_model_registry(raw,MODEL), {
            "selected_model":MODEL,"registry_status":"listed",
            "context_tokens":32768,"context_source":"model_info.max_model_len"})
        for value in (0,-1,"32768",True,3.5,1000000000000,None):
            with self.subTest(value=value):
                parsed=parse_model_registry({"data":[{"id":MODEL,"context_length":value}]},MODEL)
                self.assertIsNone(parsed["context_tokens"])

    def test_no_matching_model_or_no_context_is_unknown(self):
        self.assertEqual(parse_model_registry({"data":[{"id":"other"}]},MODEL)["registry_status"],
                         "not_listed")
        self.assertIsNone(parse_model_registry({"data":[{"id":MODEL}]},MODEL)["context_tokens"])

    def test_conflicting_ambiguous_duplicate_malformed_metadata_rejected(self):
        conflict={"data":[{"id":MODEL,"n_ctx":8192,"model_info":{"context_length":4096}}]}
        result=parse_model_registry(conflict,MODEL)
        self.assertIsNone(result["context_tokens"])
        self.assertEqual(result["context_source"],"conflicting_metadata")
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            parse_model_registry({"data":[{"id":MODEL},{"id":MODEL}]},MODEL)
        for invalid in (None,[],{},{"data":"bad"},{"data":[{}]*129}):
            with self.subTest(invalid=str(invalid)[:50]),self.assertRaises(ValueError):
                parse_model_registry(invalid,MODEL)

    def test_fetch_bounded_close_redirect_and_header_no_leak(self):
        ok=response()
        get=Mock(return_value=ok)
        result=fetch_model_diagnostics(SERVER+"/v1/models",MODEL,
                                       api_key=CONFIG["PENX_LLM_API_KEY"],http_get=get)
        self.assertEqual(result["context_tokens"],65536)
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertTrue(get.call_args.kwargs["stream"])
        self.assertLessEqual(get.call_args.kwargs["timeout"],10)
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"],
                         "Bearer test-secret-not-real")
        ok.close.assert_called_once()
        redirected=response(status=302)
        with self.assertRaisesRegex(ValueError,"redirect"):
            fetch_model_diagnostics(SERVER+"/v1/models",MODEL,
                                    http_get=Mock(return_value=redirected))
        redirected.close.assert_called_once()
        huge=response(body=b"a"*(512*1024+1))
        with self.assertRaisesRegex(ValueError,"too large"):
            fetch_model_diagnostics(SERVER+"/v1/models",MODEL,http_get=Mock(return_value=huge))
        huge.close.assert_called_once()

    def test_malformed_json_or_http_error_returns_unavailable_without_auth_leak(self):
        malformed=response(body=b"<html>not json</html>")
        get=Mock(return_value=malformed)
        report=diagnostic_report(server_url=SERVER,model_id=MODEL,http_get=get)
        self.assertEqual(report["registry_status"],"unavailable")
        self.assertEqual(report["chat"],"unknown")
        malformed.close.assert_called_once()
        forbidden=response()
        forbidden.raise_for_status.side_effect=requests.HTTPError("SECRET",response=forbidden)
        report=diagnostic_report(server_url=SERVER,model_id=MODEL,
                                 http_get=Mock(return_value=forbidden))
        self.assertEqual(report["registry_status"],"unavailable")

    def test_loopback_default_only_and_remote_explicit_gate(self):
        for endpoint in ("http://localhost:11434","http://127.0.0.1:8080","http://[::1]:8000"):
            self.assertTrue(is_loopback_endpoint(endpoint))
        for endpoint in ("http://192.168.1.2:8080","http://example.org:443","https://8.8.8.8:444"):
            self.assertFalse(is_loopback_endpoint(endpoint))
            with patch("requests.get",side_effect=AssertionError("unapproved network")):
                with self.assertRaisesRegex(ValueError,"--allow-remote"):
                    diagnostic_report(server_url=endpoint,model_id=MODEL)
        report=diagnostic_report(server_url="http://example.org:8080",model_id=MODEL,
                                 allow_remote=True,http_get=Mock(return_value=response()))
        self.assertEqual(report["registry_status"],"listed")

    def test_opt_in_probe_discloses_no_secret_and_failure_is_unknown(self):
        ask=Mock(side_effect=requests.Timeout("synthetic provider offline"))
        get=Mock(return_value=response())
        without=diagnostic_report(server_url=SERVER,model_id=MODEL,http_get=get,
                                  chat=ask)
        ask.assert_not_called()
        self.assertTrue(all(without[k]=="unknown" for k in
                            ("chat","streaming","json_schema","json_object")))
        with_probe=diagnostic_report(server_url=SERVER,model_id=MODEL,
                                     http_get=get,chat=ask,probe=True)
        ask.assert_called_once()
        self.assertEqual(with_probe["chat"],"unknown")
        self.assertEqual(with_probe["json_schema"],"unknown")

    def test_successful_probe_reports_verified_not_claimed_unsupported(self):
        def ask(messages,**kwargs):
            return MODEL,'{"ok":true}' if "response_format" in kwargs else "OK"
        info=diagnostic_report(server_url=SERVER,model_id=MODEL,
                               http_get=Mock(return_value=response()),chat=ask,
                               probe=True)
        for key in ("chat","streaming","json_schema","json_object"):
            self.assertEqual(info[key],"verified")

    def test_cli_json_and_unknown_config_errors_have_no_secrets(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            code=main([],settings=CONFIG,http_get=Mock(return_value=response()))
        self.assertEqual(code,0)
        obj=json.loads(output.getvalue())
        self.assertEqual(obj["selected_model"],MODEL)
        self.assertNotIn(CONFIG["PENX_LLM_API_KEY"],output.getvalue())
        output=io.StringIO()
        with contextlib.redirect_stdout(output),patch("requests.get",side_effect=AssertionError("network")):
            code=main([],settings={**CONFIG,"PENX_LLM_URL":"http://10.0.0.1:8080"})
        self.assertEqual(code,2)
        self.assertIn("--allow-remote",output.getvalue())

    def test_bootstrap_routes_without_loading_scanners(self):
        from penx_app.bootstrap import main as bootstrap
        with patch("sys.argv",["penx","llm-info","--probe"]), \
             patch("penx_app.analysis.model_diagnostics.main",return_value=0) as entry:
            self.assertEqual(bootstrap(),0)
        entry.assert_called_once_with(["--probe"])


if __name__=="__main__":
    unittest.main()

