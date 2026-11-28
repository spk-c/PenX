"""PX-305 offline configuration/IaC linter boundary tests.

Read-only, deterministic, no network and no execution of user-supplied
configuration. Verifies format detection, rule correctness, fail-closed input
handling, redaction and CLI/bootstrap dispatch.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application.local_config_cli import main as config_cli
from penx_app.bootstrap import main as bootstrap_main
from penx_app.scanners.local_config import (
    MAX_CONFIG_BYTES,
    detect_format,
    lint_local_config,
    read_local_config,
)


def rule_ids(report):
    return [f.rule_id for f in report.findings]


class LocalConfigFormatDetectionTests(unittest.TestCase):
    def test_nginx_detected(self):
        self.assertEqual(detect_format("events { worker_connections 1024; }\n", "x"), "nginx")
        self.assertEqual(detect_format("http { server { } }\n", "x"), "nginx")

    def test_apache_detected(self):
        self.assertEqual(detect_format("<directory /var/www>Options Indexes</directory>\n", "x"), "apache")
        self.assertEqual(detect_format("ServerTokens Public\n", "x"), "apache")

    def test_docker_compose_detected(self):
        self.assertEqual(detect_format("services:\n  web:\n    image: nginx\n", "x"), "docker_compose")

    def test_k8s_detected(self):
        self.assertEqual(detect_format("apiVersion: v1\nkind: Pod\n", "x"), "k8s")

    def test_tls_policy_detected(self):
        self.assertEqual(
            detect_format('{"protocols": ["TLSv1.3"]}\n', "x"), "tls_policy")

    def test_unknown_format(self):
        self.assertEqual(detect_format("hello world\n", "x"), "unknown")


class NginxRuleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="penx-config-nginx-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "nginx.conf"

    def write(self, text):
        self.path.write_text(text, encoding="utf-8")

    def test_weak_protocol_cipher_allow_all_server_tokens(self):
        self.write(
            "events {\n"
            "http {\n"
            "  server {\n"
            "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
            "    ssl_ciphers AES128-SHA:DES:HIGH;\n"
            "    allow all;\n"
            "    server_tokens on;\n"
            "  }\n"
            "}\n"
        )
        report = lint_local_config(self.path)
        self.assertEqual(report.format, "nginx")
        self.assertEqual(report.coverage, "COMPLETE")
        self.assertEqual(rule_ids(report), [
            "NGINX_SSLV1", "NGINX_SSL_CIPHERS", "NGINX_ALLOW_ALL", "NGINX_SERVER_TOKENS_ON"])
        self.assertEqual(report.findings[0].line, 4)

    def test_no_false_positive_on_strong_config(self):
        self.write(
            "events {\n"
            "http {\n"
            "  server {\n"
            "    ssl_protocols TLSv1.2 TLSv1.3;\n"
            "    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:HIGH;\n"
            "    server_tokens off;\n"
            "  }\n"
            "}\n"
        )
        report = lint_local_config(self.path)
        self.assertEqual(rule_ids(report), [])

    def test_excluded_cipher_token_not_flagged(self):
        self.write("http {\n  server {\n    ssl_ciphers !DES:HIGH;\n  }\n}\n")
        report = lint_local_config(self.path)
        self.assertNotIn("NGINX_SSL_CIPHERS", rule_ids(report))


class ApacheRuleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="penx-config-apache-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "apache.conf"

    def test_indexes_tokens_trace(self):
        self.path.write_text(
            "<directory /var/www>\n"
            "    Options Indexes\n"
            "    ServerTokens Public\n"
            "    TraceEnabled On\n"
            "</directory>\n",
            encoding="utf-8",
        )
        report = lint_local_config(self.path)
        self.assertEqual(report.format, "apache")
        self.assertEqual(rule_ids(report), [
            "APACHE_INDEXES", "APACHE_SERVER_TOKENS", "APACHE_TRACE_ON"])

    def test_indexes_suppressed_by_negation(self):
        self.path.write_text("<directory /var/www>\n    Options -Indexes\n</directory>\n",
                             encoding="utf-8")
        report = lint_local_config(self.path)
        self.assertNotIn("APACHE_INDEXES", rule_ids(report))


class DockerComposeRuleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="penx-config-compose-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "docker-compose.yml"

    def test_full_findings_and_secret_redaction(self):
        self.path.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    privileged: true\n"
            "    user: root\n"
            "    volumes:\n"
            "      - /etc:/app/etc\n"
            "      - /var/www:/app/www\n"
            "    ports:\n"
            '      - "0.0.0.0:8080:8080"\n'
            "    environment:\n"
            "      - API_KEY=super-secret\n"
            "      - DB_PASSWORD=${DB_PASSWORD}\n",
            encoding="utf-8",
        )
        report = lint_local_config(self.path)
        self.assertEqual(report.format, "docker_compose")
        self.assertEqual(report.coverage, "COMPLETE")
        self.assertEqual(rule_ids(report), [
            "YAML_PRIVILEGED", "YAML_ROOT_USER", "YAML_HOST_MOUNT",
            "YAML_ALL_INTERFACE_PORT", "YAML_ENV_SECRET"])
        # The secret value must never appear in the report.
        dump = json.dumps(report.to_dict())
        self.assertNotIn("super-secret", dump)
        self.assertIn("API_KEY=***", dump)
        # A ${...} reference is not a literal secret and must not be flagged.
        self.assertEqual(sum(1 for f in report.findings if f.rule_id == "YAML_ENV_SECRET"), 1)

    def test_normal_mount_not_flagged(self):
        self.path.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    volumes:\n"
            "      - /app:/data\n"
            "      - /srv/data:/srv\n",
            encoding="utf-8",
        )
        report = lint_local_config(self.path)
        self.assertNotIn("YAML_HOST_MOUNT", rule_ids(report))


class KubernetesRuleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="penx-config-k8s-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "pod.yaml"

    def test_privileged_and_root_in_container(self):
        self.path.write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx\n"
            "      privileged: true\n"
            "      user: root\n",
            encoding="utf-8",
        )
        report = lint_local_config(self.path)
        self.assertEqual(report.format, "k8s")
        self.assertEqual(rule_ids(report), ["YAML_PRIVILEGED", "YAML_ROOT_USER"])


class TlsPolicyRuleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="penx-config-tls-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "policy.json"

    def test_weak_protocol_and_cipher(self):
        self.path.write_text(
            json.dumps({"protocols": ["TLSv1", "TLSv1.3"], "ciphers": ["AES128-SHA", "DES"]}),
            encoding="utf-8",
        )
        report = lint_local_config(self.path)
        self.assertEqual(report.format, "tls_policy")
        self.assertEqual(rule_ids(report), ["TLS_PROTOCOL", "TLS_CIPHER"])

    def test_tls_block_and_strong_policy(self):
        self.path.write_text(
            json.dumps({"tls": {"ssl_protocols": "TLSv1.2 TLSv1.3",
                                "ssl_ciphers": "ECDHE-RSA-AES128-GCM-SHA256:HIGH"}}),
            encoding="utf-8",
        )
        report = lint_local_config(self.path)
        self.assertEqual(rule_ids(report), [])


class FailClosedInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="penx-config-fail-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "cfg"

    def test_missing_file(self):
        with self.assertRaises(ValueError):
            lint_local_config(self.path)

    def test_non_utf8(self):
        self.path.write_bytes(b"\xff\xfe\x00abc")
        with self.assertRaises(ValueError):
            lint_local_config(self.path)

    def test_too_large_file(self):
        self.path.write_bytes(b"a" * (MAX_CONFIG_BYTES + 1))
        with self.assertRaises(ValueError):
            lint_local_config(self.path)

    def test_directory_rejected(self):
        directory = Path(self.directory.name) / "adir"
        directory.mkdir()
        with self.assertRaises(ValueError):
            lint_local_config(directory)

    def test_symlink_rejected(self):
        real = self.path.with_name("actual")
        real.write_text("services:\n", encoding="utf-8")
        try:
            self.path.symlink_to(real)
        except (NotImplementedError, OSError):
            self.skipTest("symlink unavailable")
        with self.assertRaises(ValueError):
            lint_local_config(self.path)

    def test_unknown_format_is_partial_with_no_findings(self):
        self.path.write_text("hello world\n", encoding="utf-8")
        report = lint_local_config(self.path)
        self.assertEqual(report.format, "unknown")
        self.assertEqual(report.coverage, "PARTIAL")
        self.assertEqual(report.findings, ())
        self.assertIn("Format not recognized", report.limitations[1])


class DeterminismAndSecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="penx-config-determinism-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "nginx.conf"
        self.path.write_text(
            "http {\n  server {\n    ssl_protocols TLSv1;\n  }\n}\n",
            encoding="utf-8",
        )

    def test_deterministic_report_and_sha256(self):
        first = lint_local_config(self.path)
        second = lint_local_config(self.path)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.source_sha256, second.source_sha256)

    def test_no_network_or_execution(self):
        with (patch("socket.create_connection",
                    side_effect=AssertionError("unexpected network")),
              patch("subprocess.run",
                    side_effect=AssertionError("unexpected executable")),
              patch("urllib.request.urlopen",
                    side_effect=AssertionError("unexpected outbound lookup"))):
            report = lint_local_config(self.path)
        self.assertEqual(rule_ids(report), ["NGINX_SSLV1"])

    def test_yaml_alias_and_billion_laughs_bounded(self):
        # Anchors/aliases and self-referencing values are a billion-laughs
        # pattern for real YAML parsers. The bounded line parser never expands
        # them, so only the genuine sensitive mount is reported and nothing
        # recurses or crashes.
        anchor_text = (
            "services:\n"
            "  web: &anchor\n"
            "    image: nginx\n"
            "    volumes:\n"
            "      - /etc:/app/etc\n"
            "    nested: &a *a\n"
            "    deep: *a\n"
            "    deeper: *a\n"
            "    deepest: *a\n")
        self.path.write_text(anchor_text, encoding="utf-8")
        report = lint_local_config(self.path)
        # Only the real sensitive mount is reported; no crash, no expansion.
        self.assertEqual(report.format, "docker_compose")
        self.assertEqual(rule_ids(report), ["YAML_HOST_MOUNT"])


class CliAndBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="penx-config-cli-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "nginx.conf"
        self.path.write_text(
            "http {\n  server {\n    ssl_protocols TLSv1;\n  }\n}\n",
            encoding="utf-8",
        )

    def test_cli_lint_success_is_json(self):
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(config_cli(["lint", "--file", str(self.path)]), 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["schema"], "penx-config-lint-v1")
        self.assertEqual(data["format"], "nginx")
        self.assertFalse(data["network_access"])
        self.assertEqual([f["rule_id"] for f in data["findings"]], ["NGINX_SSLV1"])

    def test_cli_lint_failure_is_redacted_and_nonzero(self):
        bad = self.path.with_name("bad.conf")
        bad.write_bytes(b"\xff\xfe")
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(config_cli(["lint", "--file", str(bad)]), 2)
        data = json.loads(out.getvalue())
        self.assertEqual(data["status"], "unverified")
        self.assertEqual(data["network_access"], False)
        # The raw bytes of the file must not be echoed back.
        self.assertNotIn(b"\xff", out.getvalue().encode("utf-8", "replace"))

    def test_cli_missing_file_is_nonzero(self):
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(config_cli(["lint", "--file", str(self.path.with_name("nope"))]), 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "unverified")

    def test_bootstrap_dispatch_is_noninteractive(self):
        with patch("sys.argv", ["penx.py", "config", "lint", "--file", str(self.path)]), \
             redirect_stdout(StringIO()) as out:
            self.assertEqual(bootstrap_main(), 0)
        self.assertEqual(json.loads(out.getvalue())["format"], "nginx")


if __name__ == "__main__":
    unittest.main()
