"""Offline contract tests for PX-003 local MariaDB read-only session verification."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch

from penx_app.application import evidence_verification as verification


class FakeMariaDBError(Exception):
    pass


class FakeMariaDBConnection:
    def __init__(self):
        self.start_transaction = Mock()
        self.close = Mock()


def fake_mysql(conn=None):
    mysql = types.ModuleType("mysql")
    mysql.__path__ = []
    connector = types.ModuleType("mysql.connector")
    connector.Error = FakeMariaDBError
    connector.connect = Mock(return_value=conn or FakeMariaDBConnection())
    mysql.connector = connector
    return {"mysql": mysql, "mysql.connector": connector}, connector


class MariaDBReadonlyFactoryTests(unittest.TestCase):
    def factory(self, **kwargs):
        options = {
            "host": "127.0.0.1", "port": 3306,
            "database": "penx_test", "user": "penx_reader",
            "password": "only-a-test-secret",
        }
        options.update(kwargs)
        return verification._read_only_mariadb_factory(**options)

    def test_local_credential_and_consistent_snapshot_are_required(self):
        conn = FakeMariaDBConnection()
        modules, api = fake_mysql(conn)
        with patch.dict(sys.modules, modules):
            actual = self.factory()()
        self.assertIs(actual, conn)
        self.assertEqual(api.connect.call_count, 1)
        sent = api.connect.call_args.kwargs
        self.assertEqual(sent["host"], "127.0.0.1")
        self.assertEqual(sent["database"], "penx_test")
        self.assertEqual(sent["user"], "penx_reader")
        self.assertEqual(sent["password"], "only-a-test-secret")
        self.assertEqual(sent["autocommit"], False)
        self.assertEqual(sent["allow_local_infile"], False)
        self.assertEqual(sent["connection_timeout"], 5)
        conn.start_transaction.assert_called_once_with(
            consistent_snapshot=True, isolation_level="REPEATABLE READ",
            readonly=True)
        conn.close.assert_not_called()

    def test_remote_or_invalid_connection_refused_before_import(self):
        candidates = [
            {"host": "198.51.100.42"}, {"host": "evil.example.test"},
            {"host": "127.0.0.1 "}, {"port": 0}, {"port": 65536},
            {"port": "3306"}, {"database": "a; DROP DATABASE penx"},
            {"database": ""}, {"user": "bad user"}, {"password": ""},
        ]
        with patch.dict(sys.modules, {"mysql": None, "mysql.connector": None}):
            for bad in candidates:
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    self.factory(**bad)

    def test_transaction_rejection_closes_connection(self):
        conn = FakeMariaDBConnection()
        conn.start_transaction.side_effect = FakeMariaDBError("no READ ONLY")
        modules, _ = fake_mysql(conn)
        with patch.dict(sys.modules, modules), self.assertRaises(FakeMariaDBError):
            self.factory()()
        conn.close.assert_called_once()

    def test_connection_failure_is_redacted_at_cli(self):
        modules, api = fake_mysql()
        api.connect.side_effect = FakeMariaDBError("private remote password in URL")
        stream = StringIO()
        with (patch.dict(sys.modules, modules),
              patch.dict(os.environ, {"PENX_VERIFY_MARIADB_PASSWORD": "top-secret"}),
              redirect_stdout(stream)):
            status = verification.main([
                "--session", "44", "--mariadb-host", "127.0.0.1",
                "--mariadb-db", "penx_test", "--mariadb-user", "penx_reader",
                "--artifacts", "local-artifacts"])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stream.getvalue())["status"], "unverified")
        self.assertNotIn("top-secret", stream.getvalue())
        self.assertNotIn("private remote", stream.getvalue())

    def test_cli_passes_factory_without_printing_password(self):
        conn = FakeMariaDBConnection()
        modules, api = fake_mysql(conn)
        captured = []

        def fake_verify(session, artifacts, factory):
            captured.append((session, artifacts))
            link = factory()
            link.close()
            return {"status": "verified-retained-integrity", "session_id": session}

        stream = StringIO()
        with (patch.dict(sys.modules, modules),
              patch.dict(os.environ, {"PENX_VERIFY_MARIADB_PASSWORD": "hidden-secret"}),
              patch.object(verification, "verify_session_provenance",
                           side_effect=fake_verify),
              redirect_stdout(stream)):
            status = verification.main([
                "--session", "44", "--mariadb-host", "127.0.0.1",
                "--mariadb-db", "penx_test", "--mariadb-user", "penx_reader",
                "--mariadb-port", "3308", "--artifacts", "private-captures"])
        self.assertEqual(status, 0)
        parsed = json.loads(stream.getvalue())
        self.assertEqual(parsed["backend"], "mariadb-read-only")
        self.assertEqual(parsed["session_id"], 44)
        self.assertEqual(captured, [(44, "private-captures")])
        self.assertNotIn("hidden-secret", stream.getvalue())
        self.assertEqual(api.connect.call_args.kwargs["port"], 3308)
        conn.start_transaction.assert_called_once()
        conn.close.assert_called_once()

    def test_optional_connector_absence_fails_with_generic_json(self):
        stream = StringIO()
        with (patch.dict(sys.modules, {"mysql": None,
                                       "mysql.connector": None}),
              patch.dict(os.environ, {
                  "PENX_VERIFY_MARIADB_PASSWORD": "local-secret",
              }), redirect_stdout(stream)):
            status = verification.main([
                "--session", "55", "--mariadb-host", "localhost",
                "--mariadb-db", "penx_test", "--mariadb-user", "penx_reader",
                "--artifacts", "private"])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stream.getvalue()),
                         {"status": "unverified",
                          "error": "provenance-check-failed"})
        self.assertNotIn("local-secret", stream.getvalue())

    def test_mariadb_options_never_valid_with_metadata_or_sqlite(self):
        cases = [
            ["--metadata", "metadata.json", "--mariadb-host", "127.0.0.1"],
            ["--session", "1", "--sqlite-db", "file.sqlite",
             "--mariadb-host", "127.0.0.1"],
            ["--session", "1", "--mariadb-db", "penx_test"],
            ["--session", "1", "--mariadb-host", "127.0.0.1",
             "--mariadb-db", "penx_test"],
        ]
        with patch.dict(sys.modules, {"mysql": None, "mysql.connector": None}):
            for case in cases:
                with self.subTest(case=case), redirect_stdout(StringIO()) as out:
                    self.assertEqual(verification.main(
                        [*case, "--artifacts", "private"]), 2)
                    self.assertEqual(json.loads(out.getvalue())["status"],
                                     "unverified")

    def test_mariadb_needs_explicit_password_and_never_uses_app_credentials(self):
        with patch.dict(os.environ, {"PENX_VERIFY_MARIADB_PASSWORD": ""}), \
             redirect_stdout(StringIO()) as out:
            self.assertEqual(verification.main([
                "--session", "1", "--mariadb-host", "localhost",
                "--mariadb-db", "penx_test", "--mariadb-user", "penx_reader",
                "--artifacts", "private"]), 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "unverified")

    def test_adapter_failure_from_query_is_redacted(self):
        modules, _ = fake_mysql()
        stream = StringIO()
        with (patch.dict(sys.modules, modules),
              patch.dict(os.environ, {"PENX_VERIFY_MARIADB_PASSWORD": "secret"}),
              patch.object(verification, "verify_session_provenance",
                           side_effect=FakeMariaDBError("private SQL")),
              redirect_stdout(stream)):
            status = verification.main([
                "--session", "1", "--mariadb-host", "127.0.0.1",
                "--mariadb-db", "penx_test", "--mariadb-user", "penx_reader",
                "--artifacts", "private"])
        self.assertEqual(status, 2)
        self.assertNotIn("private SQL", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
