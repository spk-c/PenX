"""Windows-only negative Authenticode acceptance tests for unsigned fixtures.

Never create signing keys, trust new certificates, install or execute EXEs.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_signed_windows_release.ps1"


class WindowsSignatureVerificationTests(unittest.TestCase):
    def test_readonly_signer_gate_is_explicit_and_no_auto_signing(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for expected in (
            "Get-AuthenticodeSignature", "Get-LocalSha256",
            "ExpectedSignerThumbprint", "ExpectedSha256",
            "SignatureStatus]::Valid", "RequireTimestamp",
            "release_published = $false",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("signtool sign", source.lower())
        self.assertNotIn("gh release create", source.lower())

    @unittest.skipUnless(os.name == "nt", "Windows Authenticode only")
    def test_unsigned_exe_rejected_even_with_correct_sha256(self):
        with tempfile.TemporaryDirectory(prefix="penx-unsigned-signature-") as tmp:
            path = Path(tmp) / "unsigned-fixture.exe"
            original = b"MZ" + b"unsigned-offline-test-only" * 8
            path.write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            proc = subprocess.run([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(SCRIPT), "-ArtifactPath", str(path),
                "-ExpectedSha256", digest,
                "-ExpectedSignerThumbprint", "0" * 40,
            ], capture_output=True, text=True, timeout=30, check=False)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Authenticode signature", proc.stdout + proc.stderr)
            self.assertEqual(path.read_bytes(), original)

    @unittest.skipUnless(os.name == "nt", "Windows Authenticode only")
    def test_modified_digest_is_rejected_before_signature(self):
        with tempfile.TemporaryDirectory(prefix="penx-hash-signature-") as tmp:
            path = Path(tmp) / "unsigned-fixture.exe"
            path.write_bytes(b"MZ" + b"synthetic-unsigned")
            proc = subprocess.run([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(SCRIPT), "-ArtifactPath", str(path),
                "-ExpectedSha256", "f" * 64,
                "-ExpectedSignerThumbprint", "0" * 40,
            ], capture_output=True, text=True, timeout=30, check=False)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("SHA-256 differs", proc.stdout + proc.stderr)

    @unittest.skipUnless(os.name == "nt", "Windows Authenticode only")
    def test_non_executable_file_refused(self):
        with tempfile.TemporaryDirectory(prefix="penx-nonexe-signature-") as tmp:
            path = Path(tmp) / "unsigned-fixture.zip"
            data = b"not-an-executable"
            path.write_bytes(data)
            proc = subprocess.run([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(SCRIPT), "-ArtifactPath", str(path),
                "-ExpectedSha256", hashlib.sha256(data).hexdigest(),
                "-ExpectedSignerThumbprint", "0" * 40,
            ], capture_output=True, text=True, timeout=30, check=False)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("non-reparse-point Windows .exe", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
