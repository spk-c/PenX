"""Regression coverage for issue #81/#82 field worksheet provenance gates."""
from __future__ import annotations

from pathlib import Path
import unittest

from scripts.validate_field_acceptance import MATRICES, validate_worksheet


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_refactor_field_evidence.ps1"


def _matrix_section(matrix, status="NOT RUN"):
    lines = ["", "## " + matrix["heading"], ""]
    for key in matrix["keys"]:
        row = ["synthetic-evidence"] * matrix["columns"]
        row[0] = key
        row[matrix["status"]] = status
        lines.append("| " + " | ".join(row) + " |")
    return lines


def worksheet(status="NOT RUN", unsigned=True, matrices=None):
    if matrices is None:
        matrices = MATRICES
    lines = ["Status: NOT SIGNED OFF" if unsigned else "Status: SIGNED OFF"]
    for matrix in matrices:
        lines += _matrix_section(matrix, status)
    return "\n".join(lines)


class FieldAcceptanceValidatorTests(unittest.TestCase):
    def test_generated_template_has_all_required_rows(self):
        code = SCRIPT.read_text(encoding="utf-8")
        for matrix in MATRICES:
            self.assertIn("## " + matrix["heading"], code)
            for key in matrix["keys"]:
                with self.subTest(section=matrix["heading"], key=key):
                    self.assertIn('"| ' + key + ' |', code)
        self.assertIn("An automated template or CI fixture is never a field-test sign-off.", code)

    def test_unsigned_template_is_valid_but_not_signed_off(self):
        self.assertEqual(validate_worksheet(worksheet(), allow_incomplete=True), [])
        problems = validate_worksheet(worksheet())
        self.assertTrue(any("required PASS" in p for p in problems))
        self.assertTrue(any("NOT SIGNED OFF" in p for p in problems))

    def test_complete_metadata_is_structurally_valid_not_proof(self):
        self.assertEqual(validate_worksheet(worksheet("PASS", unsigned=False)), [])

    def test_missing_provenance_rejects_pass_even_if_incomplete_allowed(self):
        data = worksheet("PASS", unsigned=False)
        data = data.replace(
            "| 1 | synthetic-evidence | PASS | synthetic-evidence |",
            "| 1 | synthetic-evidence | PASS | |", 1,
        )
        errors = validate_worksheet(data, allow_incomplete=True)
        self.assertTrue(any("PASS missing column" in x for x in errors))

    def test_missing_row_and_duplicate_id_are_rejected(self):
        data = worksheet()
        data = data.replace("| 5 | synthetic-evidence | NOT RUN |", "| deleted | synthetic-evidence | NOT RUN |", 1)
        self.assertTrue(any("missing row '5'" in p for p in
                            validate_worksheet(data, allow_incomplete=True)))
        lines = worksheet().splitlines()
        entry = next(line for line in lines if line.startswith("| 1 |"))
        lines.insert(lines.index(entry) + 1, entry)
        self.assertTrue(any("duplicate row '1'" in p for p in
                            validate_worksheet("\n".join(lines), allow_incomplete=True)))

    def test_nonpass_status_and_invalid_status(self):
        data = worksheet(status="BLOCKED", unsigned=False)
        self.assertEqual(validate_worksheet(data, allow_incomplete=True), [])
        self.assertTrue(any("required PASS" in e for e in validate_worksheet(data)))
        invalid = worksheet(status="PASSED", unsigned=False)
        self.assertTrue(any("invalid result" in e for e in
                            validate_worksheet(invalid, allow_incomplete=True)))

    def test_windows_only_worksheet_validates_without_kali(self):
        # Kali sections are optional: a Windows-only worksheet must still pass.
        windows = [m for m in MATRICES if not m.get("optional_section")]
        self.assertEqual(
            validate_worksheet(worksheet(matrices=windows), allow_incomplete=True),
            [],
        )

    def test_kali_section_absent_is_not_an_error_but_present_is_validated(self):
        windows = [m for m in MATRICES if not m.get("optional_section")]
        base = worksheet(matrices=windows)
        self.assertNotIn("## Kali loopback scanner matrix", base)
        # Omitting the optional Kali sections produces no section error.
        self.assertEqual(validate_worksheet(base, allow_incomplete=True), [])
        # A duplicated Kali heading is rejected once the section is present.
        kali = next(m for m in MATRICES
                    if m["heading"] == "Kali loopback scanner matrix")
        doubled = base + "\n" + "\n".join(_matrix_section(kali)) \
                  + "\n" + "\n".join(_matrix_section(kali))
        self.assertTrue(any("expected exactly one section" in p
                            for p in validate_worksheet(doubled, allow_incomplete=True)))

    def test_kali_missing_row_rejected(self):
        data = worksheet()
        data = data.replace("| kali-debian-build-install | NOT RUN |",
                            "| deleted | NOT RUN |", 1)
        self.assertTrue(any("missing row 'kali-debian-build-install'" in p
                            for p in validate_worksheet(data, allow_incomplete=True)))

    def test_kali_duplicate_row_rejected(self):
        lines = worksheet().splitlines()
        entry = next(line for line in lines if line.startswith("| kali-xdg-config-0600 |"))
        lines.insert(lines.index(entry) + 1, entry)
        self.assertTrue(any("duplicate row 'kali-xdg-config-0600'" in p
                            for p in validate_worksheet("\n".join(lines), allow_incomplete=True)))

    def test_kali_pass_missing_os_arch_rejected(self):
        # A Kali PASS row must record its OS/arch/kernel provenance (column 3).
        data = worksheet("PASS", unsigned=False)
        data = data.replace(
            "| kali-debian-build-install | PASS | synthetic-evidence |",
            "| kali-debian-build-install | PASS |  |", 1,
        )
        errors = validate_worksheet(data, allow_incomplete=True)
        self.assertTrue(any("PASS missing column 3" in p for p in errors))


if __name__ == "__main__":
    unittest.main()
