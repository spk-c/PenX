"""Regression coverage for issue #81/#82 field worksheet provenance gates."""
from __future__ import annotations

from pathlib import Path
import unittest

from scripts.validate_field_acceptance import MATRICES, validate_worksheet


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_refactor_field_evidence.ps1"


def worksheet(status="NOT RUN", unsigned=True):
    lines = ["Status: NOT SIGNED OFF" if unsigned else "Status: SIGNED OFF"]
    for matrix in MATRICES:
        lines += ["", "## " + matrix["heading"], ""]
        for key in matrix["keys"]:
            row = ["synthetic-evidence"] * matrix["columns"]
            row[0] = key
            row[matrix["status"]] = status
            lines.append("| " + " | ".join(row) + " |")
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


if __name__ == "__main__":
    unittest.main()
