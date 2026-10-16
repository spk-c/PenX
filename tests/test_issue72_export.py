"""Regression test for executive report output formatting (issue #72)."""
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from penx_app.reporting.export import export_menu


class ExecutiveExportOutputTests(unittest.TestCase):
    def test_executive_paths_are_printed_on_separate_lines(self):
        data = {"history": (42, "example.test")}
        capture = io.StringIO()
        with patch("penx_app.cli.cli_navigation.navigation_input", return_value="5"), \
             patch("penx_app.reporting.export.os.makedirs"), \
             patch("penx_app.reporting.export.export_pdf", return_value="example.pdf") as pdf, \
             patch("penx_app.reporting.export.export_html", return_value="example.html") as html, \
             redirect_stdout(capture):
            export_menu(data)

        pdf.assert_called_once()
        html.assert_called_once()
        self.assertEqual(pdf.call_args.kwargs["mode"], "executive")
        self.assertEqual(html.call_args.kwargs["mode"], "executive")
        lines = capture.getvalue().splitlines()
        self.assertIn("[+] Executive PDF: example.pdf", lines)
        self.assertIn("[+] Executive HTML: example.html", lines)
        self.assertNotIn("\\n[+] Executive HTML:", capture.getvalue())


if __name__ == "__main__":
    unittest.main()
