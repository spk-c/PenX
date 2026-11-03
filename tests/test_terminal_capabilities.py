"""Offline regression tests for terminal capability detection and plain mode.

Covers the PX-103 foundation: NO_COLOR / TERM=dumb / PENX_PLAIN resolution,
redirected-TTY plain output, the noninteractive stdout contract (no ANSI)
and 80-column visible-length wrapping.
"""
from __future__ import annotations

import io
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from penx_app.cli import app, cli_views, console_ui
from penx_app.cli.terminal import (
    DEFAULT_WIDTH,
    detect_capabilities,
    visible_length,
    wrap_text,
)


class FakeTTY(io.StringIO):
    """Stream that reports isatty() == True, for capability tests."""

    def isatty(self):  # type: ignore[override]
        return True


def _caps(stream, **environ):
    environ.setdefault("COLUMNS", "80")
    return detect_capabilities(stream=stream, environ=environ)


class CapabilityDetectionTests(unittest.TestCase):
    def test_interactive_tty_enables_color(self):
        caps = _caps(FakeTTY())
        self.assertTrue(caps.interactive)
        self.assertTrue(caps.color)
        self.assertFalse(caps.plain)
        self.assertEqual(caps.width, DEFAULT_WIDTH)

    def test_redirected_stream_is_plain(self):
        caps = _caps(io.StringIO())
        self.assertFalse(caps.interactive)
        self.assertFalse(caps.color)
        self.assertTrue(caps.plain)
        self.assertEqual(caps.width, DEFAULT_WIDTH)

    def test_stream_without_isatty_is_plain(self):
        caps = _caps(object())
        self.assertTrue(caps.plain)
        self.assertFalse(caps.color)

    def test_no_color_disables_color_only(self):
        caps = _caps(FakeTTY(), NO_COLOR="")
        self.assertTrue(caps.interactive)
        self.assertFalse(caps.color)
        self.assertFalse(caps.plain)

    def test_term_dumb_forces_plain(self):
        caps = _caps(FakeTTY(), TERM="dumb")
        self.assertTrue(caps.plain)
        self.assertFalse(caps.color)
        caps = _caps(FakeTTY(), TERM=" DUMB ")
        self.assertTrue(caps.plain)
        caps = _caps(FakeTTY(), TERM="xterm-256color")
        self.assertFalse(caps.plain)
        self.assertTrue(caps.color)

    def test_penx_plain_values(self):
        for value in ("1", "on", "true", "yes", "YES"):
            with self.subTest(value=value):
                caps = _caps(FakeTTY(), PENX_PLAIN=value)
                self.assertTrue(caps.plain)
                self.assertFalse(caps.color)
        for value in ("0", "no", "", "off", "maybe"):
            with self.subTest(value=value):
                caps = _caps(FakeTTY(), PENX_PLAIN=value)
                self.assertFalse(caps.plain)
                self.assertTrue(caps.color)

    def test_columns_override(self):
        self.assertEqual(_caps(io.StringIO(), COLUMNS="100").width, 100)
        self.assertEqual(_caps(io.StringIO(), COLUMNS="40").width, 40)

    def test_invalid_columns_fall_back_to_default(self):
        for value in ("", "abc", "-5", "80.5"):
            with self.subTest(value=value):
                self.assertEqual(_caps(io.StringIO(), COLUMNS=value).width,
                                 DEFAULT_WIDTH)

    def test_interactive_width_uses_terminal_size_without_columns(self):
        fake_size = types.SimpleNamespace(columns=132, lines=50)
        with patch("penx_app.cli.terminal.shutil.get_terminal_size",
                  return_value=fake_size):
            caps = detect_capabilities(stream=FakeTTY(), environ={})
        self.assertEqual(caps.width, 132)

    def test_plain_mode_wins_over_color_defaults(self):
        caps = _caps(FakeTTY(), PENX_PLAIN="1")
        self.assertTrue(caps.plain)
        self.assertFalse(caps.color)


class WrapTextTests(unittest.TestCase):
    def test_short_text_unchanged(self):
        self.assertEqual(wrap_text("hello world", 80), "hello world")
        self.assertEqual(wrap_text("", 80), "")

    def test_exactly_width_stays_single_line(self):
        self.assertEqual(wrap_text("a" * 80, 80), "a" * 80)

    def test_over_width_breaks(self):
        self.assertEqual(wrap_text("a" * 81, 80), "a" * 80 + "\n" + "a")

    def test_word_wrap_respects_boundaries(self):
        text = " ".join(["word"] * 20)
        result = wrap_text(text, 80)
        lines = result.split("\n")
        for line in lines:
            self.assertLessEqual(len(line), 80)
        self.assertEqual(" ".join(line.strip() for line in lines), text)
        for line in lines:
            self.assertEqual(line, line.strip())

    def test_long_word_hard_split(self):
        self.assertEqual(wrap_text("x" * 100, 80), "x" * 80 + "\n" + "x" * 20)

    def test_ansi_sequences_are_zero_width(self):
        styled = "\033[92m" + "a" * 80 + "\033[0m"
        self.assertEqual(wrap_text(styled, 80), styled)

    def test_ansi_wrap_keeps_sequences_intact(self):
        # The leading escape stays with the first line; none is split apart.
        result = wrap_text("\033[92m" + "a" * 81 + "\033[0m", 80)
        self.assertEqual(result, "\033[92m" + "a" * 80 + "\n" + "a\033[0m")

    def test_wrap_preserves_newlines(self):
        self.assertEqual(wrap_text("a\nb", 80), "a\nb")

    def test_wrap_minimum_width_one(self):
        self.assertEqual(wrap_text("abc", 1), "a\nb\nc")

    def test_visible_length(self):
        self.assertEqual(visible_length("\033[92mabc\033[0m"), 3)
        self.assertEqual(visible_length("abc"), 3)


class BadgePhaseTests(unittest.TestCase):
    def test_badge_plain_when_redirected(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(console_ui.badge("high"), "[HIGH]")
            self.assertEqual(console_ui.badge(None), "[UNKNOWN]")
            self.assertEqual(console_ui.badge("weird"), "[WEIRD]")

    def test_badge_colored_on_tty(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream):
            self.assertEqual(console_ui.badge("high"),
                             "\033[91m[HIGH]\033[0m")
            self.assertEqual(console_ui.badge("medium"),
                             "\033[93m[MEDIUM]\033[0m")
            self.assertEqual(console_ui.badge("weird"),
                             "\033[90m[WEIRD]\033[0m")

    def test_badge_honors_no_color(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream), \
             patch.dict("os.environ", {"NO_COLOR": ""}, clear=False):
            self.assertEqual(console_ui.badge("high"), "[HIGH]")

    def test_badge_honors_penx_plain(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream), \
             patch.dict("os.environ", {"PENX_PLAIN": "1"}, clear=False):
            self.assertEqual(console_ui.badge("high"), "[HIGH]")

    def test_phase_plain_when_redirected(self):
        output = io.StringIO()
        with redirect_stdout(output):
            console_ui.phase("MODE", "Passive collection")
            console_ui.phase("RECON")
        self.assertEqual(output.getvalue(),
                         "  [ MODE ]  Passive collection\n"
                         "  [ RECON ]\n")

    def test_phase_colored_on_tty(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream):
            console_ui.phase("MODE", "Passive collection")
        self.assertEqual(stream.getvalue(),
                         "\033[95m  [ MODE ]\033[0m  Passive collection\n")


class CliViewsContractTests(unittest.TestCase):
    """Noninteractive stdout must stay escape-free (JSON/SARIF/log safety)."""

    def test_messages_plain_when_redirected(self):
        output = io.StringIO()
        with redirect_stdout(output):
            cli_views.success("ok")
            cli_views.warn("w")
            cli_views.error("e")
            cli_views.info("i")
        self.assertEqual(output.getvalue(),
                         "[+] ok\n[!] w\n[x] e\n[*] i\n")

    def test_divider_plain_when_redirected(self):
        output = io.StringIO()
        with redirect_stdout(output):
            cli_views.divider()
            cli_views.divider("Session SL#1")
        self.assertEqual(output.getvalue(),
                         "-" * 60 + "\n"
                         + "\n" + "-" * 20 + " Session SL#1 " + "-" * 20 + "\n")

    def test_banner_plain_when_redirected(self):
        output = io.StringIO()
        with redirect_stdout(output):
            cli_views.banner()
        self.assertEqual(output.getvalue(),
                         "PenX | AI Security Assessment | Local LLM | "
                         "Windows 10/11\n" + "-" * 60 + "\n")

    def test_messages_colored_on_tty(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream):
            cli_views.success("ok")
            cli_views.warn("w")
            cli_views.error("e")
            cli_views.info("i")
        self.assertEqual(stream.getvalue(),
                         "\033[92m[+] ok\033[0m\n"
                         "\033[93m[!] w\033[0m\n"
                         "\033[91m[✗] e\033[0m\n"
                         "\033[94m[*] i\033[0m\n")

    def test_divider_colored_on_tty(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream):
            cli_views.divider()
            cli_views.divider("X")
        self.assertEqual(stream.getvalue(),
                         "\033[90m" + "─" * 60 + "\033[0m\n"
                         + "\n\033[33m" + "─" * 20 + " X " + "─" * 20 + "\033[0m\n")

    def test_banner_colored_on_tty(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream):
            cli_views.banner()
        out = stream.getvalue()
        self.assertTrue(out.startswith("\x1b[2J\x1b[H\n\033[95m\n    ██████"))
        self.assertIn("\033[0m\n    \033[90mPenX | AI Security Assessment", out)
        self.assertTrue(out.endswith("\033[90m" + "─" * 60 + "\033[0m\n\n"))

    def test_no_color_interactive_drops_ansi(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream), \
             patch.dict("os.environ", {"NO_COLOR": ""}, clear=False):
            cli_views.success("ok")
            cli_views.banner()
        out = stream.getvalue()
        self.assertTrue(out.startswith("[+] ok\n"))
        self.assertIn("████", out)
        self.assertNotIn("\033[9", out)

    def test_penx_plain_interactive_drops_ansi(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream), \
             patch.dict("os.environ", {"PENX_PLAIN": "1"}, clear=False):
            cli_views.success("ok")
            cli_views.banner()
        self.assertEqual(stream.getvalue(),
                         "[+] ok\n"
                         "PenX | AI Security Assessment | Local LLM | "
                         "Windows 10/11\n" + "-" * 60 + "\n")


class AppPromptTests(unittest.TestCase):
    def test_prompt_plain_when_redirected(self):
        with redirect_stdout(io.StringIO()), \
             patch("builtins.input", return_value="x") as fake:
            app.prompt("Target: ")
        fake.assert_called_once_with("Target: ")

    def test_prompt_colored_on_tty(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream), \
             patch("builtins.input", return_value="x") as fake:
            app.prompt("Target: ")
        fake.assert_called_once_with("\033[36mTarget: \033[0m")

    def test_style_and_pause_helpers_plain(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(app._style("[1]", "92"), "[1]")
            self.assertEqual(app._pause("Press Enter to continue..."),
                             "\nPress Enter to continue...")

    def test_style_and_pause_helpers_colored(self):
        stream = FakeTTY()
        with patch.object(sys, "stdout", stream):
            self.assertEqual(app._style("[1]", "92"), "\033[92m[1]\033[0m")
            self.assertEqual(
                app._pause("Press Enter to continue..."),
                "\n\033[90mPress Enter to continue...\033[0m")


if __name__ == "__main__":
    unittest.main()
