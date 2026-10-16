#!/usr/bin/env python3
"""Record a REAL PenX -> localhost HTTP check -> saved report workflow on Windows.

The HTTP request and PenX CLI/database/PDF generation are real. The "AI" step is
a clearly labelled scripted OpenAI-compatible endpoint for repeatability,
NOT an actual trained language model. No third-party hosts are contacted.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from imageio_ffmpeg import get_ffmpeg_exe
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "localhost_demo_video"
OUTPUT.mkdir(exist_ok=True)
TARGET = "http://127.0.0.1:8765"
MODEL_URL = "http://127.0.0.1:8766"
WIDTH, HEIGHT, FPS = 1280, 720, 12
ESC = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)")
BG = (7, 16, 28)
GREEN = (85, 238, 184)
PALE = (226, 238, 246)
MUTED = (154, 179, 196)

class LocalTestSite(BaseHTTPRequestHandler):
    """A real HTTP endpoint, deliberately isolated to localhost."""
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server-Info", "PenX-Localhost-Fixture")
        self.send_header("X-PenX-Demo", "Real-Local-HTTP-Response")
        self.end_headers()

    def do_GET(self):
        self.do_HEAD()
        self.wfile.write(b"<h1>PenX localhost lab: authorized test only</h1>")

    def log_message(self, fmt, *args):
        pass


class ScriptedModel(BaseHTTPRequestHandler):
    """Scripted *fixture* output; must never be advertised as a real LLM."""
    calls = []

    def respond(self, response):
        data = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/v1/models":
            self.respond({"object": "list", "data": [{"id": "scripted-localhost-demo", "object": "model"}]})
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw)
        messages = body.get("messages") or []
        user_text = str(messages[-1].get("content", "")) if messages else ""
        review = "AI ANALYSIS TO REVIEW" in user_text
        if not review and ("HTTP 200" not in user_text or "Real-Local-HTTP-Response" not in user_text):
            self.send_error(400, "Scanner evidence missing; refusing simulated analysis")
            return
        ScriptedModel.calls.append("review" if review else "initial")
        if review:
            answer = (
                "REVIEW: Check HTTP header configuration before production deployment "
                "| VERDICT: VALID\n"
                "EVIDENCE: HTTP 200 -> http://127.0.0.1:8765/\n"
                "ISSUE: Informational operational review only; no exploit was demonstrated.\n"
                "ADJUSTED_RISK_LEVEL: LOW"
            )
        else:
            answer = (
                "RISK_LEVEL: LOW\n"
                "SUMMARY: The locally hosted training web server returned HTTP 200. "
                "Header data was collected. No exploitable vulnerability was established.\n"
                "REC: Check HTTP header configuration before production deployment\n"
                "DESC: Review the real response headers captured from the localhost training "
                "server; this informational check is not a verified vulnerability."
            )
        self.respond({
            "id": "chatcmpl-scripted-localhost",
            "object": "chat.completion",
            "model": "scripted-localhost-demo",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": answer},
                         "finish_reason": "stop"}],
        })

    def log_message(self, fmt, *args):
        pass


def capture_workflow():
    web = ThreadingHTTPServer(("127.0.0.1", 8765), LocalTestSite)
    ai = ThreadingHTTPServer(("127.0.0.1", 8766), ScriptedModel)
    for server in (web, ai):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(TARGET, timeout=5) as response:
            if response.status != 200:
                raise RuntimeError("Local training server did not start")
        with tempfile.TemporaryDirectory(prefix="penx_localhost_video_", ignore_cleanup_errors=True) as directory:
            db_file = Path(directory) / "penx-demo.sqlite"
            env = dict(os.environ)
            env.update({
                "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
                "PENX_DB_ENGINE": "sqlite", "PENX_DB_PATH": str(db_file),
                "PENX_MODEL": "scripted-localhost-demo",
                "PENX_LLM_URL": MODEL_URL, "PENX_STRUCTURED_OUTPUT": "off",
                "PENX_CVE_DISCOVERY": "off", "PENX_CVE_PRIORITY": "off",
                "PENX_VERIFY_SOURCES": "off", "PENX_MAX_LOOPS": "1",
                "PENX_LIVE_OUTPUT": "0",
            })
            # ACTUAL PenX menu choices: New Scan -> localhost URL -> HTTP Headers
            # -> decline edits -> History -> session 1 -> Back -> Exit.
            inputs = "1\n" + TARGET + "\n4\nn\n\n2\n1\n0\n\n8\n"
            run = subprocess.run(
                [sys.executable, "-u", str(ROOT / "penx.py")],
                cwd=ROOT, env=env, input=inputs, capture_output=True,
                text=True, encoding="utf-8", errors="replace",
                timeout=100, check=False
            )
            transcript = ESC.sub("", run.stdout).replace("\r", "")
            (OUTPUT / "actual-PenX-transcript.txt").write_text(
                "Real localhost HTTP scan; scripted AI endpoint (NOT a language model).\n\n"
                + transcript + "\nSTDERR:\n" + run.stderr, encoding="utf-8")
            if run.returncode:
                raise RuntimeError(f"PenX exited {run.returncode}: {transcript[-1500:]} {run.stderr[-500:]}")
            must = ["NEW SCAN", "Running HTTP", "AI ANALYSIS", "self-review",
                    "Automatic reports created", "SCAN HISTORY", "Shutting down PenX"]
            missing = [term for term in must if term.lower() not in transcript.lower()]
            if missing:
                raise RuntimeError(f"Missing real workflow stages {missing}: {transcript[-3000:]}")
            with sqlite3.connect(db_file) as db:
                rows = db.execute("SELECT raw_scan, ai_analysis, risk_level FROM summary").fetchall()
                status = db.execute("SELECT status FROM history WHERE sl_no=1").fetchone()
            if not rows or not status or status[0] != "active":
                raise RuntimeError("No committed PenX assessment")
            raw_scan, analysis, risk = rows[0]
            if "HTTP 200" not in raw_scan or "Real-Local-HTTP-Response" not in raw_scan:
                raise RuntimeError("Real PenX HTTP-header adapter did not record localhost evidence")
            if ScriptedModel.calls != ["initial", "review"]:
                raise RuntimeError(f"Expected initial+review stub calls, got {ScriptedModel.calls}")
            if risk != "LOW":
                raise RuntimeError(f"Unexpected report risk: {risk}")
            html_files = sorted((ROOT / "reports").glob("penx_SL1_*.html"))
            pdf_files = sorted((ROOT / "reports").glob("penx_SL1_*.pdf"))
            if len(html_files) != 1 or len(pdf_files) != 1:
                raise RuntimeError("PenX did not generate both automatic report formats")
            html = html_files[0].read_text(encoding="utf-8")
            if "127.0.0.1" not in html or "training web server" not in analysis:
                # The JSON/legacy analysis is intentionally a fixture, never inferred AI.
                raise RuntimeError("Report/analysis content unexpectedly incomplete")
            for entry in html_files + pdf_files:
                (OUTPUT / entry.name).write_bytes(entry.read_bytes())
            return transcript, raw_scan, analysis, pdf_files[0]
    finally:
        for server in (web, ai):
            server.shutdown()
            server.server_close()


def font(size=20, bold=False):
    options = ([r"C:\Windows\Fonts\consolab.ttf",
                r"C:\Windows\Fonts\consola.ttf"] if bold
               else [r"C:\Windows\Fonts\consola.ttf",
                     r"C:\Windows\Fonts\consolab.ttf"])
    options += ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]
    for name in options:
        if Path(name).exists():
            return ImageFont.truetype(name, size)
    return ImageFont.load_default()


def base(title, subtitle, number):
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    d = ImageDraw.Draw(image)
    for x in range(45, WIDTH, 80):
        d.line((x, 0, x, HEIGHT), fill=(12, 32, 44))
    for y in range(44, HEIGHT, 80):
        d.line((0, y, WIDTH, y), fill=(12, 32, 44))
    d.rounded_rectangle((30, 25, 1250, 694), radius=20, fill=(12, 27, 40),
                        outline=(39, 92, 91), width=2)
    d.text((62, 45), "PenX", font=font(38, True), fill=GREEN)
    d.text((200, 60), title, font=font(24, True), fill=PALE)
    d.text((63, 109), subtitle, font=font(17), fill=MUTED)
    d.line((62, 150, 1210, 150), fill=(45, 93, 91), width=2)
    d.text((62, 650), "REAL LOCALHOST HTTP CHECK  |  SCRIPTED AI FIXTURE  |  NO INTERNET TARGETS",
           font=font(14), fill=GREEN)
    d.text((1120, 650), number, font=font(16, True), fill=MUTED)
    return image, d


def terminal(image, draw, content, *, label, max_rows=17):
    draw.rounded_rectangle((63, 178, 1217, 620), radius=14,
                           fill=(7, 17, 28), outline=(34, 71, 87), width=2)
    draw.rounded_rectangle((64, 179, 1216, 221), radius=12, fill=(22, 44, 57))
    draw.rectangle((64, 209, 1216, 222), fill=(22, 44, 57))
    draw.text((90, 188), label, font=font(18, True), fill=(196, 225, 232))
    lines = content.replace("\r", "").splitlines()
    lines = [line.replace("\t", "  ")[:108] for line in lines if line.strip()]
    if len(lines) > max_rows:
        lines = lines[-max_rows:]
    y = 243
    for line in lines:
        color = PALE
        if any(key in line for key in ["200", "LOW", "penx>", "127.0.0.1", "created", "Running"]):
            color = GREEN
        if "[!]" in line:
            color = (244, 196, 104)
        draw.text((90, y), line, font=font(18), fill=color)
        y += 21


def excerpt(source, start, end=None, *, fallback=None):
    where = source.find(start)
    if where < 0:
        return fallback if fallback is not None else source[-1000:]
    piece = source[where:]
    if end:
        e = piece.find(end, len(start))
        if e >= 0:
            piece = piece[:e]
    return piece


def pdf_page(pdf_path):
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(str(pdf_path))
    picture = doc[0].render(scale=1.6).to_pil().convert("RGB")
    doc.close()
    return picture


def frame(scene, progress, seconds, transcript, raw_scan, analysis, document):
    names = [
        ("LOCALHOST DEMO", "A reproducible workflow using the actual PenX source CLI", "01 / 07"),
        ("START PENX", "Real menu output captured from the Windows runner", "02 / 07"),
        ("CHOOSE A TARGET", "PenX checks an actual HTTP server listening on 127.0.0.1:8765", "03 / 07"),
        ("REAL SCAN DATA", "HTTP 200 and response headers recorded by PenX", "04 / 07"),
        ("SCRIPTED AI REVIEW", "Deterministic local API fixture — NOT a real language model", "05 / 07"),
        ("HTML + PDF REPORTS", "Real session saved to SQLite; reports generated by PenX", "06 / 07"),
        ("REAL PDF EXPORT", "Page one of the PDF actually produced by PenX", "07 / 07"),
    ]
    title, subtitle, label = names[scene]
    im, d = base(title, subtitle, label)
    if scene == 0:
        d.text((85, 224), "127.0.0.1:8765", font=font(43, True), fill=PALE)
        d.text((85, 304), "PenX -> HTTP HEAD -> response headers", font=font(26), fill=GREEN)
        d.text((85, 359), "-> scripted review -> SQLite -> HTML/PDF", font=font(26), fill=(196, 221, 233))
        d.text((85, 465), "HTTP request, database and reports: genuine.", font=font(21), fill=PALE)
        d.text((85, 506), "AI messages: predefined demonstration fixture.", font=font(21), fill=(244, 194, 108))
    elif scene == 1:
        # Original application banner/menu extracted from captured output.
        terminal(im, d, excerpt(transcript, "PenX |", "penx>") + "\npenx> 1",
                 label="PenX terminal — captured startup", max_rows=18)
    elif scene == 2:
        terminal(im, d,
                 excerpt(transcript, "NEW SCAN", "AI ANALYSIS"),
                 label="PenX -> New Scan -> HTTP headers selection", max_rows=17)
    elif scene == 3:
        terminal(im, d, raw_scan,
                 label="Unmodified raw_scan field saved in PenX SQLite", max_rows=17)
    elif scene == 4:
        terminal(im, d,
                 excerpt(transcript, "AI ANALYSIS", "SAVING TO DATABASE"),
                 label="Real PenX processing / model responses supplied by scripted fixture",
                 max_rows=17)
    elif scene == 5:
        terminal(im, d,
                 excerpt(transcript, "SAVING TO DATABASE", "Press Enter to continue"),
                 label="Actual PenX database commit and automatic report output",
                 max_rows=17)
    elif scene == 6:
        # Actual PenX PDF page shown, not a mockup.
        available_w, available_h = 980, 470
        ratio = min(available_w / document.width, available_h / document.height)
        rendered = document.resize((int(document.width * ratio),
                                    int(document.height * ratio)),
                                   Image.Resampling.LANCZOS)
        dest = (WIDTH-rendered.width)//2, 172
        im.paste(rendered, dest)
        d.rectangle((dest[0]-2, dest[1]-2, dest[0]+rendered.width+2,
                     dest[1]+rendered.height+2), outline=GREEN, width=2)
    return im


def render_video(transcript, raw_scan, analysis, pdf_file):
    document = pdf_page(pdf_file)
    file = OUTPUT / "PenX-Localhost-Workflow-Real-Scan.mp4"
    durations = [4, 5, 6, 6, 6, 6, 6]
    total = sum(durations)
    command = [get_ffmpeg_exe(), "-y", "-hide_banner", "-loglevel", "error",
               "-f", "rawvideo", "-pix_fmt", "rgb24",
               "-s", f"{WIDTH}x{HEIGHT}", "-r", str(FPS), "-i", "-",
               "-c:v", "libx264", "-preset", "veryfast", "-crf", "24",
               "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(file)]
    ffmpeg = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE)
    assert ffmpeg.stdin is not None
    still = None
    elapsed = 0
    for scene, duration in enumerate(durations):
        for index in range(duration*FPS):
            image = frame(scene, index/(duration*FPS), elapsed + index/FPS,
                          transcript, raw_scan, analysis, document)
            if scene == 3 and index == 12:
                still = image.copy()
            ffmpeg.stdin.write(image.tobytes())
        elapsed += duration
    ffmpeg.stdin.close()
    err = ffmpeg.stderr.read().decode("utf-8", "replace")
    result = ffmpeg.wait()
    if result != 0 or not file.is_file() or file.stat().st_size < 10000:
        raise RuntimeError(f"Video encoder failed {result}: {err[-1500:]}")
    if still:
        still.save(OUTPUT / "PenX-Localhost-Video-Preview.png")
    print(f"Recorded {total}s / {WIDTH}x{HEIGHT}: {file} ({file.stat().st_size} bytes)")


if __name__ == "__main__":
    recorded_text, evidence, judgement, pdf = capture_workflow()
    render_video(recorded_text, evidence, judgement, pdf)
