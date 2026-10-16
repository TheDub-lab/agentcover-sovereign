#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""Render the prompt-injection demo into an animated GIF for the write-up.

It runs ``examples/mcp_injection_demo.py`` for real, captures the transcript,
and paints it into a scrolling terminal-window GIF (no screen recorder needed).

    pip install Pillow
    python examples/make_injection_gif.py

Output: ``docs/img/mcp-injection-demo.gif``.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "docs", "img", "mcp-injection-demo.gif")

WIDTH_CHARS = 92
FONT_SIZE = 16
LINE_H = FONT_SIZE + 6
PAD = 18
TITLEBAR = 34
VIEW_ROWS = 33
FRAME_MS = 70
HOLD_MS = 900

BG = (13, 17, 23)
BG2 = (22, 27, 34)
FG = (201, 209, 217)
GRAY = (110, 118, 129)
GREEN = (126, 231, 135)
RED = (255, 123, 114)
YELLOW = (210, 168, 92)
CYAN = (121, 192, 255)
WHITE = (240, 246, 252)


def load_font():
    for c in (r"C:\Windows\Fonts\consola.ttf",
              r"C:\Windows\Fonts\CascadiaMono.ttf",
              r"C:\Windows\Fonts\lucon.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
              "/System/Library/Fonts/Menlo.ttc"):
        if os.path.exists(c):
            return ImageFont.truetype(c, FONT_SIZE)
    return ImageFont.load_default()


def run_demo() -> str:
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "mcp_injection_demo.py")],
        capture_output=True, text=True, encoding="utf-8",
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"demo exited {proc.returncode}")
    return proc.stdout


def normalize(text: str) -> list[str]:
    raw = text.replace("\r", "").split("\n")
    root = None
    for ln in raw:
        if ln.startswith("workspace: "):
            root = ln.split("workspace: ", 1)[1].strip()
    out: list[str] = []
    for ln in raw:
        s = ln.rstrip()
        if s.startswith("workspace: ") or s.startswith("server   : "):
            continue
        if root:
            s = s.replace(root, "<root>")
        st = s.strip()
        if st.startswith('{"seq"'):
            try:
                o = json.loads(st)
                s = (f"#{o['seq']} {str(o['decision']):8} "
                     f"{str(o['target']):12} rule={o.get('rule_id') or '-'}")
            except (json.JSONDecodeError, KeyError):
                pass
        out.append(s)
    # collapse runs of blank lines to one
    collapsed: list[str] = []
    for s in out:
        if s.strip() == "" and collapsed and collapsed[-1].strip() == "":
            continue
        collapsed.append(s)
    return collapsed


def color_for(line: str):
    if "BLOCKED" in line or " denied" in line:
        return RED
    if "ALLOWED" in line or "SUCCEEDED" in line or " allowed" in line:
        return GREEN
    stripped = line.strip()
    if stripped.startswith("="):
        return GRAY
    if stripped.startswith("#") and " rule=" in stripped:
        return CYAN
    if stripped.startswith("-> "):
        return FG
    low = line.lower()
    if "without the guard" in low:
        return YELLOW
    if "with the guard" in low:
        return CYAN
    if "leaked secret" in low or "exfil file" in low or "injection" in low:
        return YELLOW
    if "agent:" in line:
        return WHITE
    return FG


def wrap(lines: list[str]) -> list[str]:
    out: list[str] = []
    for ln in lines:
        if ln.strip() == "":
            out.append("")
            continue
        parts = textwrap.wrap(ln, WIDTH_CHARS,
                              subsequent_indent=" " * 4,
                              break_long_words=True, break_on_hyphens=False)
        out.extend(parts or [""])
    return out


def main() -> int:
    print("running examples/mcp_injection_demo.py ...")
    lines = wrap(normalize(run_demo()))

    font = load_font()
    char_w = max(6, int(font.getlength("M")))
    width = PAD * 2 + char_w * WIDTH_CHARS
    height = TITLEBAR + PAD * 2 + LINE_H * VIEW_ROWS

    def draw_frame(shown: list[str], cursor: bool) -> Image.Image:
        img = Image.new("RGB", (width, height), BG)
        d = ImageDraw.Draw(img)
        # title bar
        d.rectangle([0, 0, width, TITLEBAR], fill=BG2)
        for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            cx = 16 + i * 20
            d.ellipse([cx - 6, TITLEBAR // 2 - 6, cx + 6, TITLEBAR // 2 + 6], fill=c)
        title = "safety-guard  mcp-proxy  -  prompt injection demo"
        d.text((78, TITLEBAR // 2 - FONT_SIZE // 2 - 1), title, font=font, fill=GRAY)

        visible = shown[-VIEW_ROWS:]
        y = TITLEBAR + PAD
        for i, ln in enumerate(visible):
            d.text((PAD, y), ln, font=font, fill=color_for(ln))
            y += LINE_H
        if cursor:
            cy = TITLEBAR + PAD + (len(visible) - 1) * LINE_H
            last = visible[-1] if visible else ""
            cx = PAD + min(len(last), WIDTH_CHARS) * char_w
            d.rectangle([cx + 1, cy + 2, cx + char_w, cy + LINE_H - 3],
                        fill=FG)
        return img

    frames: list[Image.Image] = []
    durations: list[int] = []
    for i in range(1, len(lines) + 1):
        shown = lines[:i]
        frames.append(draw_frame(shown, cursor=True).quantize(colors=64))
        last = lines[i - 1].strip()
        if last.startswith("=") or (last and set(last) == {"="}):
            durations.append(HOLD_MS)
        elif last == "":
            durations.append(FRAME_MS * 3)
        else:
            durations.append(FRAME_MS)
    # final hold without a cursor
    frames.append(draw_frame(lines, cursor=False).quantize(colors=64))
    durations.append(2500)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    frames[0].save(OUT, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True, disposal=2)
    size_mb = os.path.getsize(OUT) / 1e6
    print(f"wrote {OUT}  ({len(frames)} frames, {size_mb:.1f} MB, "
          f"{width}x{height})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
