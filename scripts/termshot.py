#!/usr/bin/env python3
"""Render captured terminal output as a self-contained dark SVG.

Screenshots of a terminal are the wrong artefact for a repository. They are
raster, so they blur on a high-density display and again when GitHub scales
them; they carry whatever font and colour scheme the machine happened to have;
and they cannot be diffed, so a stale one survives indefinitely. An SVG built
from the captured text has none of those problems: it is sharp at any zoom, the
text is selectable and searchable, it is a few kilobytes, and regenerating it
after a change is one command.

Colour is applied by rule rather than by an ANSI capture, because these commands
deliberately emit no escape codes: their output is piped into files and read by
other programs as often as it is read by a person.

Usage:
    python scripts/termshot.py <input.txt> <output.svg> "<title>"
"""

from __future__ import annotations

import html
import re
import sys

# The palette is the one the published evidence page uses, so a reader moving
# between the two is not asked to relearn what a colour means.
BG = "#0a0e1a"
PANEL = "#111725"
BORDER = "#1e2942"
FG = "#c8d3e8"
DIM = "#6b7a99"
ACCENT = "#5b8cff"
GOOD = "#3fb984"
WARN = "#e8b04b"
BAD = "#e05a5a"
HEAD = "#ffffff"

CHAR_W = 8.05
LINE_H = 20.0
PAD_X = 26
PAD_TOP = 62
PAD_BOTTOM = 22

# Rules are checked in order and the first match wins.
RULES: list[tuple[re.Pattern[str], str, bool]] = [
    (re.compile(r"\bSURVIVED\b"), GOOD, True),
    (re.compile(r"\brefuted\b"), DIM, False),
    (re.compile(r"\bOUTSIDE the interval\b"), BAD, True),
    (re.compile(r"\binside the interval\b"), GOOD, False),
    (re.compile(r"^\s*(the answer key|Found\.|not measured)"), ACCENT, True),
    (re.compile(r"real miscalibration"), WARN, False),
    (re.compile(r"nothing to correct"), GOOD, False),
    (re.compile(r"^\s{2}note:"), DIM, False),
    (re.compile(r"^\s{4}(TERMINAL_DECLINE|DELAY_EXCEEDS_ACTION_SPACE)"), WARN, False),
    (re.compile(r"^\S.*\S$"), HEAD, True),        # a flush-left line is a section
    (re.compile(r"^  \S"), ACCENT, False),        # two-space indent is a subheading
]


def style_for(line: str) -> tuple[str, bool]:
    for pattern, colour, bold in RULES:
        if pattern.search(line):
            return colour, bold
    return FG, False


def render(lines: list[str], title: str) -> str:
    width = max([len(line) for line in lines] + [len(title) + 12])
    px_w = int(PAD_X * 2 + width * CHAR_W)
    px_h = int(PAD_TOP + len(lines) * LINE_H + PAD_BOTTOM)

    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{px_w}" height="{px_h}" '
        f'viewBox="0 0 {px_w} {px_h}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">',
        f'<rect width="{px_w}" height="{px_h}" rx="10" fill="{BG}"/>',
        f'<rect x="0.5" y="0.5" width="{px_w-1}" height="{px_h-1}" rx="10" fill="none" stroke="{BORDER}"/>',
        f'<rect x="1" y="1" width="{px_w-2}" height="38" rx="9" fill="{PANEL}"/>',
        f'<rect x="1" y="30" width="{px_w-2}" height="10" fill="{PANEL}"/>',
        f'<line x1="1" y1="39.5" x2="{px_w-1}" y2="39.5" stroke="{BORDER}"/>',
    ]
    for i, colour in enumerate((BAD, WARN, GOOD)):
        out.append(f'<circle cx="{22 + i*17}" cy="20" r="5" fill="{colour}" opacity="0.55"/>')
    out.append(
        f'<text x="{px_w/2}" y="25" fill="{DIM}" font-size="12.5" text-anchor="middle">'
        f"{html.escape(title)}</text>"
    )

    y = PAD_TOP
    for line in lines:
        if line.strip():
            colour, bold = style_for(line)
            weight = ' font-weight="600"' if bold else ""
            out.append(
                f'<text x="{PAD_X}" y="{y:.1f}" fill="{colour}" font-size="13"'
                f'{weight} xml:space="preserve">{html.escape(line)}</text>'
            )
        y += LINE_H

    out.append("</svg>")
    return "\n".join(out)


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst, title = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(src, encoding="utf-8") as fh:
        lines = [line.rstrip("\n").rstrip() for line in fh]
    while lines and not lines[-1]:
        lines.pop()
    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(lines, title))
    print(f"{dst}: {len(lines)} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
