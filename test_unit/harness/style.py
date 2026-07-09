"""Pacman-style terminal coloring for the live logs.

Callsites emit plain messages with light markers; the logger runs them through
stylize() for the terminal and strips ANSI for the log file. Markers:
  "::"  leading  -> bold-blue pacman header  (:: like `:: Synchronizing...`)
  "->"  leading  -> blue action arrow (optionally indented)
  "[pass]" / "[ok]" / "[fail]" / "[error]" / "[warn]" / "[na]" / "[skip]"
                 -> colored status chips, anywhere in the line
Respects NO_COLOR / FORCE_COLOR and only colors a real TTY.
"""
from __future__ import annotations

import os
import re
import sys

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return sys.stdout.isatty()
    except (ValueError, AttributeError):
        return False


ENABLED = _enabled()


def _w(code: str, s: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if ENABLED else s


def bold(s):      return _w("1", s)
def dim(s):       return _w("2", s)
def red(s):       return _w("38;5;203", s)
def green(s):     return _w("38;5;114", s)
def yellow(s):    return _w("38;5;221", s)
def blue(s):      return _w("38;5;39", s)
def cyan(s):      return _w("38;5;44", s)
def magenta(s):   return _w("38;5;176", s)
def bold_blue(s): return _w("1;38;5;39", s)
def bold_white(s):return _w("1;38;5;255", s)


def strip(s: str) -> str:
    return _ANSI_RE.sub("", s)


# stable per-distro tag color, so parallel jobs are visually distinct
_PALETTE = ["38;5;39", "38;5;114", "38;5;221", "38;5;176", "38;5;44",
            "38;5;209", "38;5;147", "38;5;112", "38;5;180", "38;5;75",
            "38;5;168", "38;5;79", "38;5;215", "38;5;141", "38;5;107"]


def distro_tag(name: str, width: int = 10) -> str:
    idx = sum(ord(c) for c in name) % len(_PALETTE)
    return _w("1;" + _PALETTE[idx], name.ljust(width))


# per-phase tag color for the live log (matches the phase a line belongs to)
_PHASE_COLORS = {
    "CORE":    "38;5;39",
    "SETUP":   "38;5;176",
    "PREP":    "38;5;44",
    "OPENVPN": "38;5;114",
    "L2TP":    "38;5;221",
    "PPTP":    "38;5;209",
    "VM":      "38;5;245",
}


def phase_tag(label: str) -> str:
    """Colored `[PHASE]` chip (tight — one space each side at the call site)."""
    code = _PHASE_COLORS.get(label, "38;5;250")
    return _w("1;" + code, f"[{label}]")


_STATUS = {
    "[pass]":  ("38;5;114", "✓ pass"),
    "[ok]":    ("38;5;114", "✓ ok"),
    "[fail]":  ("38;5;203", "✗ fail"),
    "[error]": ("38;5;203", "✗ error"),
    "[warn]":  ("38;5;221", "! warn"),
    "[na]":    ("38;5;44",  "• n/a"),
    "[skip]":  ("2",        "• skip"),
}


def status_chip(status: str) -> str:
    """Colored chip for a Status value string (pass/fail/error/na/skip)."""
    tok = f"[{status}]"
    if tok in _STATUS:
        code, label = _STATUS[tok]
        return _w(code, f"[{label}]")
    return tok


def stylize(msg: str) -> str:
    if msg.startswith("::"):
        return f"{bold_blue('::')} {bold_white(msg[2:].strip())}"
    stripped = msg.lstrip()
    if stripped.startswith("->"):
        indent = msg[:len(msg) - len(stripped)]
        msg = f"{indent}{blue('->')} {stripped[2:].strip()}"
    for token, (code, label) in _STATUS.items():
        if token in msg:
            msg = msg.replace(token, _w(code, f"[{label}]"))
    return msg
