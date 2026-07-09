"""Global cooperative-abort flag, set on Ctrl+C (SIGINT).

Long-running polling loops (VM boot wait, provisioning poll, panel wait) and the
per-job phase boundaries check `is_set()` and bail, so an interrupted run unwinds
promptly and each job reaches its `finally` teardown (delete VMs + bridge).
Teardown itself never checks this flag, so cleanup always completes.
"""
from __future__ import annotations

import threading

_event = threading.Event()


def set():          # noqa: A001 - deliberate simple verb name
    _event.set()


def is_set() -> bool:
    return _event.is_set()


def clear():
    _event.clear()
