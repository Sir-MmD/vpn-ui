"""One-time preflight probes (run once at run start, shared by all jobs)."""
from __future__ import annotations

import socket


def vless_reachable(cfg: dict, timeout: int = 8) -> tuple[bool, str]:
    """TCP-connect to the external outbound node (address/port parsed from the
    share link). If it's down, the xray-route sub-test is marked N/A everywhere
    instead of falsely failing."""
    vo = cfg["vless_outbound"]
    host, port = vo["address"], int(vo["port"])
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"{host}:{port} reachable"
    except OSError as e:
        return False, f"{host}:{port} unreachable: {e}"
