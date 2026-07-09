"""`--random` CLI switch E2E (server VM only — no tunnels).

`vpn-ui --random` generates a fresh random panel port, login username, login
password and web base path, persists them to the DB, and prints them. This phase
runs it on the server VM, parses the printed values, restarts the panel, and
asserts the panel now answers on the NEW port + web path with the NEW credentials
(and no longer on the old port). It then restores the harness defaults (port
2083, admin/admin, "/") via the `setting` CLI so later phases — notably
`--systemd`, which reuses the shared panel object at :2083 — keep working.

Runs after warp, before systemd.
"""
from __future__ import annotations

import re

from . import provision
from .incus import Incus
from .model import SubTest, Status, PHASE_RANDOM
from .panel import Panel

_RE = {
    "port": re.compile(r"Port:\s*(\d+)"),
    "username": re.compile(r"Username:\s*(\S+)"),
    "password": re.compile(r"Password:\s*(\S+)"),
    "webpath": re.compile(r"WebPath:\s*(\S+)"),
}


def _parse(out: str) -> dict:
    vals = {}
    for k, rx in _RE.items():
        m = rx.search(out or "")
        if m:
            vals[k] = m.group(1)
    return vals


def run(incus: Incus, vm: str, panel: Panel, cfg: dict, result, log=None) -> None:
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_RANDOM)
    log(":: random — `vpn-ui --random` randomizes port + username + password + web path")

    def sub(name, ok, detail, logtxt=""):
        st = SubTest(name, Status.PASS if ok else Status.FAIL, detail, logtxt)
        phase.add(st)
        log(f"-> {name} [{st.status.value}] {detail}")
        return ok

    ptimeout = cfg["vm"]["panel_timeout"]

    # Harness defaults, restored at the end so downstream phases keep working.
    orig_port, orig_user, orig_pass, orig_bp = (
        panel.port, panel.username, panel.password, panel._bp)

    def restart_and_recover():
        """Best-effort: restart the panel under the ORIGINAL settings."""
        incus.exec(vm, f"systemctl stop {provision.PANEL_UNIT} 2>/dev/null; true", check=False)
        incus.exec(vm, f"{provision.REMOTE_BIN} setting -port {orig_port} "
                       f"-username {orig_user} -password {orig_pass} "
                       f"-webBasePath {orig_bp}", check=False)
        provision.start_panel(incus, vm)

    # 1) Stop the panel so the CLI writes settings without contending on the DB.
    incus.exec(vm, f"systemctl stop {provision.PANEL_UNIT} 2>/dev/null; true", check=False)

    # 2) Run the switch and capture what it generated.
    rc, out, err = incus.exec(vm, f"{provision.REMOTE_BIN} --random", check=False)
    if not sub("random-cli", rc == 0, f"`--random` exit={rc}",
               (out or "") + "\n" + (err or "")):
        restart_and_recover()
        return

    vals = _parse(out)
    if not sub("random-parsed",
               all(k in vals for k in ("port", "username", "password", "webpath")),
               f"parsed keys {sorted(vals)}", out):
        restart_and_recover()
        return

    new_port = int(vals["port"])
    new_user, new_pass, new_bp = vals["username"], vals["password"], vals["webpath"]

    # 3) Generated values must actually differ from the defaults (i.e. be random).
    changed = (new_port != orig_port
               and new_user != orig_user
               and new_bp.rstrip("/") not in ("", orig_bp.rstrip("/")))
    sub("random-differs", changed,
        f"port {orig_port}->{new_port}, user {orig_user!r}->{new_user!r}, "
        f"path {orig_bp!r}->{new_bp!r}")

    # 4) Restart the panel; it must now bind the new port + serve the new web path
    #    and accept the new credentials.
    provision.start_panel(incus, vm)
    newp = Panel(panel.host, new_port, new_bp, panel.scheme, new_user, new_pass,
                 timeout=panel.timeout)
    try:
        newp.wait_up(ptimeout)
        newp.login()
        sub("random-applied", True, f"panel reachable + login at {newp.root}")
    except Exception as e:  # noqa: BLE001
        _, jlog, _ = incus.exec(
            vm, f"journalctl -u {provision.PANEL_UNIT} --no-pager | tail -n 60", check=False)
        sub("random-applied", False, str(e)[:200], jlog)

    # 5) The old port no longer serves the panel (the port genuinely moved).
    oldp = Panel(panel.host, orig_port, orig_bp, panel.scheme, orig_user, orig_pass, timeout=5)
    old_dead = False
    try:
        oldp.wait_up(6)
    except Exception:  # noqa: BLE001
        old_dead = True
    sub("old-port-dead", old_dead, f"old port {orig_port} unreachable after randomize")

    # 6) Restore harness defaults so `--systemd` (and any later phase) still works.
    incus.exec(vm, f"systemctl stop {provision.PANEL_UNIT} 2>/dev/null; true", check=False)
    rc, rout, rerr = incus.exec(
        vm, f"{provision.REMOTE_BIN} setting -port {orig_port} "
            f"-username {orig_user} -password {orig_pass} -webBasePath {orig_bp}", check=False)
    provision.start_panel(incus, vm)
    try:
        panel.wait_up(ptimeout)
        panel.login()
        sub("restored-defaults", rc == 0,
            f"defaults restored (port {orig_port}, user {orig_user!r})",
            (rout or "") + (rerr or ""))
    except Exception as e:  # noqa: BLE001
        sub("restored-defaults", False, str(e)[:200], (rout or "") + (rerr or ""))
