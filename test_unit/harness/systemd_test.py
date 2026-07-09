"""`--systemd` CLI switch E2E (server VM only — no tunnels).

`vpn-ui --systemd` must install + enable-at-boot + start the panel as a systemd
unit named `vpn-ui` (/etc/systemd/system/vpn-ui.service) and then exit
(main.go installSystemd -> return). This phase runs it on the server VM and
asserts, via systemctl, that the unit was created, is enabled, and is active —
and that the panel actually answers under the new unit.

Runs LAST: it swaps the panel's supervisor. The harness normally runs the panel
as the transient unit `vpn-ui-panel`, which binds :2083; that unit is stopped
first, otherwise the new `vpn-ui` unit would fight for the busy port and read as
`activating` (Restart=on-failure) rather than `active`.
"""
from __future__ import annotations

from . import provision
from .incus import Incus
from .model import SubTest, Status, PHASE_SYSTEMD
from .panel import Panel

SERVICE = "vpn-ui"
UNIT_FILE = f"/etc/systemd/system/{SERVICE}.service"


def run(incus: Incus, vm: str, panel: Panel, cfg: dict, result, log=None) -> None:
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_SYSTEMD)
    log(f":: systemd — `vpn-ui --systemd` installs + enables + starts unit {SERVICE!r}")

    def sub(name, ok, detail, logtxt=""):
        st = SubTest(name, Status.PASS if ok else Status.FAIL, detail, logtxt)
        phase.add(st)
        log(f"-> {name} [{st.status.value}] {detail}")
        return ok

    # 1) Free :2083 — stop the transient harness unit so the new unit can bind it.
    incus.exec(vm, f"systemctl stop {provision.PANEL_UNIT} 2>/dev/null; true", check=False)

    # 2) Run the CLI switch (VM exec is root, satisfying the write to /etc/systemd).
    rc, out, err = incus.exec(vm, f"{provision.REMOTE_BIN} --systemd", check=False)
    if not sub("systemd-cli", rc == 0, f"`--systemd` exit={rc}",
               (out or "") + "\n" + (err or "")):
        return  # installer failed; nothing downstream can pass

    # 3) Unit file created.
    rc, _, _ = incus.exec(vm, f"test -f {UNIT_FILE}", check=False)
    sub("unit-file", rc == 0, f"{UNIT_FILE} {'exists' if rc == 0 else 'MISSING'}")

    # 4) Enabled at boot.
    _, out, _ = incus.exec(vm, f"systemctl is-enabled {SERVICE}", check=False)
    en = (out or "").strip()
    sub("unit-enabled", en == "enabled", f"is-enabled={en!r}")

    # 5) Active now.
    _, out, _ = incus.exec(vm, f"systemctl is-active {SERVICE}", check=False)
    act = (out or "").strip()
    unit_active = act == "active"
    jlog = ""
    if not unit_active:
        _, jlog, _ = incus.exec(vm, f"journalctl -u {SERVICE} --no-pager | tail -n 50",
                                check=False)
    sub("unit-active", unit_active, f"is-active={act!r}", jlog)

    # 6) Panel answers under the new unit (fresh process -> re-login).
    try:
        panel.wait_up(cfg["vm"]["panel_timeout"])
        panel.login()
        sub("panel-up-under-systemd", True, f"panel reachable + login at {panel.root}")
    except Exception as e:  # noqa: BLE001
        _, jlog, _ = incus.exec(vm, f"journalctl -u {SERVICE} --no-pager | tail -n 80",
                                check=False)
        sub("panel-up-under-systemd", False, str(e)[:200], jlog)
