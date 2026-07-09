"""`--uninstall` CLI switch E2E (server VM only — full teardown assertion).

`vpn-ui --uninstall --yes` reverses everything the panel installs: it stops and
removes the systemd unit `vpn-ui.service`, kills the VPN daemons
(openvpn/xl2tpd/pptpd/pluto), deletes the nft table `ip vpn`, removes the /etc
configs, the bundle trees under /usr/libexec/vpn-ui, the fwmark-1/table-100
policy routing, logs, the sibling `bin/` dir, the DB, and finally the binary file
itself. It deliberately KEEPS distro packages (libreswan/nftables/iproute2 +
kernel modules) — printing them as "remove manually" — and cannot reverse the
GRUB boot-default pin / modprobe un-blacklist edits (also flagged in stdout).
`--yes` skips the interactive confirm.

Runs LAST, after systemd: at entry the panel is live under the installed
`vpn-ui.service` unit. This phase asserts the install is present, runs the
uninstall, then asserts the host is left clean.
"""
from __future__ import annotations

from . import provision
from .incus import Incus
from .model import (SubTest, Status, PHASE_UNINSTALL, PHASE_SYSTEMD,
                    PHASE_SETUP, PHASE_BULK, PHASE_BACKUP,
                    PHASE_OPENVPN, PHASE_L2TP, PHASE_PPTP)
from .panel import Panel

# Reuse the server-side binary path the core-init/systemd phases push to.
UNIT_FILE = "/etc/systemd/system/vpn-ui.service"
LIBEXEC = "/usr/libexec/vpn-ui"
BIN_DIR = provision.REMOTE_DIR + "/bin"
DB_FILE = provision.REMOTE_DIR + "/vpn-ui.db"
ETC_CONFIGS = [
    "/etc/vpn-ui",
    "/etc/sysctl.d/99-vpn-ui.conf",
    "/etc/modules-load.d/vpn-ui.conf",
    "/etc/xl2tpd/xl2tpd.conf",
]
DAEMONS = ["openvpn", "xl2tpd", "pptpd", "pluto"]


def run(incus: Incus, vm: str, panel: Panel, cfg: dict, result, log=None) -> None:
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_UNINSTALL)
    port = cfg["panel"]["port"]
    log(":: uninstall — `vpn-ui --uninstall --yes` tears everything down + assert clean host")

    def sub(name, status, detail, logtxt=""):
        st = SubTest(name, status, detail, logtxt)
        phase.add(st)
        log(f"-> {name} [{st.status.value}] {detail}")
        return st

    def _ex(cmd, timeout=30):
        """incus.exec wrapper that never raises, so one bad check can't abort
        the driver. Returns (rc, out, err)."""
        try:
            return incus.exec(vm, cmd, timeout=timeout, check=False)
        except Exception as e:  # noqa: BLE001
            return 1, "", str(e)[:300]

    # warp-cli only installs on apt distros (see warp_test); elsewhere its
    # post-uninstall absence check is NA rather than a real FAIL.
    rc, _, _ = _ex("command -v apt-get")
    apt_based = rc == 0

    # --- 1) sanity: the install is actually present before we tear it down.
    #     Which artifacts exist depends on which phases the --tests selection
    #     actually ran — the orchestrator uses dependency-aware substrate: the
    #     panel (port) comes from core-init and is always up; server-setup (and so
    #     the nft `ip vpn` table + /etc/vpn-ui it creates) runs only for
    #     protocol/bulk/backup selections; the /usr/libexec/vpn-ui bundle is only
    #     extracted once a protocol daemon runs; the vpn-ui.service unit only
    #     exists if the systemd phase ran. Mirror those conditions so a narrow
    #     selection (e.g. `--tests uninstall`, panel-only) doesn't spuriously FAIL
    #     on artifacts that were never installed. The default full run selects
    #     everything, so all checks apply. ---
    sel = cfg.get("_selected")  # None => no --tests filter (all phases)

    def _ran(p):
        return sel is None or p in sel

    protos = (PHASE_OPENVPN, PHASE_L2TP, PHASE_PPTP)
    setup_ran = (any(_ran(p) for p in protos) or _ran(PHASE_SETUP)
                 or _ran(PHASE_BULK) or _ran(PHASE_BACKUP))
    checks = [(f"ss -ltn | grep -q ':{port} '", f"panel :{port}")]  # core-init (always)
    if setup_ran:
        checks.append(("test -e /etc/vpn-ui", "/etc/vpn-ui"))
        checks.append(("nft list table ip vpn", "nft table ip vpn"))
    if _ran(PHASE_SYSTEMD):
        checks.insert(0, (f"test -f {UNIT_FILE}", "vpn-ui.service"))
    if any(_ran(p) for p in protos):
        checks.append((f"test -d {LIBEXEC}", LIBEXEC))  # bundle extracted by a running daemon
    present, miss = [], []
    for cmd, label in checks:
        rc, _, _ = _ex(cmd)
        (present if rc == 0 else miss).append(label)
    sub("install-present",
        Status.PASS if not miss else Status.FAIL,
        "install artifacts present" if not miss
        else f"missing before uninstall: {', '.join(miss)}",
        "present: " + ", ".join(present)
        + ("\nMISSING: " + ", ".join(miss) if miss else ""))

    # --- 2) run the uninstall (root exec; --yes skips the interactive confirm) --
    rc, out, err = _ex(f"{provision.REMOTE_BIN} --uninstall --yes", timeout=360)
    combined = (out or "") + ("\n" + err if err else "")
    sub("uninstall-run",
        Status.PASS if rc == 0 else Status.FAIL,
        f"`--uninstall --yes` exit={rc}", combined[-2000:])
    # NB: even on rc!=0 we still run every removal assert below — the switch may
    # have completed most of the teardown before erroring.

    # --- 3) assert the host is clean ---
    # systemd unit removed + inactive + panel port no longer served.
    rc_unit, _, _ = _ex(f"test -f {UNIT_FILE}")
    rc_act, _, _ = _ex("systemctl is-active --quiet vpn-ui")
    rc_port, _, _ = _ex(f"ss -ltn | grep -q ':{port} '")
    unit_gone = rc_unit != 0 and rc_act != 0 and rc_port != 0
    sub("systemd-removed", Status.PASS if unit_gone else Status.FAIL,
        f"unit-file={'gone' if rc_unit != 0 else 'PRESENT'}, "
        f"is-active={'no' if rc_act != 0 else 'YES'}, "
        f"port :{port}={'free' if rc_port != 0 else 'LISTENING'}")

    # nft table `ip vpn` removed (the command must now FAIL).
    rc_nft, _, nft_err = _ex("nft list table ip vpn")
    sub("nft-table-removed", Status.PASS if rc_nft != 0 else Status.FAIL,
        "table ip vpn gone" if rc_nft != 0 else "table ip vpn STILL PRESENT",
        nft_err)

    # /etc configs + per-server openvpn dirs removed.
    still = []
    for p in ETC_CONFIGS:
        rc, _, _ = _ex(f"test -e {p}")
        if rc == 0:
            still.append(p)
    _, ov, _ = _ex("ls -d /etc/openvpn/server-* 2>/dev/null")
    ov = (ov or "").strip()
    if ov:
        still.append("/etc/openvpn/server-*")
    sub("etc-configs-removed", Status.PASS if not still else Status.FAIL,
        "all /etc configs removed" if not still
        else f"still present: {', '.join(still)}", ov)

    # bundle trees under /usr/libexec/vpn-ui removed.
    rc, _, _ = _ex(f"test -d {LIBEXEC}")
    sub("libexec-removed", Status.PASS if rc != 0 else Status.FAIL,
        f"{LIBEXEC} gone" if rc != 0 else f"{LIBEXEC} STILL PRESENT")

    # policy routing: no fwmark-1 -> table 100 rule, and table 100 is empty.
    _, rule_out, _ = _ex("ip rule")
    has_rule = "fwmark 0x1 lookup 100" in (rule_out or "")
    _, route_out, _ = _ex("ip route show table 100")
    route_out = (route_out or "").strip()
    routing_gone = (not has_rule) and route_out == ""
    sub("policy-routing-removed", Status.PASS if routing_gone else Status.FAIL,
        "fwmark rule + table 100 gone" if routing_gone
        else f"rule={'present' if has_rule else 'gone'}, "
             f"table100={'non-empty' if route_out else 'empty'}",
        (rule_out or "") + "\n== table 100 ==\n" + route_out)

    # VPN daemons no longer running.
    alive = []
    for d in DAEMONS:
        rc, _, _ = _ex(f"pgrep -x {d}")
        if rc == 0:
            alive.append(d)
    sub("daemons-stopped", Status.PASS if not alive else Status.FAIL,
        "no vpn daemons running" if not alive
        else f"still running: {', '.join(alive)}")

    # sibling bin/ dir + DB file removed.
    rc_bin, _, _ = _ex(f"test -d {BIN_DIR}")
    rc_db, _, _ = _ex(f"test -f {DB_FILE}")
    bin_db_gone = rc_bin != 0 and rc_db != 0
    sub("bin-db-removed", Status.PASS if bin_db_gone else Status.FAIL,
        f"bin/={'gone' if rc_bin != 0 else 'PRESENT'}, "
        f"db={'gone' if rc_db != 0 else 'PRESENT'}")

    # the binary file itself removed.
    rc, _, _ = _ex(f"test -f {provision.REMOTE_BIN}")
    sub("binary-removed", Status.PASS if rc != 0 else Status.FAIL,
        f"{provision.REMOTE_BIN} {'gone' if rc != 0 else 'STILL PRESENT'}")

    # warp-cli absent at the end (apt = must be gone; non-apt = NA). It may have
    # already been removed by the earlier warp phase — either way the goal is
    # simply that warp-cli is absent now.
    rc, _, _ = _ex("command -v warp-cli")
    warp_absent = rc != 0
    if apt_based:
        sub("warp-cli-absent", Status.PASS if warp_absent else Status.FAIL,
            "warp-cli absent" if warp_absent else "warp-cli STILL PRESENT")
    else:
        sub("warp-cli-absent", Status.NA, "non-apt distro — warp-cli not managed here")

    # --- 4) soft: uninstall stdout flags the packages it deliberately kept /
    #         the GRUB pin it can't reverse. Informational — never a hard fail. ---
    low = combined.lower()
    noted = any(t in low for t in
                ("remove manually", "libreswan", "nftables", "iproute2", "grub"))
    sub("kept-packages-noted", Status.PASS if noted else Status.NA,
        "stdout flags kept packages / GRUB" if noted
        else "no kept-package note found (informational)", combined[-1500:])
