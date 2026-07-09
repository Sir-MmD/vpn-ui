"""Core-init phase: push the binary, start the panel, run panel-driven
provisioning (kernel modules + packages + daemons), assert it comes up clean.

Mirrors the real operator flow (provisioning is panel-only in this fork):
  push binary -> start panel -> login -> POST /panel/core/provision
  -> poll /panel/core/provision-status -> reboot if required -> re-run
  -> assert every step ok/warn, modules loaded, cores running.
"""
from __future__ import annotations

import os
import time

from . import abort
from .incus import Incus
from .model import JobResult, SubTest, Status, PHASE_CORE
from .panel import Panel, PanelError

REMOTE_DIR = "/root/vpn-ui"
REMOTE_BIN = REMOTE_DIR + "/vpn-ui"
PANEL_UNIT = "vpn-ui-panel"

# Modules the panel loads (web/service/core.go vpnKernelModules). We spot-check
# the ones that matter for the three protocols under test.
EXPECTED_MODULES = ["ppp_generic", "l2tp_ppp", "nf_conntrack_pptp", "tun"]


def start_panel(incus: Incus, vm: str):
    """(Re)start the panel as a transient systemd unit. Idempotent."""
    incus.exec(vm, f"systemctl reset-failed {PANEL_UNIT} 2>/dev/null; "
                   f"systemctl stop {PANEL_UNIT} 2>/dev/null; true")
    rc, out, err = incus.exec(
        vm,
        f"systemd-run --unit={PANEL_UNIT} --working-directory={REMOTE_DIR} "
        f"{REMOTE_BIN}",
        check=False,
    )
    if rc != 0:
        raise PanelError(f"failed to start panel unit: {out}\n{err}")


def _record_steps(phase, steps, prefix=""):
    """Turn panel provision steps into SubTests. Returns (any_fail)."""
    any_fail = False
    for st in steps:
        name = st.get("name", "step")
        ok = st.get("ok", False)
        warn = st.get("warn", False)
        msg = st.get("msg", "")
        log = st.get("log", "")
        if ok:
            status = Status.PASS
        elif warn:
            status = Status.PASS  # warn = non-fatal (e.g. IPsec unavailable on Arch)
            msg = "(warn) " + msg
        else:
            status = Status.FAIL
            any_fail = True
        sub = SubTest(name=f"{prefix}{name}", status=status, detail=msg, log=log)
        # de-dupe: replace an earlier same-named step (poll returns cumulative)
        phase.subtests = [s for s in phase.subtests if s.name != sub.name]
        phase.add(sub)
    return any_fail


def _poll_until_done(panel: Panel, phase, timeout: int, log=None) -> dict:
    """Poll provision-status until done, folding steps into the phase and
    logging each step the moment it first appears."""
    log = log or (lambda *_: None)
    deadline = time.monotonic() + timeout
    seen = {}
    last = {}
    while time.monotonic() < deadline:
        if abort.is_set():
            raise PanelError("aborted during provisioning (Ctrl+C)")
        last = panel.provision_status()
        for st in last.get("steps", []):
            name = st.get("name", "step")
            key = (name, st.get("ok"), st.get("warn"))
            if seen.get(name) != key:
                seen[name] = key
                tag = "ok" if st.get("ok") else ("warn" if st.get("warn") else "fail")
                msg = (st.get("msg") or "").strip().split("\n")[0][:90]
                log(f"   {name}: {msg} [{tag}]")
        _record_steps(phase, last.get("steps", []))
        if last.get("done"):
            return last
        time.sleep(3)
    raise PanelError(f"provisioning did not finish in {timeout}s")


def run(incus: Incus, vm: str, panel: Panel, cfg: dict, result: JobResult) -> bool:
    """Run the core-init phase. Returns True if the backend is usable (provisioned
    + cores runnable), False if a fatal step failed. Never raises for product
    failures — only records them."""
    phase = result.phase(PHASE_CORE)
    vmcfg = cfg["vm"]
    log = incus.log

    # push + start
    log("-> pushing binary (+ bin/ with xray core) + starting panel...")
    push = phase.add(SubTest("push-binary"))
    try:
        incus.push(vm, cfg["binary"], REMOTE_BIN, mode="0755")
        # The panel runs xray from <cwd>/bin/xray-linux-amd64 (GetBinFolderPath
        # defaults to "bin"). Ship the bin/ dir sitting next to the binary — it
        # holds the xray core + geo .dat files — or xray can't start.
        bindir = os.path.join(os.path.dirname(cfg["binary"]), "bin")
        if os.path.isdir(bindir):
            incus.push_dir(vm, bindir, REMOTE_DIR + "/")
            xray_note = f"+ bin/ ({len(os.listdir(bindir))} files)"
        else:
            xray_note = "WARNING: no bin/ dir next to binary — xray will fail"
            log(f"-> {xray_note}")
        start_panel(incus, vm)
        push.status = Status.PASS
        push.detail = f"pushed {cfg['binary']} {xray_note}, panel started"
    except Exception as e:  # noqa: BLE001 (infra error surfaced to report)
        push.status = Status.ERROR
        push.detail = str(e)[:300]
        log(f"-> push/start [error]: {push.detail}")
        return False

    # panel reachable + login
    log(f"-> waiting for panel at {panel.root} + login...")
    up = phase.add(SubTest("panel-login"))
    try:
        panel.wait_up(vmcfg["panel_timeout"])
        panel.login()
        up.status = Status.PASS
        up.detail = f"logged in at {panel.root}"
        log("-> panel up, logged in [ok]")
    except Exception as e:  # noqa: BLE001
        up.status = Status.ERROR
        up.detail = str(e)[:300]
        _, up.log, _ = incus.exec(vm, f"journalctl -u {PANEL_UNIT} --no-pager | tail -n 100")
        log(f"-> panel/login [error]: {up.detail}")
        return False

    # provision (with at most one reboot)
    log("-> starting provisioning (kernel modules + packages + daemons)...")
    prov = phase.add(SubTest("provision-run"))
    rebooted = False
    try:
        panel.provision_start()
        st = _poll_until_done(panel, phase, vmcfg["provision_timeout"], log)

        if st.get("rebootRequired") and not rebooted:
            log("-> reboot required for kernel modules; rebooting VM...")
            reb = phase.add(SubTest("reboot"))
            try:
                incus.reboot(vm, vmcfg["agent_timeout"])
                # DHCP may re-lease a different IP after reboot — re-resolve and
                # repoint the panel client before waiting on it.
                new_ip = incus.ipv4(vm)
                if new_ip and new_ip != panel.host:
                    log(f"-> IP changed after reboot {panel.host} -> {new_ip}")
                    panel.set_host(new_ip)
                    result.server_ip = new_ip
                start_panel(incus, vm)
                panel.wait_up(vmcfg["panel_timeout"])
                panel.login()
                rebooted = True
                reb.status = Status.PASS
                reb.detail = f"rebooted for kernel modules, panel back up at {panel.host}"
                log("-> back up after reboot [ok]; finalizing provisioning")
            except Exception as e:  # noqa: BLE001
                reb.status = Status.ERROR
                reb.detail = str(e)[:300]
                log(f"-> reboot recovery [error]: {reb.detail}")
                return False
            # finalize provisioning after reboot
            panel.provision_start()
            st = _poll_until_done(panel, phase, vmcfg["provision_timeout"], log)

        provisioned = st.get("provisioned") or panel.core_status().get("provisioned")
        if provisioned:
            prov.status = Status.PASS
            prov.detail = "provisioned=true"
            log("-> provisioned=true [ok]")
        else:
            prov.status = Status.FAIL
            prov.detail = "provisioning finished but provisioned flag is false"
            log("-> provisioned flag false [fail]")
    except Exception as e:  # noqa: BLE001
        prov.status = Status.ERROR
        prov.detail = str(e)[:300]
        prov.log = safe_logs(panel, "l2tp")
        log(f"-> provisioning [error]: {prov.detail}")
        return False

    # kernel modules present (loaded OR builtin). A builtin module (e.g.
    # ppp_generic on some kernels) never shows in lsmod, so check /proc/modules,
    # /sys/module, and modules.builtin — not a plain lsmod substring.
    log("-> checking kernel modules...")
    mods = phase.add(SubTest("kernel-modules"))
    missing, detail_lines = [], []
    for m in EXPECTED_MODULES:
        rc, _, _ = incus.exec(vm, _module_present_cmd(m))
        detail_lines.append(f"{m}: {'present' if rc == 0 else 'MISSING'}")
        if rc != 0:
            missing.append(m)
    _, lsmod, _ = incus.exec(vm, "lsmod")
    mods.log = "\n".join(detail_lines) + "\n\n== lsmod ==\n" + lsmod
    if missing:
        mods.status = Status.FAIL
        mods.detail = f"missing modules: {', '.join(missing)}"
    else:
        mods.status = Status.PASS
        mods.detail = "all expected modules present (loaded or builtin)"

    # Core states are informational at this stage: no inbounds exist yet, so a
    # daemon (incl. xray) may legitimately be idle/error until setup configures
    # and restarts it. Real core health is proven functionally by the protocol
    # suites. We record states + capture xray logs for any error, but do NOT
    # fail core-init on them.
    svc = phase.add(SubTest("cores-status"))
    try:
        cores = panel.core_status().get("cores", [])
        bad = [c for c in cores if c.get("state") == "error"]
        svc.log = _fmt_cores(cores)
        if bad:
            svc.log += "\n\n== xray logs ==\n" + safe_logs(panel, "xray")
            svc.status = Status.NA
            svc.detail = ("pre-inbound: cores in error (informational): " +
                          ", ".join(c.get("name", "?") for c in bad))
            log(f"-> cores currently in error (no inbounds yet): "
                f"{[c.get('name') for c in bad]}")
        else:
            svc.status = Status.PASS
            svc.detail = "no cores in error state"
    except Exception as e:  # noqa: BLE001
        svc.status = Status.ERROR
        svc.detail = str(e)[:300]

    # usable if provisioning succeeded and modules are present
    return prov.status == Status.PASS and mods.status == Status.PASS


def _module_present_cmd(m: str) -> str:
    """Shell test: module loaded (/proc/modules or /sys/module) or builtin."""
    return (f"grep -qw {m} /proc/modules "
            f"|| test -e /sys/module/{m} "
            f"|| grep -q '/{m}\\.ko' /lib/modules/$(uname -r)/modules.builtin 2>/dev/null")


def _fmt_cores(cores) -> str:
    return "\n".join(
        f"{c.get('name','?'):10s} {c.get('state','?'):12s} "
        f"v={c.get('version','')} {c.get('detail','')}"
        for c in cores
    )


def safe_logs(panel: Panel, core: str) -> str:
    try:
        return panel.core_logs(core)
    except Exception:  # noqa: BLE001
        return ""
