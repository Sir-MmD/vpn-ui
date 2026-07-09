"""Cloudflare warp-cli SOCKS5 install E2E (server VM only — panel API driven).

The panel's "official WARP-CLI" SOCKS5 feature installs Cloudflare's warp-cli
non-interactively via the bundled warpcli.sh, registers, puts WARP into SOCKS5
proxy mode on a chosen port, and connects. This is exactly the path that broke
when driven FROM the panel yet worked over SSH: the panel runs the installer as
a supervised child with a minimal environment, and

  - unset HOME -> `gpg --dearmor` can't write its keyring -> the cloudflare repo
    stays unsigned -> `apt install cloudflare-warp` fails "Unable to locate package",
  - no TTY -> `warp-cli registration new` refuses the implicit ToS prompt.

warpcli.sh pins HOME/PATH and routes every warp-cli call through `--accept-tos`
to fix both. This phase drives the REAL panel API end-to-end (install -> poll the
live log -> uninstall) and asserts the install succeeds, warp-cli reports
Connected, and the SOCKS5 proxy actually egresses through WARP.

Distro scope: Cloudflare's warp-cli apt repo serves Debian/Ubuntu; Arch needs the
AUR (a non-root builder the panel child hasn't got) and RPM coverage is spotty.
So a failed install on a NON-apt distro is reported NA (not applicable here),
while on apt distros — the first-class, previously-broken path — it is a real FAIL.
"""
from __future__ import annotations

import time

from .incus import Incus
from .model import SubTest, Status, PHASE_WARP
from .panel import Panel, PanelError

# SOCKS5 port the install configures. Non-default (not 10808) so the test proves
# the port really flows panel -> WARP_SOCKS_PORT -> `warp-cli proxy port`.
SOCKS_PORT = 41080

# Cap for one warp-cli run (apt install + Cloudflare register + connect). Normal
# ~130-150s; 480s absorbs slow downloads under concurrent-VM load (>300s seen once).
RUN_TIMEOUT = 480


def _poll_run(panel: Panel, timeout: int, log) -> dict:
    """Poll /warpsocks/state until the background run finishes (or timeout).
    Does NOT stream the installer's live log to the job log — it's noisy and the
    console only needs pass/fail; the tail of the log is still captured in the
    phase's subtest detail for post-mortem. Returns the final state dict; on
    timeout returns the last snapshot with done still False."""
    deadline = time.monotonic() + timeout
    last: dict = {}
    errors = 0
    while time.monotonic() < deadline:
        time.sleep(2)
        try:
            st = panel.warpsocks_state()
        except PanelError as e:
            errors += 1
            log(f"-> state poll error ({errors}): {e}")
            # A few transient blips are fine, but a panel that stays unreachable
            # (e.g. OOM-killed during a heavy dnf/EPEL depsolve on a small RHEL VM)
            # won't recover — stop polling so the caller records the outcome (NA on
            # non-apt) instead of spinning the full timeout hitting a dead socket.
            if errors >= 5:
                log("-> panel unreachable for ~10s; giving up on warp poll")
                return last
            continue
        errors = 0
        last = st
        if not st.get("running", False) and st.get("done", False):
            return st
    return last


def run(incus: Incus, vm: str, panel: Panel, cfg: dict, result, log=None) -> None:
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_WARP)
    log(":: warp-socks — install Cloudflare warp-cli in SOCKS5 mode via the panel")

    def sub(name, status, detail, logtxt=""):
        st = SubTest(name, status, detail, logtxt)
        phase.add(st)
        log(f"-> {name} [{st.status.value}] {detail}")
        return st

    # apt distros are the first-class, previously-broken path -> install failure
    # is a real FAIL. Elsewhere (Arch AUR / spotty RPM) a failure is NA.
    rc, _, _ = incus.exec(vm, "command -v apt-get", check=False)
    apt_based = rc == 0
    fail_status = Status.FAIL if apt_based else Status.NA
    scope = "apt (must pass)" if apt_based else "non-apt (best-effort -> NA on fail)"
    log(f"-> distro package base: {scope}")

    # 0) Clean slate: warp-cli should not already be installed on a fresh VM.
    try:
        pre = panel.warpsocks_installed()
    except PanelError as e:
        sub("precheck", Status.ERROR, f"installed check failed: {e}")
        return
    sub("not-installed-initially", Status.PASS if not pre else Status.NA,
        "warp-cli absent on fresh VM" if not pre else "already present (unexpected)")

    # 1) Install + SOCKS5 config, driven exactly like the modal.
    try:
        start = panel.warpsocks_start("install", SOCKS_PORT)
    except PanelError as e:
        sub("install", Status.ERROR, f"could not start install: {e}")
        return
    if not start.get("running") and not start.get("done"):
        # A run may already be in flight (shouldn't be) — poll anyway.
        log("-> install did not report running; polling state regardless")
    log(f"-> install started (port {SOCKS_PORT}); polling until done, up to {RUN_TIMEOUT}s")

    final = _poll_run(panel, RUN_TIMEOUT, log)
    if not final.get("done"):
        sub("install", fail_status, f"install did not finish within {RUN_TIMEOUT}s",
            (final.get("log", "") or "")[-2000:])
        return
    ok = bool(final.get("success"))
    install_log = (final.get("log", "") or "")[-2000:]
    sub("install", Status.PASS if ok else fail_status,
        "warp-cli installed + SOCKS5 configured" if ok
        else "installer reported failure", install_log)
    if not ok:
        # Non-apt NA, or apt FAIL: nothing downstream can pass. Try to leave the
        # VM clean anyway (best-effort), then stop.
        _best_effort_uninstall(panel, log)
        return

    # 2) The panel now reports warp-cli present.
    try:
        installed = panel.warpsocks_installed()
    except PanelError as e:
        installed = False
        log(f"-> installed recheck error: {e}")
    sub("warp-cli-present", Status.PASS if installed else Status.FAIL,
        "panel detects warp-cli" if installed else "panel does NOT detect warp-cli")

    # 3) warp-cli itself reports Connected (registration + connect really worked,
    #    not just that the script exited 0). `warp-cli connect` returns as soon as
    #    it *initiates*, so status can read "Connecting" for a second or two before
    #    settling on "Connected" — poll a short while rather than one-shot it.
    connected, out = _wait_connected(incus, vm, settle=24)
    sub("warp-status-connected", Status.PASS if connected else Status.FAIL,
        f"status={_first_line(out)!r}", out)

    # 4) The SOCKS5 proxy actually egresses through WARP. Cloudflare's trace
    #    endpoint reports `warp=on` (or plus/full) only when the request left via
    #    the WARP tunnel — proving mode proxy + port + connect all took effect.
    #    Retry while the tunnel finishes coming up (races the connect above).
    trace_cmd = (f"curl -s --max-time 25 --socks5-hostname 127.0.0.1:{SOCKS_PORT} "
                 "https://www.cloudflare.com/cdn-cgi/trace 2>&1")
    warp_line, trace = "warp=?", ""
    for attempt in range(4):
        _, trace, _ = incus.exec(vm, trace_cmd, timeout=40, check=False)
        warp_line = next((l for l in (trace or "").splitlines()
                          if l.startswith("warp=")), "warp=?")
        if warp_line in ("warp=on", "warp=plus", "warp=full"):
            break
        time.sleep(4)
    egressed = warp_line in ("warp=on", "warp=plus", "warp=full")
    sub("socks-egress-warp", Status.PASS if egressed else Status.FAIL,
        f"proxy trace {warp_line!r} on :{SOCKS_PORT}", trace)

    # 5) Uninstall path (the modal's delete button). Leaves the VM clean and
    #    exercises the uninstall branch of warpcli.sh.
    try:
        panel.warpsocks_start("uninstall", 0)
        log(f"-> uninstall started; polling up to {RUN_TIMEOUT}s")
        un = _poll_run(panel, RUN_TIMEOUT, log)
        un_ok = un.get("done") and un.get("success")
        sub("uninstall", Status.PASS if un_ok else Status.FAIL,
            "warp-cli removed" if un_ok else "uninstall reported failure",
            (un.get("log", "") or "")[-1500:])
        gone = not panel.warpsocks_installed()
        sub("removed-after-uninstall", Status.PASS if gone else Status.FAIL,
            "warp-cli absent after uninstall" if gone else "still present after uninstall")
    except PanelError as e:
        sub("uninstall", Status.ERROR, f"uninstall error: {e}")


def _wait_connected(incus: Incus, vm: str, settle: int = 24):
    """Poll `warp-cli status` up to `settle` seconds, returning (connected, last).
    Matches the whole word "connected" so the transient "Connecting" does not
    count as done."""
    deadline = time.monotonic() + settle
    out = ""
    while True:
        _, out, _ = incus.exec(vm, "warp-cli --accept-tos status 2>&1", check=False)
        low = (out or "").lower()
        # "connected" but not merely "connecting": strip the -ing form first.
        if "connected" in low.replace("connecting", ""):
            return True, out
        if time.monotonic() >= deadline:
            return False, out
        time.sleep(3)


def _best_effort_uninstall(panel: Panel, log):
    """Try to remove a half-installed warp-cli so a kept VM isn't left dirty.
    Purely best-effort — swallow everything."""
    try:
        panel.warpsocks_start("uninstall", 0)
        _poll_run(panel, RUN_TIMEOUT, log)
    except Exception as e:  # noqa: BLE001
        log(f"-> best-effort uninstall skipped: {e}")


def _first_line(s: str) -> str:
    for line in (s or "").splitlines():
        if line.strip():
            return line.strip()
    return ""
