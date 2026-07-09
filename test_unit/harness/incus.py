"""Thin wrapper over the `incus` CLI for VM + network lifecycle.

Every job gets its own bridge network (isolated subnet) so parallel jobs never
clash. VMs are launched with `--vm` (real kernel, needed for ppp/l2tp/tun
modules that containers can't load). All exec/file calls go through the
incus-agent, so callers must wait_agent() first.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass

from . import abort


class IncusError(RuntimeError):
    pass


def _run(args, timeout=120, check=True, input_bytes=None, abortable=True):
    """Run an incus command, return CompletedProcess. Raise on failure if check.

    A timeout is turned into a returncode-124 CompletedProcess rather than a
    raised TimeoutExpired, so a hung guest command (e.g. `ipsec up l2tp` against
    a server with no IPsec) fails gracefully instead of crashing the driver.

    abortable (default True): once Ctrl+C has set the global abort flag, bail
    BEFORE spawning the process so a job in the middle of a long provisioning
    sequence (dozens of `exec`s) unwinds to its teardown at the very next incus
    call instead of grinding through the rest. Teardown primitives (delete /
    network delete / preclean) pass abortable=False so cleanup always completes."""
    if abortable and abort.is_set():
        raise IncusError(f"aborted (Ctrl+C) before: incus {' '.join(map(str, args))}")
    try:
        if input_bytes is None:
            # Never inherit the parent's stdin: when the whole run is launched as
            # `echo <pw> | sudo -S ./run.sh`, a leftover password byte on that pipe
            # would otherwise be read by `incus` as a YAML config on stdin ("cannot
            # construct !!int 0 into api.NetworkPut"). Force an empty stdin.
            proc = subprocess.run(
                ["incus", *args],
                capture_output=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
        else:
            proc = subprocess.run(
                ["incus", *args],
                capture_output=True,
                timeout=timeout,
                input=input_bytes,
            )
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess(
            args, 124, b"", f"timed out after {timeout}s".encode())
    if check and proc.returncode != 0:
        raise IncusError(
            f"incus {' '.join(args)} -> rc={proc.returncode}\n"
            f"stdout: {proc.stdout.decode(errors='replace')}\n"
            f"stderr: {proc.stderr.decode(errors='replace')}"
        )
    return proc


# ---------------------------------------------------------------------------
# Host firewall handling.
#
# A freshly-created incus managed bridge needs the host to (a) accept DHCP/DNS
# from the bridge and (b) FORWARD packets both ways (NAT out + return). incus
# installs its own nftables/iptables rules for managed bridges, so on a host
# with *plain* nftables/iptables (or no firewall at all) a new bridge Just
# Works. Two managers get in the way and need an explicit per-bridge allow:
#
#   * firewalld — its nftables table is `flags owner,persist`, so only
#     firewalld may edit its chains; incus can't insert. A new bridge lands in
#     the default zone (drop/reject), so we add it to the `trusted` zone.
#   * ufw       — defaults to DROP on the forward chain in its own filter
#     table; an nftables drop in ANY table is final, so incus's accept in its
#     own table isn't enough. We add explicit `ufw route allow` on the bridge.
#
# All commands run as root (run.sh enforces it). firewall-cmd is run with the
# desktop polkit-agent env stripped so it can't pop a GUI password dialog: as
# root with no reachable agent, polkit implicitly authorizes root (verified:
# `sudo firewall-cmd --add-interface` -> success, no prompt).
_AGENT_ENV = ("DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "XDG_RUNTIME_DIR")


def _raw(args, timeout=30, strip_agent=False):
    """Run a non-incus host command (systemctl/firewall-cmd/ufw). Never raises.
    strip_agent removes the desktop polkit-agent env so firewall-cmd can't pop
    a GUI dialog."""
    env = None
    if strip_agent:
        env = {k: v for k, v in os.environ.items() if k not in _AGENT_ENV}
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None


def _service_active(name: str) -> bool:
    p = _raw(["systemctl", "is-active", name])
    return bool(p) and p.returncode == 0


def _firewalld_active() -> bool:
    """True if firewalld is running. A freshly-created incus bridge is NOT in a
    trusted zone, so firewalld drops DHCP/forwarded traffic on it until we trust
    it — unlike the default incusbr0 which incus trusts at init time."""
    return _service_active("firewalld")


def _ufw_active() -> bool:
    """True if ufw is installed and reports `Status: active`. An inactive ufw
    installs no chains, so there is nothing to allow."""
    p = _raw(["ufw", "status"])
    if not p or p.returncode != 0:
        return False
    return b"Status: active" in (p.stdout or b"")


def _firewalld_trust(bridge: str, add: bool):
    flag = "--add-interface" if add else "--remove-interface"
    _raw(["firewall-cmd", "--zone=trusted", f"{flag}={bridge}"], strip_agent=True)


def _ufw_allow(bridge: str, add: bool):
    """Allow input + bidirectional forwarding on the bridge. `ufw route allow`
    covers forwarded (NATed) traffic; `ufw allow in on` covers DHCP/DNS to the
    host. On removal the same rules are deleted (best-effort)."""
    verb = ["allow"] if add else ["delete", "allow"]
    _raw(["ufw", *verb, "in", "on", bridge])
    _raw(["ufw", "route", *verb, "in", "on", bridge])
    _raw(["ufw", "route", *verb, "out", "on", bridge])


def firewall_open_bridge(bridge: str, add: bool) -> list:
    """Open (add=True) / close (add=False) a managed bridge in whichever host
    firewall is active. Returns the managers adjusted (for logging). Plain
    nftables/iptables and 'no firewall' need nothing — incus manages those
    itself, so an empty list means 'nothing to do, already fine'."""
    adjusted = []
    if _firewalld_active():
        _firewalld_trust(bridge, add)
        adjusted.append("firewalld")
    if _ufw_active():
        _ufw_allow(bridge, add)
        adjusted.append("ufw")
    return adjusted


def image_exists(image: str) -> bool:
    """Check an image ref (remote:alias) resolves, without downloading it.
    `incus image info` queries the remote and returns non-zero if not found.

    Never raises: a slow/unreachable remote (timeout) is NOT the same as a
    missing image, so on any error we optimistically return True and let the
    subsequent `incus launch` surface a real 'not found' — which happens inside
    the job's try-block and is recorded as an error instead of crashing."""
    try:
        proc = subprocess.run(["incus", "image", "info", image],
                              capture_output=True, timeout=60)
    except subprocess.SubprocessError:
        return True
    if proc.returncode == 0:
        return True
    # definitively not found only if incus says so; transient errors -> assume ok
    err = proc.stderr.decode(errors="replace").lower()
    return "not found" not in err and "no such" not in err


@dataclass
class Network:
    name: str
    subnet: str  # e.g. 10.101.0.1/24

    def gateway(self) -> str:
        return self.subnet.split("/")[0]


class Incus:
    """Namespaced helper: all instances/networks carry a per-run prefix."""

    def __init__(self, prefix: str, logger=None):
        self.prefix = prefix
        self.log = logger or (lambda *_: None)

    # ---- networks -------------------------------------------------------
    def create_network(self, index: int) -> Network:
        """Create an isolated managed bridge. The bridge name doubles as the
        Linux interface name (IFNAMSIZ=15), so keep it short: 'vt<index>'.
        subnet 10.<100+index>.0.0/24 stays clear of VPN tunnel subnets
        (10.0-10.3.<id>.0/24)."""
        full = f"vt{index}"
        subnet = f"10.{100 + index}.0.1/24"
        _run([
            "network", "create", full,
            f"ipv4.address={subnet}",
            "ipv4.nat=true",
            "ipv6.address=none",
        ])
        adjusted = firewall_open_bridge(full, add=True)
        if adjusted:
            self.log(f"network {full} created ({subnet}); opened in {', '.join(adjusted)}")
        else:
            self.log(f"network {full} created ({subnet})")
        return Network(full, subnet)

    def delete_network(self, net: Network):
        firewall_open_bridge(net.name, add=False)
        _run(["network", "delete", net.name], check=False, abortable=False)

    def preclean(self, index: int):
        """Remove any leftover instances/network from a prior aborted run with
        this job's (deterministic, index-based) names, so a killed/crashed run
        doesn't block the next one with 'already exists'. Best-effort."""
        for suffix in ("srv", "cla", "clb", "clc"):
            self.delete(f"{self.prefix}-{suffix}")
        net = f"vt{index}"
        firewall_open_bridge(net, add=False)
        _run(["network", "delete", net], check=False, abortable=False)

    # ---- instances ------------------------------------------------------
    def launch(self, image: str, name: str, net: Network,
               cpu: int, memory: str):
        full = f"{self.prefix}-{name}"
        # init (not launch) so the agent:config disk can be added BEFORE first
        # boot. Several images: VM images (almalinux/rockylinux/archlinux/some
        # fedora) refuse creation with "requires an agent:config disk be added";
        # ubuntu/debian bundle it. Adding it explicitly is harmless for those
        # that already have it and fixes the rest — uniform across all distros.
        _run([
            "init", image, full, "--vm",
            "--network", net.name,
            "-c", f"limits.cpu={cpu}",
            "-c", f"limits.memory={memory}",
            # archlinux (and some others) are built without secureboot support;
            # incus refuses to start them unless this is off. Harmless elsewhere.
            "-c", "security.secureboot=false",
        ], timeout=600)
        _run(["config", "device", "add", full, "agent", "disk",
              "source=agent:config"], check=False)
        _run(["start", full], timeout=180)
        self.log(f"instance {full} launched from {image}")
        return full

    def delete(self, name_full: str):
        _run(["delete", name_full, "--force"], check=False, timeout=180, abortable=False)

    def wait_agent(self, name_full: str, timeout: int):
        """Block until `incus exec` works (agent up + system booted enough)."""
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            if abort.is_set():
                raise IncusError(f"{name_full} agent wait aborted (Ctrl+C)")
            proc = _run(["exec", name_full, "--", "true"],
                        timeout=30, check=False)
            if proc.returncode == 0:
                self.log(f"{name_full} agent ready")
                return
            last = proc.stderr.decode(errors="replace")
            time.sleep(3)
        raise IncusError(f"{name_full} agent not ready in {timeout}s: {last}")

    def ipv4(self, name_full: str, timeout: int = 60) -> str:
        """Return the instance's IPv4 on its bridge (enp5s0/eth0), waiting for DHCP."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if abort.is_set():
                raise IncusError(f"{name_full} ip wait aborted (Ctrl+C)")
            proc = _run(["list", name_full, "--format", "json"],
                        timeout=30, check=False)
            if proc.returncode == 0:
                try:
                    data = json.loads(proc.stdout.decode())
                except json.JSONDecodeError:
                    data = []
                for inst in data:
                    state = inst.get("state") or {}
                    for iface, info in (state.get("network") or {}).items():
                        if iface == "lo":
                            continue
                        for addr in info.get("addresses", []):
                            if addr.get("family") == "inet" and \
                               addr.get("scope") == "global":
                                return addr["address"]
            time.sleep(2)
        raise IncusError(f"{name_full} has no global IPv4 after {timeout}s")

    # ---- exec / files ---------------------------------------------------
    def exec(self, name_full: str, cmd, timeout=300, check=False, env=None):
        """Run a shell command inside the VM. cmd is a string run via `sh -c`.
        Returns (rc, stdout_str, stderr_str)."""
        args = ["exec", name_full]
        for k, v in (env or {}).items():
            args += ["--env", f"{k}={v}"]
        args += ["--", "sh", "-c", cmd]
        proc = _run(args, timeout=timeout, check=False)
        out = proc.stdout.decode(errors="replace")
        err = proc.stderr.decode(errors="replace")
        if check and proc.returncode != 0:
            raise IncusError(f"exec in {name_full} failed ({proc.returncode}): "
                             f"{cmd}\n{out}\n{err}")
        return proc.returncode, out, err

    def push(self, name_full: str, local_path: str, remote_path: str,
             mode: str = "0755"):
        _run(["file", "push", local_path, f"{name_full}{remote_path}",
              "--mode", mode, "--create-dirs"], timeout=300)

    def push_dir(self, name_full: str, local_dir: str, remote_parent: str):
        """Recursively push a local directory into remote_parent (which must end
        with '/'), creating remote_parent/<basename(local_dir)>."""
        if not remote_parent.endswith("/"):
            remote_parent += "/"
        _run(["file", "push", "-r", local_dir.rstrip("/"),
              f"{name_full}{remote_parent}", "--create-dirs"], timeout=600)

    def push_bytes(self, name_full: str, data: str, remote_path: str,
                   mode: str = "0644"):
        """Write a string to a file inside the VM via stdin."""
        _run(["file", "push", "-", f"{name_full}{remote_path}",
              "--mode", mode, "--create-dirs"],
             timeout=120, input_bytes=data.encode())

    def pull_text(self, name_full: str, remote_path: str) -> str:
        proc = _run(["file", "pull", f"{name_full}{remote_path}", "-"],
                    timeout=120, check=False)
        return proc.stdout.decode(errors="replace") if proc.returncode == 0 else ""

    def reboot(self, name_full: str, agent_timeout: int):
        _run(["restart", name_full], timeout=180, check=False)
        time.sleep(5)
        self.wait_agent(name_full, agent_timeout)
