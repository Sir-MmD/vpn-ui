"""Client VM base: package prep, net-fact discovery, generic tunnel helpers.

Both client VMs are Ubuntu 26 (apt). A Client wraps one incus VM and knows how
to install the VPN tooling, pin a host route to the server (so tunnel packets
don't loop), curl through whatever the current default route is, and read the
active tunnel interface IP.

Embedded bash uses @@TOKEN@@ sentinels (not f-strings) so shell $()/${} never
collide with Python formatting.
"""
from __future__ import annotations

import time

from ..incus import Incus

CLIENT_PKGS_APT = (
    "openvpn xl2tpd ppp strongswan strongswan-starter "
    "libstrongswan-extra-plugins libcharon-extra-plugins "
    "pptp-linux ppp-mppe curl iproute2 net-tools dnsutils"
)


class Client:
    def __init__(self, incus: Incus, vm_full: str, label: str, logger=None):
        self.incus = incus
        self.vm = vm_full
        self.label = label                 # "A" or "B"
        self.log = logger or (lambda *_: None)
        self.eth = ""
        self.gw = ""
        self.bridge_net = ""               # e.g. 10.101.0.
        self.orig_public_ip = ""

    # ---- lifecycle ------------------------------------------------------
    def wait_network(self, timeout: int = 120) -> bool:
        """Agent-ready (vsock) does NOT mean the network is up. Wait for a default
        route + working DNS before touching apt, or the install fails instantly."""
        import time as _t
        deadline = _t.monotonic() + timeout
        while _t.monotonic() < deadline:
            rc, _, _ = self.incus.exec(
                self.vm,
                "ip -4 route show default | grep -q . && "
                "getent hosts archive.ubuntu.com >/dev/null 2>&1",
                timeout=20)
            if rc == 0:
                return True
            _t.sleep(4)
        return False

    def prep(self) -> tuple[bool, str]:
        """Install tooling + discover net facts. Returns (ok, log).

        Best-effort: a single unavailable package (names drift across Ubuntu
        releases) must not zero out the rest. We install the batch, then retry
        each package individually, and only hard-fail if openvpn itself is
        missing afterwards (the one tool every path needs)."""
        buf = []
        if not self.wait_network():
            buf.append("network/DNS not up within timeout before apt")
        self.incus.exec(self.vm, "export DEBIAN_FRONTEND=noninteractive; "
                                 "apt-get update -qq", timeout=300)
        rc, out, err = self.incus.exec(
            self.vm,
            "export DEBIAN_FRONTEND=noninteractive; "
            f"apt-get install -y -qq {CLIENT_PKGS_APT}",
            timeout=600,
        )
        buf.append((out + err)[-1500:])
        if rc != 0:
            # retry per-package so one bad name doesn't sink the batch
            for pkg in CLIENT_PKGS_APT.split():
                self.incus.exec(
                    self.vm,
                    "export DEBIAN_FRONTEND=noninteractive; "
                    f"apt-get install -y -qq {pkg}", timeout=300)
        have_ovpn, _, _ = self.incus.exec(self.vm, "command -v openvpn")
        if have_ovpn != 0:
            buf.append("FATAL: openvpn not installed")
            return False, "\n".join(buf)

        # default route interface + gateway
        _, out, _ = self.incus.exec(
            self.vm, "ip route show default | head -n1")
        parts = out.split()
        if "via" in parts:
            self.gw = parts[parts.index("via") + 1]
        if "dev" in parts:
            self.eth = parts[parts.index("dev") + 1]
        buf.append(f"default route: gw={self.gw} dev={self.eth}")

        # bridge /24 prefix (first three octets) for DNS-leak local-resolver check
        _, out, _ = self.incus.exec(
            self.vm, f"ip -4 -o addr show dev {self.eth} | awk '{{print $4}}' | head -n1")
        if "/" in out:
            ip = out.split("/")[0].strip()
            self.bridge_net = ".".join(ip.split(".")[:3]) + "."
        buf.append(f"bridge net prefix: {self.bridge_net}")

        # baseline public IP (pre-tunnel), best-effort — Cloudflare trace
        _, out, _ = self.incus.exec(
            self.vm, "curl -s -4 --max-time 15 https://1.1.1.1/cdn-cgi/trace "
                     "| grep '^ip=' | cut -d= -f2")
        self.orig_public_ip = out.strip().split("\n")[-1].strip()
        buf.append(f"baseline public IP: {self.orig_public_ip}")
        return True, "\n".join(buf)

    def apply_tunnel_dns(self, iface: str, dns=("1.1.1.1", "8.8.8.8")):
        """Point the resolver at the VPN-pushed DNS on the tunnel interface, as a
        real VPN client does — bare CLI clients (openvpn especially) don't
        auto-apply pushed DNS, which would otherwise look like a DNS leak."""
        self.sh(f"resolvectl dns {iface} {' '.join(dns)} 2>/dev/null; "
                f"resolvectl default-route {iface} true 2>/dev/null; "
                f"resolvectl flush-caches 2>/dev/null; true")

    def pin_server_route(self, server_ip: str):
        """Ensure the VPN server stays reachable via the physical NIC once the
        tunnel grabs the default route (l2tp/pptp). Idempotent."""
        if self.gw and self.eth:
            self.incus.exec(
                self.vm,
                f"ip route replace {server_ip}/32 via {self.gw} dev {self.eth}")

    # ---- generic tunnel helpers ----------------------------------------
    def wait_iface(self, iface: str, timeout: int = 40) -> str:
        """Wait for iface to have an IPv4; return it ('' on timeout)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, out, _ = self.incus.exec(
                self.vm,
                f"ip -4 -o addr show dev {iface} 2>/dev/null | awk '{{print $4}}'")
            out = out.strip()
            if out:
                return out.split("/")[0]
            time.sleep(2)
        return ""

    def curl(self, url: str, timeout: int = 20) -> tuple[int, str]:
        """Curl a URL from inside the VM via the current default route."""
        rc, out, _ = self.incus.exec(
            self.vm,
            f"curl -s --max-time {timeout} {url}",
            timeout=timeout + 10)
        return rc, out.strip()

    def ping(self, target_ip: str, count: int = 3, timeout: int = 15) -> tuple[bool, str]:
        rc, out, err = self.incus.exec(
            self.vm, f"ping -c {count} -W 3 {target_ip}", timeout=timeout)
        return rc == 0, out + err

    def resolv(self) -> str:
        _, out, _ = self.incus.exec(self.vm, "cat /etc/resolv.conf")
        return out

    def push(self, content: str, path: str, mode: str = "0644"):
        self.incus.push_bytes(self.vm, content, path, mode=mode)

    def sh(self, cmd: str, timeout: int = 120) -> tuple[int, str]:
        rc, out, err = self.incus.exec(self.vm, cmd, timeout=timeout)
        return rc, out + err

    # ---- teardown -------------------------------------------------------
    def disconnect_all(self):
        """Best-effort kill of every VPN client process + drop tunnels."""
        self.incus.exec(self.vm, (
            "pkill -f 'openvpn --config' 2>/dev/null; "
            "poff -a 2>/dev/null; pkill pppd 2>/dev/null; "
            "(echo 'd vpn' > /var/run/xl2tpd/l2tp-control 2>/dev/null); "
            "pkill xl2tpd 2>/dev/null; "
            "ipsec down l2tp 2>/dev/null; ipsec stop 2>/dev/null; "
            "systemctl stop strongswan strongswan-starter 2>/dev/null; true"
        ))
        time.sleep(2)
