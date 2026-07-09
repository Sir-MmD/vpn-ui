"""OpenVPN client connect/disconnect.

Uses the panel-exported .ovpn (username/password auth, no client cert) and
forces the data cipher on the CLI to exercise old vs new negotiation against a
server configured with cipherMode=all.
"""
from __future__ import annotations

import time

from .base import Client

CIPHER = {"new": "AES-256-GCM", "old": "AES-256-CBC"}


def connect(client: Client, inbound, which: str, transport: str = "udp",
            cipher: str = "new", server_ip: str = "") -> tuple[bool, str, str]:
    """Bring up an OpenVPN tunnel for account A/B. Returns (ok, tunnel_ip, log)."""
    acct = inbound.accounts[which]
    profile = inbound.ovpn_udp if transport == "udp" else inbound.ovpn_tcp
    ciph = CIPHER[cipher]

    client.push(profile, "/etc/vpn/client.ovpn")
    client.push(f"{acct.user}\n{acct.password}\n", "/etc/vpn/creds.txt", mode="0600")
    if server_ip:
        client.pin_server_route(server_ip)

    client.sh("pkill -f 'openvpn --config' 2>/dev/null; rm -f /var/log/ovpn.log; true")
    cmd = (
        "openvpn --config /etc/vpn/client.ovpn "
        "--auth-user-pass /etc/vpn/creds.txt "
        f"--data-ciphers {ciph} --data-ciphers-fallback {ciph} --cipher {ciph} "
        "--connect-retry-max 3 --connect-timeout 15 "
        "--daemon --log /var/log/ovpn.log --writepid /run/ovpn.pid"
    )
    client.sh(cmd)

    ip = client.wait_iface("tun0", timeout=45)
    if ip:
        client.apply_tunnel_dns("tun0")
    _, log = client.sh("cat /var/log/ovpn.log 2>/dev/null | tail -n 40")
    if not ip:
        return False, "", f"tun0 never came up ({transport}/{cipher})\n{log}"
    # confirm the session initialised
    time.sleep(2)
    _, log = client.sh("cat /var/log/ovpn.log 2>/dev/null | tail -n 40")
    ok = "Initialization Sequence Completed" in log
    return ok, ip, log


def disconnect(client: Client):
    client.sh("kill $(cat /run/ovpn.pid 2>/dev/null) 2>/dev/null; "
              "pkill -f 'openvpn --config' 2>/dev/null; true")
    time.sleep(2)
