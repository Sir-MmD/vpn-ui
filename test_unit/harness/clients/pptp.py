"""PPTP client connect/disconnect (pppd + pptp plugin, MSCHAPv2 + MPPE-128)."""
from __future__ import annotations

import time

from .base import Client

_PEER = """pty "pptp @@SERVER@@ --nolaunchpppd"
name @@USER@@
password @@PASS@@
remotename PPTP
require-mppe-128
refuse-eap
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
noauth
persist
maxfail 3
defaultroute
replacedefaultroute
usepeerdns
"""


def connect(client: Client, inbound, which: str,
            server_ip: str) -> tuple[bool, str, str]:
    """Bring up a PPTP tunnel. Returns (ok, tunnel_ip, log)."""
    acct = inbound.accounts[which]
    peer = (_PEER.replace("@@SERVER@@", server_ip)
                 .replace("@@USER@@", acct.user)
                 .replace("@@PASS@@", acct.password))
    client.push(peer, "/etc/ppp/peers/vpn")
    client.sh("modprobe ppp_mppe 2>/dev/null; true")
    client.pin_server_route(server_ip)

    client.sh("poff vpn 2>/dev/null; pkill pppd 2>/dev/null; sleep 1; "
              "pon vpn 2>/dev/null || pppd call vpn")
    ip = client.wait_iface("ppp0", timeout=40)
    if ip:
        client.apply_tunnel_dns("ppp0")
    _, log = client.sh("journalctl -u ppp* --no-pager 2>/dev/null | tail -n 20; "
                       "grep -i ppp /var/log/syslog 2>/dev/null | tail -n 30; "
                       "plog 2>/dev/null | tail -n 30")
    if not ip:
        return False, "", "pptp ppp0 never came up\n" + log
    return True, ip, log


def disconnect(client: Client):
    client.sh("poff vpn 2>/dev/null; pkill pppd 2>/dev/null; true")
    time.sleep(2)
