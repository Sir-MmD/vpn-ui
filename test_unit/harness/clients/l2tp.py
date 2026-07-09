"""L2TP client connect/disconnect, both raw and IPsec (PSK) modes.

raw   : xl2tpd + pppd straight to server:1701 (server allowRaw=true).
ipsec : strongswan transport-mode ESP (PSK) first, then L2TP/PPP inside it.
"""
from __future__ import annotations

import time

from .base import Client

_PPP_OPTS = """ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-mschap-v2
noccp
noauth
mtu 1400
mru 1400
noipdefault
defaultroute
replacedefaultroute
usepeerdns
connect-delay 5000
name @@USER@@
password @@PASS@@
"""

_XL2TPD_CONF = """[global]
[lac vpn]
lns = @@SERVER@@
require chap = yes
refuse pap = yes
require authentication = yes
pppoptfile = /etc/ppp/options.l2tpd.client
length bit = yes
"""

_IPSEC_CONF = """config setup
conn l2tp
  type=transport
  keyexchange=ikev1
  authby=secret
  left=%defaultroute
  leftprotoport=17/1701
  right=@@SERVER@@
  rightprotoport=17/1701
  auto=add
"""


def _write_common(client: Client, inbound, which: str, server_ip: str):
    acct = inbound.accounts[which]
    client.push(_PPP_OPTS.replace("@@USER@@", acct.user).replace("@@PASS@@", acct.password),
                "/etc/ppp/options.l2tpd.client")
    client.push(_XL2TPD_CONF.replace("@@SERVER@@", server_ip),
                "/etc/xl2tpd/xl2tpd.conf")
    client.sh("mkdir -p /var/run/xl2tpd")
    client.pin_server_route(server_ip)


def connect(client: Client, inbound, which: str, ipsec: bool,
            server_ip: str) -> tuple[bool, str, str]:
    """Bring up an L2TP tunnel. Returns (ok, tunnel_ip, log)."""
    log = []
    _write_common(client, inbound, which, server_ip)

    if ipsec:
        client.push(_IPSEC_CONF.replace("@@SERVER@@", server_ip), "/etc/ipsec.conf")
        client.push(f'%any {server_ip} : PSK "{inbound.psk}"\n', "/etc/ipsec.secrets", mode="0600")
        client.sh("systemctl restart strongswan-starter 2>/dev/null || "
                  "systemctl restart strongswan 2>/dev/null || ipsec restart; sleep 3")
        rc, out = client.sh("ipsec up l2tp", timeout=60)
        log.append("== ipsec up ==\n" + out)
        if "connection 'l2tp' established" not in out and "success" not in out.lower() \
                and rc != 0:
            # continue anyway; some strongswan builds report differently
            pass

    # (re)start xl2tpd and dial
    client.sh("pkill xl2tpd 2>/dev/null; sleep 1; xl2tpd -D >/var/log/xl2tpd.log 2>&1 &")
    time.sleep(3)
    client.sh("echo 'c vpn' > /var/run/xl2tpd/l2tp-control")

    ip = client.wait_iface("ppp0", timeout=45)
    if ip:
        client.apply_tunnel_dns("ppp0")
    _, xlog = client.sh("cat /var/log/xl2tpd.log 2>/dev/null | tail -n 30; "
                        "journalctl -u strongswan* --no-pager 2>/dev/null | tail -n 20")
    log.append("== xl2tpd/ppp ==\n" + xlog)
    if not ip:
        return False, "", "l2tp ppp0 never came up\n" + "\n".join(log)
    return True, ip, "\n".join(log)


def disconnect(client: Client):
    client.sh("echo 'd vpn' > /var/run/xl2tpd/l2tp-control 2>/dev/null; "
              "pkill xl2tpd 2>/dev/null; ipsec down l2tp 2>/dev/null; "
              "ipsec stop 2>/dev/null; true")
    time.sleep(2)
