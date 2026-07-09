"""Server-setup phase: build one inbound per protocol (each with 2 accounts),
add two email-based source-IP routing rules against the built-in outbounds
(A-accounts -> `direct`/freedom, B-accounts -> `blocked`/blackhole), and assert
the panel translated the blackhole rule to a per-client source-IP rule.

Topology (chosen so no port/tag collisions and both client VMs are reused):
  - one inbound per protocol, clientToClient + crossInbound both enabled
  - account A on client-VM-A, account B on client-VM-B
  - client-to-client  = A and B on the SAME protocol inbound
  - cross-inbound     = A on protocol X, B on protocol Y (cross-protocol; the
    nftables gate is IP/inbound-level, so this exercises the same code path)

Tunnel IPs are deterministic (radius.go computeVpnClientIP / vpnrange.go):
  IP = 10.<base>.<inboundId>.<2 + clientIndex>, base: l2tp=0 pptp=1 ovpn-udp=2 ovpn-tcp=3
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .model import JobResult, SubTest, Status, PHASE_SETUP
from .panel import Panel

# protocol base octet for the 10.<base>.<id>.<host> tunnel address
BASE = {"l2tp": 0, "pptp": 1, "ovpn-udp": 2, "ovpn-tcp": 3}

PSK = "TestPSK-9182"  # L2TP/IPsec pre-shared key

# User Limit (devices per account). All three protocols run at K=2 so the User
# Limit Strategy test can drive a 3rd device past the cap (needs the 3rd client
# VM). K=2 also keeps the per-account block allocator + source-IP routing on the
# hot path for every protocol.
L2TP_USER_LIMIT = 2
OVPN_USER_LIMIT = 2
PPTP_USER_LIMIT = 2

# Ports for the SECOND same-protocol inbound (protocols.py multi-inbound test).
# Distinct from the primary ports (openvpn udp 1194 / tcp 1443, l2tp 1701, pptp
# 1723) and from each other so the panel's port-uniqueness check passes. NOTE:
# xl2tpd/pptpd each bind ONE fixed port (1701/1723) and serve every inbound —
# differentiated by account -> RADIUS -> IP range — so for l2tp/pptp this port is
# only a unique label; only openvpn actually listens on its own per-inbound port.
SECOND_PORTS = {
    "openvpn": {"udp": 1195, "tcp": 1444},
    "l2tp":    {"udp": 1799},
    "pptp":    {"udp": 1798},
}


def build_second_inbound(panel: Panel, proto: str) -> Inbound:
    """Create a SECOND inbound of `proto` on a distinct port + IP pool with its own
    single account (index 0, user_limit=1), for the multi-inbound-same-proto E2E
    test (protocols.py). Returns the Inbound. Raises on panel error (the caller
    treats an inability to create a 2nd same-proto inbound as a product FAIL).
    Reuses the exact settings shapes the primary inbounds are built with above."""
    ports = SECOND_PORTS[proto]
    acct = _acct(proto + "2", 0)   # distinct emails: ovpn2a@t / l2tp2a@t / pptp2a@t
    if proto == "openvpn":
        certs = panel.generate_openvpn_certs()
        settings = {
            "udpEnable": True, "tcpEnable": True,
            "tcpPort": ports["tcp"],
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "caCert": certs["caCert"], "caKey": certs["caKey"],
            "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
            "tlsCrypt": certs["tlsCrypt"],
            "cipherMode": "all",
            "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-openvpn-2", ports["udp"], "openvpn", settings)
        iid = inb["id"]
        return Inbound(
            protocol="openvpn", inbound_id=iid, udp_port=ports["udp"],
            tcp_port=ports["tcp"], accounts={"A": acct},
            ovpn_udp=panel.download_ovpn(iid, "udp"),
            ovpn_tcp=panel.download_ovpn(iid, "tcp"), user_limit=1)
    if proto == "l2tp":
        settings = {
            "ipsecEnable": True, "ipsecPsk": PSK, "allowRaw": True,
            "clientToClient": True, "crossInbound": True,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-l2tp-2", ports["udp"], "l2tp", settings)
        return Inbound(
            protocol="l2tp", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, psk=PSK, user_limit=1)
    if proto == "pptp":
        settings = {
            "clientToClient": True, "crossInbound": True,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-pptp-2", ports["udp"], "pptp", settings)
        return Inbound(
            protocol="pptp", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
    raise ValueError(proto)


@dataclass
class Account:
    user: str
    password: str
    email: str
    index: int      # zero-based position in clients[]


@dataclass
class Inbound:
    protocol: str          # openvpn | l2tp | pptp
    inbound_id: int
    udp_port: int
    tcp_port: int          # openvpn only; 0 otherwise
    accounts: dict         # {"A": Account, "B": Account}
    psk: str = ""          # l2tp ipsec
    ovpn_udp: str = ""     # exported .ovpn profile text (openvpn)
    ovpn_tcp: str = ""
    user_limit: int = 1    # devices-per-account (User Limit feature); >1 = block mode

    def client_ip(self, which: str, transport: str = "udp", device: int = 0) -> str:
        """Tunnel IP for account A/B on this inbound. With user_limit K>1 each
        account owns an aligned K-block: host base = (index+1)*K, device d = base+d
        (mirrors Go vpnAccountDeviceIP). K==1 keeps the legacy 2+index host."""
        acct = self.accounts[which]
        if self.protocol == "openvpn":
            base = BASE["ovpn-tcp"] if transport == "tcp" else BASE["ovpn-udp"]
        else:
            base = BASE[self.protocol]
        if self.user_limit > 1:
            host = (acct.index + 1) * self.user_limit + device
        else:
            host = 2 + acct.index
        return f"10.{base}.{self.inbound_id}.{host}"


@dataclass
class ServerConfig:
    server_ip: str
    inbounds: dict = field(default_factory=dict)   # protocol -> Inbound


def _acct(prefix: str, idx: int) -> Account:
    letter = "A" if idx == 0 else "B"
    return Account(user=f"{prefix}{letter.lower()}",
                   password=f"Pw-{prefix}{letter}-9k",
                   email=f"{prefix}{letter.lower()}@t",
                   index=idx)


def run(panel: Panel, server_ip: str, cfg: dict, result: JobResult,
        log=None) -> ServerConfig | None:
    """Build inbounds/accounts/outbound/routing. Returns ServerConfig, or None
    if a fatal setup error occurred (subtests record the detail)."""
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_SETUP)
    sc = ServerConfig(server_ip=server_ip)

    # ---- OpenVPN inbound ------------------------------------------------
    log("-> creating openvpn inbound (certs + 2 accounts, ciphers=all)...")
    ov = phase.add(SubTest("openvpn-inbound"))
    try:
        certs = panel.generate_openvpn_certs()
        settings = {
            "udpEnable": True, "tcpEnable": True,
            "tcpPort": 1443,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "caCert": certs["caCert"], "caKey": certs["caKey"],
            "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
            "tlsCrypt": certs["tlsCrypt"],
            "cipherMode": "all",
            # AEAD (new) + a default-provider CBC (old); both testable without
            # the OpenSSL legacy provider.
            "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            "clientToClient": True,
            "crossInbound": True,
            "userLimit": OVPN_USER_LIMIT,  # exercise the connect-hook block allocator
            "clients": [
                _dict_client(_acct("ovpn", 0)),
                _dict_client(_acct("ovpn", 1)),
            ],
        }
        inb = panel.add_inbound("test-openvpn", 1194, "openvpn", settings)
        iid = inb["id"]
        sc.inbounds["openvpn"] = Inbound(
            protocol="openvpn", inbound_id=iid, udp_port=1194, tcp_port=1443,
            accounts={"A": _acct("ovpn", 0), "B": _acct("ovpn", 1)},
            ovpn_udp=panel.download_ovpn(iid, "udp"),
            ovpn_tcp=panel.download_ovpn(iid, "tcp"),
            user_limit=OVPN_USER_LIMIT,
        )
        ov.status = Status.PASS
        ov.detail = f"inbound {iid}, udp 1194 / tcp 1443, 2 accounts, ciphers all"
    except Exception as e:  # noqa: BLE001
        ov.status = Status.ERROR
        ov.detail = str(e)[:300]

    log(f"-> openvpn-inbound [{ov.status.value}] {ov.detail}")

    # ---- L2TP inbound ---------------------------------------------------
    log("-> creating l2tp inbound (raw+ipsec, 2 accounts)...")
    l2 = phase.add(SubTest("l2tp-inbound"))
    try:
        settings = {
            "ipsecEnable": True, "ipsecPsk": PSK, "allowRaw": True,
            "clientToClient": True, "crossInbound": True,
            "userLimit": L2TP_USER_LIMIT,  # exercise the per-account block allocator
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(_acct("l2tp", 0)),
                        _dict_client(_acct("l2tp", 1))],
        }
        inb = panel.add_inbound("test-l2tp", 1701, "l2tp", settings)
        iid = inb["id"]
        sc.inbounds["l2tp"] = Inbound(
            protocol="l2tp", inbound_id=iid, udp_port=1701, tcp_port=0,
            accounts={"A": _acct("l2tp", 0), "B": _acct("l2tp", 1)}, psk=PSK,
            user_limit=L2TP_USER_LIMIT,
        )
        l2.status = Status.PASS
        l2.detail = f"inbound {iid}, raw+ipsec, psk set, 2 accounts"
    except Exception as e:  # noqa: BLE001
        l2.status = Status.ERROR
        l2.detail = str(e)[:300]

    log(f"-> l2tp-inbound [{l2.status.value}] {l2.detail}")

    # ---- PPTP inbound ---------------------------------------------------
    log("-> creating pptp inbound (2 accounts)...")
    pp = phase.add(SubTest("pptp-inbound"))
    try:
        settings = {
            "clientToClient": True, "crossInbound": True,
            "userLimit": PPTP_USER_LIMIT,  # exercise the per-account block allocator
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(_acct("pptp", 0)),
                        _dict_client(_acct("pptp", 1))],
        }
        inb = panel.add_inbound("test-pptp", 1723, "pptp", settings)
        iid = inb["id"]
        sc.inbounds["pptp"] = Inbound(
            protocol="pptp", inbound_id=iid, udp_port=1723, tcp_port=0,
            accounts={"A": _acct("pptp", 0), "B": _acct("pptp", 1)},
            user_limit=PPTP_USER_LIMIT,
        )
        pp.status = Status.PASS
        pp.detail = f"inbound {iid}, 2 accounts"
    except Exception as e:  # noqa: BLE001
        pp.status = Status.ERROR
        pp.detail = str(e)[:300]

    log(f"-> pptp-inbound [{pp.status.value}] {pp.detail}")

    # ---- source-IP routing rules (built-in outbounds, no external link) ----
    # Prove Xray routes by source IP using the two outbounds every config already
    # ships: `direct` (freedom) and `blocked` (blackhole). Author by email (the
    # panel auto-translates email -> source IP): A-accounts -> freedom (reach the
    # internet), B-accounts -> blackhole (cut off). The per-protocol `routing`
    # check then proves the split deterministically from the CONTRAST — same
    # protocol, adjacent tunnel IPs, only the rule differs — with no external
    # outbound and no exit-IP compare (which false-fails whenever the outbound and
    # the test host happen to share an egress IP).
    log("-> adding source-IP routing rules (A->freedom, B->blackhole)...")
    route = phase.add(SubTest("routing-rules"))
    try:
        tmpl = panel.get_xray_template()
        routing = tmpl.setdefault("routing", {})
        rules = routing.setdefault("rules", [])
        a_emails = [ib.accounts["A"].email for ib in sc.inbounds.values()]
        b_emails = [ib.accounts["B"].email for ib in sc.inbounds.values()]
        # insert at the front so these win over the default catch-all / geoip rules
        rules.insert(0, {"type": "field", "outboundTag": "direct", "user": a_emails})
        rules.insert(1, {"type": "field", "outboundTag": "blocked", "user": b_emails})
        panel.update_xray_template(tmpl)
        route.status = Status.PASS
        route.detail = f"A->freedom {a_emails}, B->blackhole {b_emails}"
        route.log = (f"freedom (direct):  {', '.join(a_emails)}\n"
                     f"blackhole (blocked): {', '.join(b_emails)}")
    except Exception as e:  # noqa: BLE001
        route.status = Status.ERROR
        route.detail = str(e)[:300]

    log(f"-> routing-rules [{route.status.value}] {route.detail}")

    # ---- assert email->source-IP translation ---------------------------
    # The blackhole rule is the meaningful one: verify the panel translated the
    # B-account emails into a source-IP rule bound to `blocked`. (B is a client on
    # every inbound; openvpn B appears at both its 10.2/10.3 transport IPs.)
    log("-> verifying panel translated B emails -> source-IP (blackhole)...")
    trans = phase.add(SubTest("routing-translation"))
    try:
        want_ips = set()
        for ib in sc.inbounds.values():
            if ib.protocol == "openvpn":
                want_ips.add(ib.client_ip("B", "udp"))
                want_ips.add(ib.client_ip("B", "tcp"))
            else:
                want_ips.add(ib.client_ip("B"))
        conf = panel.get_config_json()
        src_seen = set()
        for r in conf.get("routing", {}).get("rules", []):
            if r.get("outboundTag") == "blocked":
                for s in r.get("source", []) or []:
                    src_seen.add(s)
        # A source may be a bare IP (K==1) or a CIDR block (User Limit K>1) — a
        # want IP counts as a hit if it equals or is contained in a seen source.
        import ipaddress as _ip
        def _covers(src: str, ip: str) -> bool:
            try:
                return _ip.ip_address(ip) in _ip.ip_network(src, strict=False)
            except ValueError:
                return src == ip
        hit = {w for w in want_ips if any(_covers(s, w) for s in src_seen)}
        trans.log = f"expected any of {sorted(want_ips)}\nsaw blackhole source {sorted(src_seen)}"
        if hit:
            trans.status = Status.PASS
            trans.detail = f"panel translated B user->source (blackhole); matched {sorted(hit)}"
        else:
            trans.status = Status.FAIL
            trans.detail = "no blackhole source-IP rule found for B accounts"
    except Exception as e:  # noqa: BLE001
        trans.status = Status.ERROR
        trans.detail = str(e)[:300]

    # ---- xray actually running with the new config ---------------------
    # Pre-inbound xray may be idle/error; now that inbounds + routing exist it
    # must run, or all tproxy->xray->internet + routing tests will fail. Restart
    # and verify, capturing logs so a backend xray failure is visible here.
    log("-> restarting xray + verifying it runs with the new config...")
    xr = phase.add(SubTest("xray-running"))
    try:
        import time as _t
        panel.restart_core("xray")
        _t.sleep(3)
        cores = {c.get("name"): c for c in panel.core_status().get("cores", [])}
        xstate = (cores.get("xray") or {}).get("state", "?")
        xr.log = f"state={xstate}\n\n== xray logs ==\n" + _safe(panel, "xray")
        if xstate in ("running", "idle"):
            xr.status = Status.PASS
            xr.detail = f"xray {xstate}"
        else:
            xr.status = Status.FAIL
            xr.detail = f"xray not running (state={xstate}) — internet/routing will fail"
        log(f"-> xray-running [{xr.status.value}] {xr.detail}")
    except Exception as e:  # noqa: BLE001
        xr.status = Status.ERROR
        xr.detail = str(e)[:300]

    # fatal only if we couldn't build any inbound
    if all(p not in sc.inbounds for p in ("openvpn", "l2tp", "pptp")):
        return None
    return sc


def _safe(panel: Panel, core: str) -> str:
    try:
        return panel.core_logs(core)
    except Exception:  # noqa: BLE001
        return "(no logs)"


def _dict_client(a: Account) -> dict:
    return {"id": a.user, "password": a.password, "email": a.email, "enable": True}
