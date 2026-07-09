"""Post-connection checks run inside a connected client VM.

Each returns a SubTest. Ping-based peer checks (client-to-client, cross-inbound)
take the already-connected peer's tunnel IP from the orchestrator.
"""
from __future__ import annotations

import json
import time

from .clients.base import Client
from .model import SubTest, Status


def tunnel_egress(client: Client, ifaces=("tun0", "ppp0")) -> SubTest:
    """Confirm external traffic egresses via the tunnel. NOTE: openvpn pushes
    `redirect-gateway def1`, which adds 0.0.0.0/1 + 128.0.0.0/1 via tun and
    deliberately LEAVES the `default` route intact — so we must ask the kernel
    which iface a real external IP resolves to, not inspect `default`."""
    st = SubTest("tunnel-egress")
    _, route_get = client.sh("ip route get 1.1.1.1")
    _, full = client.sh("ip route")
    st.log = "== ip route get 1.1.1.1 ==\n" + route_get + "\n== ip route ==\n" + full
    if any(f"dev {i}" in route_get for i in ifaces):
        st.status = Status.PASS
        st.detail = route_get.strip().split("\n")[0]
    else:
        st.status = Status.FAIL
        st.detail = "external traffic not via tunnel: " + route_get.strip()[:120]
    return st


def internet(client: Client) -> SubTest:
    """Reachability through the tunnel. Retries: the server-side tproxy->xray
    path can take a few seconds to warm up after a fresh connect (slower on
    older kernels like ubuntu-22's 5.15), so a single immediate curl races the
    cold path. On persistent failure, capture route/DNS/IP-only diagnostics to
    separate a dead data-plane from a DNS-only problem."""
    st = SubTest("internet")
    t0 = time.monotonic()
    code = ""
    for attempt in range(6):
        _, code = client.sh(
            "curl -s -o /dev/null -w '%{http_code}' --max-time 15 "
            "https://www.google.com/generate_204")
        if code.strip() in ("204", "200"):
            st.status = Status.PASS
            st.detail = f"reachable (HTTP {code.strip()}, attempt {attempt + 1})"
            st.log = f"http_code={code} attempts={attempt + 1}"
            st.duration_s = round(time.monotonic() - t0, 1)
            return st
        time.sleep(3)
    st.duration_s = round(time.monotonic() - t0, 1)
    # diagnose: IP-only curl (no DNS) isolates data-plane from resolver
    _, ipcode = client.sh(
        "curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://1.1.1.1")
    _, rg = client.sh("ip route get 1.1.1.1")
    _, rslv = client.sh("cat /etc/resolv.conf")
    st.status = Status.FAIL
    st.detail = (f"no internet after retries (https code={code.strip()!r}, "
                 f"ip-only http code={ipcode.strip()!r})")
    st.log = (f"https generate_204 code={code}\nhttp://1.1.1.1 code={ipcode}\n"
              f"== route get 1.1.1.1 ==\n{rg}\n== resolv.conf ==\n{rslv}")
    return st


# DNS the panel pushes to clients (server_setup sets dns1/dns2 to these for all
# three protocols). A non-leaking client resolves via these, through the tunnel.
PUSHED_DNS = ("1.1.1.1", "8.8.8.8")


def _tunnel_dns_state(client: Client):
    """Deterministic signal: (iface, uses_pushed, via_tunnel, resolves, ifstatus, rg)."""
    _, up = client.sh("for i in tun0 ppp0; do ip -o link show $i 2>/dev/null; done")
    iface = "tun0" if "tun0:" in up else ("ppp0" if "ppp0:" in up else "")
    _, ifstatus = client.sh(f"resolvectl status {iface} 2>/dev/null" if iface else "true")
    _, rg = client.sh("ip route get 1.1.1.1 2>/dev/null | head -1")
    _, works = client.sh("getent hosts example.com >/dev/null 2>&1 && echo OK || echo FAIL")
    uses_pushed = any(d in ifstatus for d in PUSHED_DNS)
    via_tunnel = bool(iface) and f"dev {iface}" in rg
    return iface, uses_pushed, via_tunnel, ("OK" in works), ifstatus, rg


def _bashws_resolvers(client: Client, cfg: dict):
    """Run dnsleaktest.com / bash.ws with DIG probes (curl fails — must be raw DNS
    queries) and return (resolvers, raw_json). Retries a few times."""
    api = cfg["dns_leak"]["api_base"]
    host = _host(api)
    script = (
        f"id=$(curl -s --max-time 20 {api}/id); [ -z \"$id\" ] && exit 3; "
        f"for i in $(seq 1 12); do dig +short +time=3 +tries=1 $i.$id.{host} "
        ">/dev/null 2>&1; done; sleep 2; "
        f"curl -s --max-time 20 '{api}/dnsleak/test/$id?json'"
    )
    out = ""
    for _ in range(3):
        _, out = client.sh(script, timeout=120)
        try:
            data = json.loads(out)
        except (ValueError, TypeError):
            data = None
        if isinstance(data, list):
            resolvers = [e for e in data if isinstance(e, dict)
                         and e.get("type") == "dns" and e.get("ip")]
            if resolvers:
                return resolvers, out
        time.sleep(3)
    return [], out


def dns_leak(client: Client, cfg: dict) -> SubTest:
    """DNS-leak test = a real public service (dnsleaktest.com / bash.ws, via dig
    probes) for the observed resolver list, PLUS a deterministic tunnel-DNS check
    as the authoritative gate.

    In this NAT'd lab the incus bridge resolver forwards to the same public
    resolvers a VPN uses, so a public service alone can't always tell a
    local-dnsmasq leak from VPN-DNS. So: FAIL on a resolver seen in the client's
    own bridge subnet or if DNS won't resolve; PASS when the VPN-pushed DNS is on
    the tunnel iface and routes through the tunnel (clients apply it via
    base.apply_tunnel_dns) or the public service saw only non-local resolvers."""
    st = SubTest("dns-leak")
    iface, uses_pushed, via_tunnel, works, ifstatus, rg = _tunnel_dns_state(client)
    resolvers, raw = _bashws_resolvers(client, cfg)

    local_leak = [e["ip"] for e in resolvers
                  if client.bridge_net and e["ip"].startswith(client.bridge_net)]
    asns = sorted({e.get("asn", "?") for e in resolvers})
    countries = sorted({e.get("country_name", "?") for e in resolvers})
    st.log = (f"tunnel iface: {iface or '(none)'} | VPN DNS on iface: {uses_pushed} | "
              f"via tunnel: {via_tunnel} | resolves: {works}\n"
              f"route to 1.1.1.1: {rg}\n"
              f"dnsleaktest.com resolvers ({len(resolvers)}): "
              f"{[e['ip'] for e in resolvers]}\n"
              f"ASNs: {asns}\ncountries: {countries}\nraw: {raw[:800]}")

    if not works:
        st.status = Status.FAIL
        st.detail = "DNS does not resolve through the tunnel"
    elif local_leak:
        st.status = Status.FAIL
        st.detail = f"local resolver leaked (dnsleaktest.com saw {local_leak})"
    elif uses_pushed and via_tunnel:
        st.status = Status.PASS
        extra = f"; {len(resolvers)} public resolver(s) {countries}" if resolvers else ""
        st.detail = f"VPN DNS on {iface}, routed via tunnel{extra}"
    elif resolvers:
        st.status = Status.PASS
        st.detail = f"no local leak; dnsleaktest.com resolvers {countries} (ASNs {asns})"
    else:
        st.status = Status.NA
        st.detail = "inconclusive (no tunnel-DNS confirmation; leak service returned nothing)"
    return st


def _http_code(client: Client, url: str, timeout: int = 12) -> str:
    """curl's HTTP status for `url`; '000' when the connection never completed
    (blackholed / dropped / timed out)."""
    _, out = client.sh(
        f"curl -s -o /dev/null -w '%{{http_code}}' --max-time {timeout} {url}")
    return out.strip()


def _dns_count(client: Client, domain: str = "cloudflare.com") -> int:
    """Number of A records `dig` resolved through the tunnel DNS (0 = no DNS)."""
    _, out = client.sh(
        f"dig +short +time=3 +tries=1 A {domain} | grep -c '^[0-9]' || true")
    try:
        return int(out.strip().split("\n")[-1] or "0")
    except ValueError:
        return 0


def routing(freedom_client: Client, blackhole_client: Client) -> SubTest:
    """Prove source-IP routing from a CONTRAST between two clients on the same
    protocol whose ONLY difference is the routing rule: the freedom-routed client
    (A -> `direct`) reaches the internet, the blackhole-routed client (B ->
    `blocked`) is cut off. No external outbound, no exit-IP compare — the split is
    observed directly from connectivity, so it can't be fooled when the host and
    any outbound share an egress IP.

    Decisive half is the blackhole: B's tunnel is up (client-to-client ping to B
    just succeeded) yet B has NO internet and NO DNS -> Xray dropped it via the
    source rule. If routing were broken, B would fall through to the default
    `direct` outbound and reach the internet -> this FAILs, as it should."""
    st = SubTest("routing")
    # freedom (A): a couple of retries — the tproxy->xray path can be cold right
    # after connect on older kernels.
    f_http = ""
    for _ in range(4):
        f_http = _http_code(freedom_client, "https://www.google.com/generate_204", 15)
        if f_http in ("204", "200"):
            break
        time.sleep(3)
    f_dns = _dns_count(freedom_client)
    freedom_ok = f_http in ("204", "200") and f_dns > 0

    # blackhole (B): the DATA PLANE must be dead. The decisive probe is a raw-IP
    # curl (http://1.1.1.1) — no DNS involved, so a 000 there is purely "can't
    # reach the internet". https://google (needs DNS) corroborates. DNS itself is
    # NOT a gate: a resolver may still answer a name query via a cache or a B-side
    # DNS leak while every actual connection is blackholed — that's still cut off.
    b_ip = _http_code(blackhole_client, "http://1.1.1.1", 8)          # raw IP, no DNS
    b_http = _http_code(blackhole_client, "https://www.google.com/generate_204", 8)
    b_dns = _dns_count(blackhole_client)
    blackhole_ok = b_ip in ("", "000") and b_http in ("", "000")

    st.log = (f"freedom (A -> direct):  https={f_http!r} dnsA={f_dns}\n"
              f"blackhole (B -> blocked): http1.1.1.1={b_ip!r} "
              f"https={b_http!r} dnsA={b_dns} (dns not gated — leak/cache ok)")
    if freedom_ok and blackhole_ok:
        st.status = Status.PASS
        st.detail = "source-IP routing ok: A(freedom) online, B(blackhole) cut off"
    elif not blackhole_ok:
        st.status = Status.FAIL
        st.detail = (f"blackhole leaked: B reached the internet "
                     f"(http1.1.1.1={b_ip!r} https={b_http!r})")
    else:
        st.status = Status.FAIL
        st.detail = (f"freedom broke: A has no internet "
                     f"(https={f_http!r} dnsA={f_dns})")
    return st


def dns_resolve(client: Client, domain: str, name: str = "dns-resolve") -> SubTest:
    """Resolve `domain` with `dig +short` through the tunnel DNS. PASS if it
    returns at least one A record. Run per connect variant to prove tunnel DNS
    actually works on that transport/cipher, not just once for the suite."""
    st = SubTest(name)
    _, out = client.sh(f"dig +short +time=3 +tries=2 A {domain}")
    ips = [ln.strip() for ln in out.splitlines()
           if ln.strip() and ln.strip()[0].isdigit()]
    st.log = f"dig +short A {domain}:\n{out.strip() or '(empty)'}"
    if ips:
        st.status = Status.PASS
        st.detail = f"{domain} -> {', '.join(ips[:3])}"
    else:
        st.status = Status.FAIL
        st.detail = f"{domain} did not resolve through the tunnel"
    return st


def ping_peer(name: str, client: Client, peer_ip: str, must_reach: bool = True) -> SubTest:
    """client-to-client / cross-inbound reachability via ping to peer tunnel IP."""
    st = SubTest(name)
    if not peer_ip:
        st.status = Status.SKIP
        st.detail = "peer not connected"
        return st
    ok, out = client.ping(peer_ip)
    st.log = out
    if ok == must_reach:
        st.status = Status.PASS
        st.detail = f"peer {peer_ip} {'reachable' if ok else 'correctly blocked'}"
    else:
        st.status = Status.FAIL
        st.detail = f"peer {peer_ip} {'unreachable' if must_reach else 'reachable (should be blocked)'}"
    return st


def _host(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0]
