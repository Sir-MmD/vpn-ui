"""Parse an Xray share link into an Xray *outbound* object + its dial endpoint.

Supported schemes: vless:// · vmess:// · ss:// (shadowsocks) · trojan://.
Covers the common transports (tcp/ws/grpc/http-h2) and securities
(none/tls/reality) — enough to route the test's probe traffic through an
arbitrary user-supplied node dropped into run.sh.

parse_link() returns:
  {
    "outbound":  <full xray outbound dict, ready to append to outbounds[]>,
    "address":   <dial host>,      # for the reachability preflight
    "port":      <dial port int>,
    "protocol":  "vless"|"vmess"|"shadowsocks"|"trojan",
    "name":      <label from the link fragment, may be "">,
  }
"""
from __future__ import annotations

import base64
import binascii
import json
from urllib.parse import urlparse, parse_qs, unquote


class LinkError(ValueError):
    """Raised on a malformed / unsupported share link."""


def parse_link(link: str) -> dict:
    link = (link or "").strip()
    if "://" not in link:
        raise LinkError("not an xray share link (no scheme://)")
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vless":
        return _vless(link)
    if scheme == "vmess":
        return _vmess(link)
    if scheme in ("ss", "shadowsocks"):
        return _ss(link)
    if scheme == "trojan":
        return _trojan(link)
    raise LinkError(f"unsupported scheme '{scheme}://' (want vless/vmess/ss/trojan)")


# --------------------------------------------------------------------- helpers
def _q(q: dict, key: str, default: str = "") -> str:
    v = q.get(key)
    return v[0] if v else default


def _b64(s: str) -> str:
    """Decode std/url-safe base64 with optional missing padding."""
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def _split_hostport(hp: str) -> tuple[str, str]:
    hp = hp.strip().rstrip("/")
    if hp.startswith("["):                      # [ipv6]:port
        host, _, rest = hp[1:].partition("]")
        return host, rest.lstrip(":")
    host, _, port = hp.rpartition(":")
    return host, port


def _stream(net: str, security: str, q: dict) -> dict:
    """Build streamSettings from a query-param dict (parse_qs form)."""
    net = net or "tcp"
    if net == "h2":
        net = "http"
    ss = {"network": net, "security": security or "none"}

    host = _q(q, "host")
    path = _q(q, "path")
    sni = _q(q, "sni") or _q(q, "peer")
    fp = _q(q, "fp")

    if net == "ws":
        ws = {}
        if path:
            ws["path"] = path
        if host:
            ws["headers"] = {"Host": host}
        ss["wsSettings"] = ws
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": _q(q, "serviceName") or path}
    elif net == "http":
        h = {}
        if path:
            h["path"] = path
        if host:
            h["host"] = [host]
        ss["httpSettings"] = h
    else:  # tcp
        if _q(q, "headerType") == "http":
            req = {}
            if path:
                req["path"] = [path]
            if host:
                req["headers"] = {"Host": [host]}
            hdr = {"type": "http"}
            if req:
                hdr["request"] = req
            ss["tcpSettings"] = {"header": hdr}
        else:
            ss["tcpSettings"] = {"header": {"type": "none"}}

    if security == "tls":
        tls = {}
        if sni:
            tls["serverName"] = sni
        if fp:
            tls["fingerprint"] = fp
        alpn = _q(q, "alpn")
        if alpn:
            tls["alpn"] = alpn.split(",")
        if _q(q, "allowInsecure") in ("1", "true"):
            tls["allowInsecure"] = True
        ss["tlsSettings"] = tls
    elif security == "reality":
        r = {}
        if sni:
            r["serverName"] = sni
        if fp:
            r["fingerprint"] = fp
        for k_link, k_xray in (("pbk", "publicKey"), ("sid", "shortId"),
                               ("spx", "spiderX")):
            val = _q(q, k_link)
            if val:
                r[k_xray] = val
        ss["realitySettings"] = r
    return ss


# --------------------------------------------------------------------- parsers
def _vless(link: str) -> dict:
    u = urlparse(link)
    uid = unquote(u.username or "")
    host, port = u.hostname, u.port
    if not (uid and host and port):
        raise LinkError("vless: missing id/host/port")
    q = parse_qs(u.query)
    user = {"id": uid, "encryption": _q(q, "encryption") or "none"}
    flow = _q(q, "flow")
    if flow:
        user["flow"] = flow
    name = unquote(u.fragment or "")
    ob = {
        "tag": name or "ext-out",
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": _stream(_q(q, "type"), _q(q, "security") or "none", q),
    }
    return {"outbound": ob, "address": host, "port": int(port),
            "protocol": "vless", "name": name}


def _vmess(link: str) -> dict:
    raw = link.split("://", 1)[1].split("#", 1)[0]
    try:
        obj = json.loads(_b64(raw))
    except (ValueError, binascii.Error) as e:
        raise LinkError(f"vmess: bad base64/json: {e}")
    host, uid = obj.get("add"), obj.get("id")
    try:
        port = int(obj.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    if not (host and port and uid):
        raise LinkError("vmess: missing add/port/id")
    net = obj.get("net") or "tcp"
    security = "tls" if (obj.get("tls") or "none") in ("tls", "reality") else "none"
    # re-shape vmess fields into the query form _stream() expects
    q = {}
    if obj.get("host"):
        q["host"] = [obj["host"]]
    if obj.get("path"):
        q["path"] = [obj["path"]]
    if obj.get("sni"):
        q["sni"] = [obj["sni"]]
    if obj.get("type"):
        q["headerType"] = [obj["type"]]        # tcp header type (http/none)
    if net == "grpc" and obj.get("path"):
        q["serviceName"] = [obj["path"]]
    try:
        aid = int(obj.get("aid", 0) or 0)
    except (TypeError, ValueError):
        aid = 0
    user = {"id": uid, "alterId": aid, "security": obj.get("scy") or "auto"}
    name = obj.get("ps") or ""
    ob = {
        "tag": name or "ext-out",
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": _stream(net, security, q),
    }
    return {"outbound": ob, "address": host, "port": port,
            "protocol": "vmess", "name": name}


def _ss(link: str) -> dict:
    body = link.split("://", 1)[1]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = unquote(frag)
    if "?" in body:                              # drop SIP002 plugin query
        body = body.split("?", 1)[0]
    method = password = host = None
    port = None
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:                                     # base64(method:password)
            dec = _b64(userinfo)
            if ":" in dec:
                method, password = dec.split(":", 1)
        except (ValueError, binascii.Error):
            pass
        if method is None and ":" in userinfo:   # plain method:password
            method, password = unquote(userinfo).split(":", 1)
        host, port = _split_hostport(hostport)
    else:                                        # base64(method:pass@host:port)
        dec = _b64(body)
        creds, hostport = dec.rsplit("@", 1)
        method, password = creds.split(":", 1)
        host, port = _split_hostport(hostport)
    if not (method and host and port):
        raise LinkError("ss: missing method/host/port")
    ob = {
        "tag": name or "ext-out",
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": host, "port": int(port),
            "method": method, "password": password or "",
        }]},
    }
    return {"outbound": ob, "address": host, "port": int(port),
            "protocol": "shadowsocks", "name": name}


def _trojan(link: str) -> dict:
    u = urlparse(link)
    password = unquote(u.username or "")
    host, port = u.hostname, u.port
    if not (password and host and port):
        raise LinkError("trojan: missing password/host/port")
    q = parse_qs(u.query)
    name = unquote(u.fragment or "")
    ob = {
        "tag": name or "ext-out",
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port,
                                  "password": password}]},
        # trojan is TLS by default unless the link says otherwise
        "streamSettings": _stream(_q(q, "type"), _q(q, "security") or "tls", q),
    }
    return {"outbound": ob, "address": host, "port": int(port),
            "protocol": "trojan", "name": name}
