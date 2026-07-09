"""HTTP client for the vpn-ui panel.

Grounded in the actual controllers:
  - Auth: POST /login (form), server-side session, cookie "vpn-ui". Reuse jar.
  - All POST handlers bind via c.ShouldBind / c.PostForm -> send
    application/x-www-form-urlencoded, NOT JSON.
  - Response envelope: {"success":bool,"msg":str,"obj":any}. Data in "obj".
  - Paths are prefixed by webBasePath (default "/").
"""
from __future__ import annotations

import json
import time

import requests

from . import abort


class PanelError(RuntimeError):
    pass


class Panel:
    def __init__(self, host: str, port: int = 2083, base_path: str = "/",
                 scheme: str = "http", username: str = "admin",
                 password: str = "admin", timeout: int = 30):
        bp = base_path if base_path.startswith("/") else "/" + base_path
        if not bp.endswith("/"):
            bp += "/"
        self.host = host
        self.port = port
        self.scheme = scheme
        self._bp = bp
        self.root = f"{scheme}://{host}:{port}{bp}".rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.s = requests.Session()

    def set_host(self, host: str):
        """Repoint at a new host (e.g. after a reboot changed the DHCP lease)."""
        self.host = host
        self.root = f"{self.scheme}://{host}:{self.port}{self._bp}".rstrip("/")

    # ---- low level ------------------------------------------------------
    def _url(self, path: str) -> str:
        return f"{self.root}/{path.lstrip('/')}"

    def _post(self, path: str, data: dict) -> dict:
        # Surface transport failures (a dead/OOM-killed panel -> ConnectionError,
        # a hung one -> Timeout) as PanelError, which every caller already handles.
        # Otherwise a raw requests exception escapes to the orchestrator as a hard
        # ERROR even when the caller means to degrade gracefully (e.g. warp NA).
        try:
            r = self.s.post(self._url(path), data=data, timeout=self.timeout)
        except requests.RequestException as e:
            raise PanelError(f"{path} -> transport error: {e}") from e
        return self._envelope(r, path)

    def _get(self, path: str) -> dict:
        try:
            r = self.s.get(self._url(path), timeout=self.timeout)
        except requests.RequestException as e:
            raise PanelError(f"{path} -> transport error: {e}") from e
        return self._envelope(r, path)

    def _envelope(self, r: requests.Response, path: str) -> dict:
        if r.status_code == 404:
            raise PanelError(f"{path} -> 404 (not logged in, or wrong base_path)")
        try:
            body = r.json()
        except ValueError:
            raise PanelError(f"{path} -> non-JSON ({r.status_code}): {r.text[:200]}")
        if not body.get("success", False):
            raise PanelError(f"{path} failed: {body.get('msg')}")
        return body

    # ---- connectivity / auth -------------------------------------------
    def wait_up(self, timeout: int):
        """Wait until the panel answers (login page reachable)."""
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            if abort.is_set():
                raise PanelError("aborted while waiting for panel (Ctrl+C)")
            try:
                r = self.s.get(self._url("/"), timeout=5)
                if r.status_code < 500:
                    return
            except requests.RequestException as e:
                last = str(e)
            time.sleep(2)
        raise PanelError(f"panel not reachable at {self.root} in {timeout}s: {last}")

    def login(self):
        body = self._post("/login", {
            "username": self.username,
            "password": self.password,
        })
        return body

    # ---- provisioning (core-init) --------------------------------------
    def provision_start(self) -> dict:
        return self._post("/panel/core/provision", {}).get("obj", {})

    def provision_status(self) -> dict:
        return self._get("/panel/core/provision-status").get("obj", {})

    def reboot(self):
        # Fire and forget; the machine goes down. Ignore transport errors.
        try:
            self._post("/panel/core/reboot", {})
        except (PanelError, requests.RequestException):
            pass

    def core_status(self) -> dict:
        return self._get("/panel/core/status").get("obj", {})

    def core(self, name: str) -> dict:
        """One core's status dict from /panel/core/status ({} if absent). Each has
        name/state/version/inbounds/detail. IPsec is its own core named "ipsec"
        (state=running -> ipsec.service active; state=not_installed -> no libreswan)."""
        for c in self.core_status().get("cores", []) or []:
            if c.get("name") == name:
                return c
        return {}

    def core_logs(self, core: str) -> str:
        return self._get(f"/panel/core/logs/{core}").get("obj", "") or ""

    def restart_core(self, core: str):
        self._post(f"/panel/core/restart/{core}", {})

    def stop_core(self, core: str):
        self._post(f"/panel/core/stop/{core}", {})

    # ---- inbounds / clients --------------------------------------------
    def add_inbound(self, remark: str, port: int, protocol: str,
                    settings: dict, listen: str = "") -> dict:
        """Create an inbound. Returns the created inbound dict (has 'id')."""
        body = self._post("/panel/api/inbounds/add", {
            "remark": remark,
            "enable": "true",
            "listen": listen,
            "port": str(port),
            "protocol": protocol,
            "settings": json.dumps(settings),
            "streamSettings": "{}",
            "sniffing": "{}",
        })
        return body.get("obj", {})

    def get_inbound(self, inbound_id: int) -> dict:
        return self._get(f"/panel/api/inbounds/get/{inbound_id}").get("obj", {})

    def list_inbounds(self) -> list:
        return self._get("/panel/api/inbounds/list").get("obj", []) or []

    def update_inbound(self, inbound_id: int, remark: str, port: int,
                       protocol: str, settings: dict, listen: str = "") -> dict:
        return self._post(f"/panel/api/inbounds/update/{inbound_id}", {
            "id": str(inbound_id),
            "remark": remark,
            "enable": "true",
            "listen": listen,
            "port": str(port),
            "protocol": protocol,
            "settings": json.dumps(settings),
            "streamSettings": "{}",
            "sniffing": "{}",
        }).get("obj", {})

    def set_user_limit_strategy(self, inbound_id: int, strategy: str):
        """Flip an existing inbound's User Limit Strategy ('reject'/'accept') in
        place, preserving every other setting. Re-saving triggers the panel's
        on<Proto>Changed hook: GenerateAllConfigs (rewrites the openvpn
        strategy-<proto> file / blocks) + RestartServices (daemon restart = clean
        slate). L2TP/PPTP additionally read the strategy live from the DB per auth."""
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        settings["userLimitStrategy"] = strategy
        self.update_inbound(
            inbound_id,
            ib.get("remark", ""),
            ib.get("port", 0),
            ib.get("protocol", ""),
            settings,
            ib.get("listen", "") or "",
        )

    def add_client(self, inbound_id: int, client: dict):
        """Add one client (username/password account) to an inbound."""
        self._post("/panel/api/inbounds/addClient", {
            "id": str(inbound_id),
            "settings": json.dumps({"clients": [client]}),
        })

    def del_inbound(self, inbound_id: int):
        """Delete an inbound by id (POST /panel/api/inbounds/del/:id). Triggers the
        on<Proto>Changed hook -> config regen + daemon restart, so call while no
        client is connected to it."""
        self._post(f"/panel/api/inbounds/del/{inbound_id}", {})

    # ---- traffic + bulk (E2E test support) -----------------------------
    def get_client_traffics(self, email: str) -> dict:
        """Per-client counted traffic row: {up, down, total, enable, expiryTime,…}
        (bytes). Empty dict if the client has no traffic row yet."""
        return self._get(f"/panel/api/inbounds/getClientTraffics/{email}").get("obj", {}) or {}

    def reset_client_traffic(self, inbound_id: int, email: str):
        """Zero a client's counted up/down (also re-enables it). NOTE the handler
        also fires the on<Proto>Changed hooks -> VPN daemons restart, so call this
        while the client is DISCONNECTED."""
        self._post(f"/panel/api/inbounds/{inbound_id}/resetClientTraffic/{email}", {})

    def set_client_total(self, inbound_id: int, email: str, total_bytes: int):
        """Set one client's traffic limit (totalGB, in BYTES) + ensure enabled.
        Uses the updateClient endpoint (NOT a whole-inbound update) so the panel
        runs UpdateClientStat and syncs client_traffics.total — the enforcement
        table the auto-disable check reads. Restarts the daemon, so call while
        disconnected."""
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        target = None
        for c in settings.get("clients", []):
            if c.get("email") == email:
                target = dict(c)
                break
        if target is None:
            raise PanelError(f"client {email} not found on inbound {inbound_id}")
        target["totalGB"] = int(total_bytes)
        target["enable"] = True
        proto = ib.get("protocol", "")
        # UpdateInboundClient matches clientId by password for l2tp/pptp/openvpn/trojan.
        if proto in ("l2tp", "pptp", "openvpn", "trojan"):
            client_id = target.get("password", "")
        elif proto == "shadowsocks":
            client_id = target.get("email", "")
        else:
            client_id = target.get("id", "") or target.get("email", "")
        self._post(f"/panel/api/inbounds/updateClient/{client_id}", {
            "id": str(inbound_id),
            "remark": ib.get("remark", ""),
            "enable": "true",
            "listen": ib.get("listen", "") or "",
            "port": str(ib.get("port", 0)),
            "protocol": proto,
            "settings": json.dumps({"clients": [target]}),
            "streamSettings": "{}",
            "sniffing": "{}",
        })

    def bulk_update_clients(self, payload: dict) -> dict:
        """POST the bulk client op (form field data=JSON string, matching the panel
        axios convention). Returns {applied, skipped}."""
        return self._post("/panel/api/inbounds/bulkUpdateClients",
                          {"data": json.dumps(payload)}).get("obj", {}) or {}

    def get_client(self, inbound_id: int, email: str) -> dict:
        """Read one client's settings dict (totalGB/expiryTime/enable/…) by email."""
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        for c in settings.get("clients", []):
            if c.get("email") == email:
                return c
        return {}

    def generate_openvpn_certs(self) -> dict:
        """Returns {caCert,caKey,serverCert,serverKey,tlsCrypt}."""
        return self._post("/panel/api/inbounds/generate-openvpn-certs", {}).get("obj", {})

    def download_ovpn(self, inbound_id: int, proto: str) -> str:
        """proto in {udp,tcp}. Returns raw .ovpn text."""
        r = self.s.get(self._url(f"/panel/api/inbounds/{inbound_id}/ovpn/{proto}"),
                       timeout=self.timeout)
        if r.status_code != 200 or "openvpn" not in r.headers.get(
                "Content-Type", "") and "client" not in r.text[:20].lower():
            # controller returns the file directly; on error it returns the JSON envelope
            try:
                body = r.json()
                raise PanelError(f"ovpn export failed: {body.get('msg')}")
            except ValueError:
                pass
        return r.text

    # ---- xray outbound + routing ---------------------------------------
    def get_xray_template(self) -> dict:
        """Return the parsed Xray config template (dict with outbounds, routing…)."""
        body = self._post("/panel/xray/", {})
        obj = body.get("obj")
        # obj is a JSON string: {"xraySetting":<obj>, "inboundTags":..., ...}
        if isinstance(obj, str):
            obj = json.loads(obj)
        setting = obj.get("xraySetting")
        if isinstance(setting, str):
            setting = json.loads(setting)
        return setting

    def update_xray_template(self, template: dict):
        self._post("/panel/xray/update", {
            "xraySetting": json.dumps(template),
        })

    def get_config_json(self) -> dict:
        """The fully merged runtime Xray config (routing rules already translated
        from user-email to source-IP). Used to assert the translation happened."""
        body = self._get("/panel/api/server/getConfigJson")
        obj = body.get("obj")
        if isinstance(obj, str):
            obj = json.loads(obj)
        return obj

    # ---- Cloudflare warp-cli SOCKS5 (E2E test support) -----------------
    # POST /panel/xray/warpsocks/:action. install/uninstall kick off a
    # background run and return the initial state; the caller then polls
    # "state" for the live log. The install feeds the SOCKS5 port via the
    # `port` form field (the backend forwards it as WARP_SOCKS_PORT).
    def warpsocks_installed(self) -> bool:
        return bool(self._post("/panel/xray/warpsocks/installed", {})
                    .get("obj", {}).get("installed", False))

    def warpsocks_start(self, action: str, port: int = 0) -> dict:
        """action in {install, uninstall}. Returns the initial run state dict
        {running,done,success,action,log}."""
        data = {"port": str(port)} if action == "install" else {}
        return self._post(f"/panel/xray/warpsocks/{action}", data).get("obj", {}) or {}

    def warpsocks_state(self) -> dict:
        """Snapshot of the current/most-recent warp-cli run: {running,done,
        success,action,log}."""
        return self._post("/panel/xray/warpsocks/state", {}).get("obj", {}) or {}

    # ---- db backup / restore (E2E test support) ------------------------
    def download_db(self) -> bytes:
        """GET /panel/api/server/getDb -> the raw SQLite file bytes (an
        octet-stream attachment, NOT the JSON envelope). Asserts the SQLite magic
        so an HTML/JSON error page can't masquerade as a valid backup."""
        r = self.s.get(self._url("/panel/api/server/getDb"), timeout=self.timeout)
        if r.status_code != 200:
            raise PanelError(f"getDb -> HTTP {r.status_code}: {r.text[:200]}")
        if not r.content.startswith(b"SQLite format 3\x00"):
            raise PanelError(
                f"getDb did not return a SQLite db (first bytes: {r.content[:16]!r})")
        return r.content

    def import_db(self, db_bytes: bytes) -> dict:
        """POST /panel/api/server/importDB (multipart, form field name 'db').
        Replaces the live DB (InitDB + MigrateDB in-process) and restarts Xray;
        returns the JSON envelope. Re-login afterwards — the swap may drop the
        server-side session."""
        r = self.s.post(
            self._url("/panel/api/server/importDB"),
            files={"db": ("x-ui.db", db_bytes, "application/octet-stream")},
            timeout=self.timeout,
        )
        return self._envelope(r, "/panel/api/server/importDB")
