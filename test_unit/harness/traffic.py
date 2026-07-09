"""Account traffic-accounting E2E: usage counting + termination on limit.

Both run at the END of a protocol suite on account A (freedom-routed, so it can
reach the internet), which is disposable by then. Traffic is generated with the
Cloudflare sized-download endpoint (serves EXACTLY N bytes) through the tunnel,
and the panel's counted traffic is read back via getClientTraffics. The
accounting job (web/job/xray_traffic_job.go) runs on a 10s cron with no manual
trigger, so both tests POLL the counter/enable flag.

External-dependency failures (Cloudflare unreachable, couldn't push enough
bytes) are reported NA, not FAIL, to keep the suite honest on a flaky network.
"""
from __future__ import annotations

import time

from . import checks
from .clients.base import Client
from .model import SubTest, Status

MB = 1024 * 1024
# Large static files that support HTTP range requests, so `curl -r 0-(N-1)` pulls
# EXACTLY N bytes (204 sized-download services like speed.cloudflare.com/__down are
# now bot-blocked -> 403). Tried in order; first that delivers the range wins. All
# are >=1GB so any usage/limit amount fits. Overridable via config traffic_test.urls.
DEFAULT_URLS = [
    "https://proof.ovh.net/files/1Gb.dat",
    "https://ash-speed.hetzner.com/1GB.bin",
    "http://speedtest.tele2.net/1GB.zip",
]


def _download(client: Client, n_bytes: int, urls, timeout: int = 240):
    """Pull ~n_bytes through the tunnel via an HTTP range request (exact byte
    control). Tries each mirror until one delivers most of the range. Returns
    (size_downloaded, log)."""
    logs = []
    best = 0
    for url in urls:
        cmd = ("curl -s -o /dev/null -w '%{{size_download}} %{{http_code}}' "
               "-r 0-{end} --max-time {t} '{url}'").format(
                   end=n_bytes - 1, t=timeout, url=url)
        _, out = client.sh(cmd, timeout=timeout + 20)
        parts = out.strip().split()
        size = int(parts[0]) if parts and parts[0].isdigit() else 0
        logs.append(f"{url} -> {out.strip()}")
        best = max(best, size)
        # Accept if we got most of the requested range (the account may be disabled
        # mid-download, so don't insist on the full amount).
        if size >= n_bytes * 0.9 or size >= 10 * MB:
            return size, "\n".join(logs)
    return best, "\n".join(logs)


def _counted(panel, email):
    """(up+down bytes, raw row) for a client's counted traffic."""
    t = panel.get_client_traffics(email)
    return int(t.get("up", 0) or 0) + int(t.get("down", 0) or 0), t


def _connect_retry(connect_fn, client, tries=3):
    """Connect, retrying once after a clean teardown — a reset/limit change just
    restarted the daemon, so the first redial can race the restart (esp. pptp)."""
    clog = ""
    for _ in range(tries):
        ok, ip, clog = connect_fn()
        if ok:
            return ok, ip, clog
        client.disconnect_all()
        time.sleep(4)
    return False, "", clog


def usage(client: Client, panel, ib, cfg: dict, connect_fn, log, server_exec=None) -> SubTest:
    """Download a fixed amount through the tunnel and assert the panel counts it
    (within tolerance of the bytes actually pulled)."""
    st = SubTest("account-usage")
    tp = cfg.get("traffic_test", {}) or {}
    n = int(tp.get("usage_mb", 15)) * MB
    settle = int(tp.get("settle_timeout", 40))
    urls = tp.get("urls") or DEFAULT_URLS
    email = ib.accounts["A"].email
    log(f"-> account-usage (download {n // MB}MB on account A, expect it counted)...")
    try:
        # Clean the counter (also re-enables) BEFORE connecting: the reset handler
        # restarts the VPN daemons, which would drop a live tunnel.
        panel.reset_client_traffic(ib.inbound_id, email)
        time.sleep(6)
        ok, ip, clog = _connect_retry(connect_fn, client)
        if not ok:
            st.status, st.detail, st.log = Status.SKIP, "account A failed to connect", clog
            return st
        base, _ = _counted(panel, email)
        size, dlog = _download(client, n, urls)
        if size < n * 0.8:
            st.status = Status.NA
            st.detail = f"could not fetch {n // MB}MB through tunnel (got {size} B) — external dep"
            st.log = dlog
            return st
        # Poll for the counter to reflect the download. The accounting job folds
        # traffic in every 10s, so "settled" must be judged across >=2 whole cycles
        # (a poll interval shorter than the cycle would see two equal reads within
        # one cycle and stop early). Stop when it clearly reflects the download OR
        # hasn't grown for ~2 cycles.
        delta, last_grow, traj = 0, time.monotonic(), []
        deadline = time.monotonic() + settle + 60
        while time.monotonic() < deadline:
            cur, _ = _counted(panel, email)
            d = cur - base
            traj.append(d)
            if d > delta:
                delta, last_grow = d, time.monotonic()
            if delta >= n * 0.8:
                break
            if delta > 0 and time.monotonic() - last_grow >= 22:  # ~2 idle cycles
                break
            time.sleep(8)
        # Diagnostics: up/down split (from the DB row) + live server-side nft
        # accounting state, to root-cause under-counting (esp. pptp). The nft
        # counters reset every 10s, but the acct-chain RULES show which client IPs
        # have counters at all — bytes on an IP not in the *IPToEmail map are dropped
        # by CollectAndResetTraffic, which would explain a shortfall.
        _, frow = _counted(panel, email)
        up_b, down_b = int(frow.get("up", 0) or 0), int(frow.get("down", 0) or 0)
        diag = f"panel up={up_b} down={down_b} (client tunnel ip {ip})"
        if server_exec is not None:
            try:
                _, chains, _ = server_exec(
                    f"nft list chain ip vpn {ib.protocol}_acct 2>/dev/null; "
                    f"echo '--- counters ---'; nft list counters table ip vpn 2>/dev/null "
                    f"| grep -A1 {ib.protocol}_ | head -40")
                diag += "\n== server nft " + ib.protocol + "_acct ==\n" + chains
            except Exception as e:  # noqa: BLE001
                diag += f"\n(nft dump failed: {e})"
        # Wide tolerance: this proves counting WORKS and is roughly proportional,
        # not that it's byte-exact (encap/PPP/MPPE overhead & compression vary by
        # protocol — pptp counts a bit under, tunnels a bit over).
        lo, hi = n * 0.5, n * 3
        st.log = (diag + "\n" +
                  f"downloaded {size} B; counted delta {delta} B (baseline {base}); "
                  f"tolerance [{int(lo)}, {int(hi)}]\ncounter trajectory: {traj}\n{dlog}")
        if lo <= delta <= hi:
            st.status = Status.PASS
            st.detail = f"counted ~{delta // MB}MB for {size // MB}MB downloaded (within tolerance)"
        else:
            st.status = Status.FAIL
            st.detail = f"counted delta {delta} B out of tolerance for {size} B downloaded"
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    return st


def multi_user_total(clients, panel, ib, cfg: dict, connect_fns, log, server_exec=None) -> SubTest:
    """Prove per-account traffic AGGREGATION across multiple simultaneous devices.

    With user_limit K>1 one account owns K IPs (one per device). This connects
    N = min(K, #clients) devices ALL on the SAME account A — each on a DISTINCT
    client VM, each getting a distinct IP in A's block — then downloads M MB on
    EACH device and asserts the account's SINGLE counted delta ~= the SUM over all
    devices (not one device's share). That is the property that proves every
    device's IP folds onto the one account total, rather than being counted
    per-device or only for one device.

    `clients` and `connect_fns` are PARALLEL lists (connect_fns[i] connects
    clients[i] onto account A). NA (not FAIL) on external inability to push bytes;
    SKIP when the feature/hardware isn't there (K<2 or <2 devices come up)."""
    st = SubTest("multi-user-total")
    tp = cfg.get("traffic_test", {}) or {}
    per = int(tp.get("multi_user_mb", 8)) * MB
    settle = int(tp.get("settle_timeout", 40))
    urls = tp.get("urls") or DEFAULT_URLS
    email = ib.accounts["A"].email
    if getattr(ib, "user_limit", 1) < 2:
        st.status, st.detail = Status.SKIP, "user_limit < 2 (aggregation needs K>=2)"
        return st
    n_dev = min(int(ib.user_limit), len(clients), len(connect_fns))
    if n_dev < 2:
        st.status, st.detail = Status.SKIP, "fewer than 2 client VMs for multi-device test"
        return st
    log(f"-> multi-user-total ({n_dev} devices on account A, each pull {per // MB}MB; "
        f"expect counted delta ~= SUM across devices)...")
    try:
        # Clean the counter (also re-enables) BEFORE connecting — the reset handler
        # restarts the VPN daemons, which would drop a live tunnel.
        for c in clients[:n_dev]:
            c.disconnect_all()
        panel.reset_client_traffic(ib.inbound_id, email)
        time.sleep(6)
        # Connect each device onto the SAME account A on a DISTINCT client VM. Each
        # must come up with a working tunnel AND a distinct IP inside A's block.
        up, ips, conn_logs = [], [], []
        for idx in range(n_dev):
            client = clients[idx]
            ok, ip, clog = _connect_retry(connect_fns[idx], client)
            if ok and ip and ip not in ips:
                up.append((idx, client, ip))
                ips.append(ip)
                log(f"   device{idx + 1} up ip={ip}")
            else:
                dup = ip in ips
                conn_logs.append(f"device{idx + 1} connect (ok={ok} ip={ip!r} dup={dup})\n{clog[-300:]}")
                log(f"   device{idx + 1} not usable (ok={ok} ip={ip!r} dup={dup})")
        n_up = len(up)
        if n_up < 2:
            st.status = Status.SKIP
            st.detail = f"only {n_up} device came up on account A (need >=2)"
            st.log = f"ips={ips}\n" + "\n".join(conn_logs)
            return st
        # Baseline AFTER all devices are up, BEFORE any download.
        base, _ = _counted(panel, email)
        # Each connected device pulls M MB. Sum the bytes actually delivered.
        total_dl, dlogs = 0, []
        for idx, client, ip in up:
            size, dlog = _download(client, per, urls)
            total_dl += size
            dlogs.append(f"device{idx + 1} ip={ip} downloaded {size} B\n{dlog}")
            log(f"   device{idx + 1} ip={ip} downloaded {size} B")
        # External guard: couldn't push enough through the tunnels — NA, not FAIL.
        if total_dl < per * 0.8 * n_up:
            st.status = Status.NA
            st.detail = (f"could not push {per // MB}MB x {n_up} devices "
                         f"(got {total_dl} B total) — external dep")
            st.log = "\n".join(dlogs)
            return st
        # Poll for the counter to reflect the AGGREGATE download, same settle logic
        # as usage(): the accounting job folds every 10s, so "settled" is judged
        # across >=2 whole cycles (no growth for ~22s) or once it clearly reflects
        # the aggregate.
        delta, last_grow, traj = 0, time.monotonic(), []
        deadline = time.monotonic() + settle + 60
        while time.monotonic() < deadline:
            cur, _ = _counted(panel, email)
            d = cur - base
            traj.append(d)
            if d > delta:
                delta, last_grow = d, time.monotonic()
            if delta >= total_dl * 0.8:
                break
            if delta > 0 and time.monotonic() - last_grow >= 22:  # ~2 idle cycles
                break
            time.sleep(8)
        _, frow = _counted(panel, email)
        up_b, down_b = int(frow.get("up", 0) or 0), int(frow.get("down", 0) or 0)
        diag = f"panel up={up_b} down={down_b}"
        if server_exec is not None:
            try:
                _, chains, _ = server_exec(
                    f"nft list chain ip vpn {ib.protocol}_acct 2>/dev/null | head -40")
                diag += "\n== server nft " + ib.protocol + "_acct ==\n" + chains
            except Exception as e:  # noqa: BLE001
                diag += f"\n(nft dump failed: {e})"
        per_dev = total_dl / n_up
        # (a) wide tolerance of the aggregate, and (b) clearly ABOVE one device's
        # share — a delta ~ one device's bytes means only one device was counted
        # (aggregation broken), which must FAIL even though it's proportional.
        lo, hi = total_dl * 0.5, total_dl * 3
        agg_floor = 1.3 * per_dev
        st.log = ("\n".join(dlogs) + "\n" + diag + "\n" +
                  f"devices up: {n_up} ips={ips}\n"
                  f"total downloaded {total_dl} B (per-device ~{int(per_dev)} B); "
                  f"counted delta {delta} B (baseline {base})\n"
                  f"tolerance [{int(lo)}, {int(hi)}]; single-device floor {int(agg_floor)}\n"
                  f"counter trajectory: {traj}\n" + "\n".join(conn_logs))
        if not (lo <= delta <= hi):
            st.status = Status.FAIL
            st.detail = (f"counted delta {delta} B out of tolerance "
                         f"[{int(lo)},{int(hi)}] for {total_dl} B across {n_up} devices")
        elif delta <= agg_floor:
            st.status = Status.FAIL
            st.detail = (f"counted delta {delta} B ~ one device's share "
                         f"(~{int(per_dev)} B) — {n_up}-device aggregation NOT counted")
        else:
            st.status = Status.PASS
            st.detail = (f"account counted ~{delta // MB}MB = sum of {n_up} devices "
                         f"({total_dl // MB}MB total, ~{int(per_dev) // MB}MB each); aggregated")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    finally:
        for c in clients[:n_dev]:
            try:
                c.disconnect_all()
            except Exception:  # noqa: BLE001
                pass
    return st


def termination(client: Client, panel, ib, cfg: dict, connect_fn, log) -> SubTest:
    """Set a traffic limit, exceed it, and assert the account is auto-disabled AND
    its tunnel stops passing traffic."""
    st = SubTest("account-termination")
    tp = cfg.get("traffic_test", {}) or {}
    limit = int(tp.get("limit_mb", 100)) * MB
    over = int(tp.get("over_mb", 120)) * MB
    settle = int(tp.get("settle_timeout", 40))
    urls = tp.get("urls") or DEFAULT_URLS
    email = ib.accounts["A"].email
    log(f"-> account-termination (limit {limit // MB}MB, push {over // MB}MB, expect cut-off)...")
    try:
        panel.set_client_total(ib.inbound_id, email, limit)   # restart (disconnected)
        time.sleep(6)
        panel.reset_client_traffic(ib.inbound_id, email)      # zero + re-enable + restart
        time.sleep(6)
        ok, ip, clog = _connect_retry(connect_fn, client)
        if not ok:
            st.status, st.detail, st.log = Status.SKIP, "limited account A failed to connect", clog
            return st
        pre = checks.internet(client)
        if pre.status != Status.PASS:
            st.status, st.detail, st.log = Status.NA, "no internet before limit — cannot drive traffic", pre.log
            return st
        # Push more than the limit. The account may be auto-disabled MID-download
        # (that's the mechanism working), so curl can return < over_mb — anything
        # near/above the limit still proves the point; only a tiny fetch = external.
        size, dlog = _download(client, over, urls)
        if size < 10 * MB:
            st.status = Status.NA
            st.detail = f"could not push traffic through tunnel (got {size} B) — external dep"
            st.log = dlog
            return st
        # Poll for the auto-disable (accounting job every 10s; allow extra margin).
        disabled = False
        row = {}
        deadline = time.monotonic() + settle + 25
        while time.monotonic() < deadline:
            _, row = _counted(panel, email)
            if not bool(row.get("enable", True)):
                disabled = True
                break
            time.sleep(4)
        used = int(row.get("up", 0) or 0) + int(row.get("down", 0) or 0)
        if not disabled:
            # Didn't disable. If we never actually exceeded the counted limit, the
            # link was just too slow (external) — NA; otherwise it's a real FAIL.
            if used < limit:
                st.status = Status.NA
                st.detail = f"couldn't drive enough traffic to exceed {limit // MB}MB (counted {used} B)"
            else:
                st.status = Status.FAIL
                st.detail = f"account NOT disabled despite counted {used} B over a {limit // MB}MB limit"
            st.log = f"limit={limit} B downloaded={size} B counted={used} enable={row.get('enable')}\n{dlog}"
            return st
        # Disabled in the DB. "account stopped working" is NOT "no internet" — when
        # the tunnel drops the client just falls back to its direct route and still
        # reaches the internet. The real proof is that the disabled account can no
        # longer USE the VPN: a fresh connect must fail to establish a working tunnel
        # (RADIUS Access-Reject for l2tp/pptp; openvpn connect-hook rejects the lease
        # / regenerated config drops it). Give the job a cycle to kill+regen first.
        time.sleep(10)
        client.disconnect_all()
        time.sleep(4)
        ok_re, ip_re, relog = connect_fn()          # expect failure — no retry
        reworks = False
        if ok_re and ip_re:
            net = checks.internet(client)           # connected? does it actually pass traffic?
            reworks = net.status == Status.PASS
        client.disconnect_all()
        st.log = (f"limit={limit} B downloaded={size} B counted up+down={used} "
                  f"enable={row.get('enable')}\nreconnect: ok={ok_re} ip={ip_re!r} "
                  f"works_through_tunnel={reworks}\n{relog[-400:]}\n{dlog}")
        if not reworks:
            st.status = Status.PASS
            st.detail = f"account disabled after exceeding {limit // MB}MB; can no longer connect/use the VPN"
        else:
            st.status = Status.FAIL
            st.detail = "account disabled but still reconnected with a working tunnel (not enforced)"
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    return st
