"""Bulk client operations E2E (pure panel API — no tunnels).

Exercises POST /panel/api/inbounds/bulkUpdateClients: every operation
(add/subtract days, add/subtract traffic, enable, disable) plus each skip toggle
(start-after-first-use, unlimited, disabled) tested INDIVIDUALLY. Each subtest
creates fresh accounts in a known state on an existing inbound, fires one bulk
call, reads the clients back, and asserts the resulting fields.

Runs once per distro AFTER the protocol suites (the bulk regen restarts the VPN
daemons, so it must not race a live protocol test). Targets only its own
`bulk_*` accounts, leaving the protocol A/B accounts untouched.
"""
from __future__ import annotations

import time

from .model import SubTest, Status, PHASE_BULK

DAY = 86400000          # ms per day (matches Go bulkMsPerDay)
GB = 1024 * 1024 * 1024
MB = 1024 * 1024


def run(panel, sc, cfg: dict, result, log=None) -> None:
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_BULK)

    ib = None
    for p in ("openvpn", "l2tp", "pptp"):
        if p in sc.inbounds:
            ib = sc.inbounds[p]
            break
    if ib is None:
        phase.add(SubTest("bulk-ops", Status.SKIP, "no inbound available"))
        log("-> bulk-ops [skip] no inbound available")
        return
    iid = ib.inbound_id
    # A fixed base time (unix ms, second-aligned) so add/subtract day math is exact
    # and reproducible; the same `now` is used to build inputs and expected outputs.
    now = int(time.time()) * 1000
    seq = {"n": 0}

    def mk(state: dict) -> str:
        """Create a fresh bulk-test account in the given field state; return email."""
        seq["n"] += 1
        email = f"bulk{seq['n']}@t"
        client = {"id": f"bulku{seq['n']}", "password": f"Pw-bulk{seq['n']}-9k",
                  "email": email, "enable": True, "totalGB": 0, "expiryTime": 0}
        client.update(state)
        panel.add_client(iid, client)
        return email

    def expiry(email: str) -> int:
        return int(panel.get_client(iid, email).get("expiryTime", 0) or 0)

    def total(email: str) -> int:
        return int(panel.get_client(iid, email).get("totalGB", 0) or 0)

    def enabled(email: str) -> bool:
        return bool(panel.get_client(iid, email).get("enable", False))

    def targets(*emails):
        return [{"inboundId": iid, "email": e} for e in emails]

    def subtest(name: str, body):
        st = phase.add(SubTest(name))
        try:
            ok, detail, logtxt = body()
            st.status = Status.PASS if ok else Status.FAIL
            st.detail = detail
            st.log = logtxt
        except Exception as e:  # noqa: BLE001
            st.status, st.detail = Status.ERROR, str(e)[:200]
        log(f"-> {st.name} [{st.status.value}] {st.detail}")

    # ---- operations ----------------------------------------------------
    def _add_days():
        e = mk({"expiryTime": now + 10 * DAY})
        panel.bulk_update_clients({"op": "addDays", "days": 5, "targets": targets(e)})
        got, want = expiry(e), now + 15 * DAY
        return got == want, f"expiry {got} want {want}", f"addDays 5 on now+10d -> {got}"

    def _sub_days():
        e = mk({"expiryTime": now + 10 * DAY})
        panel.bulk_update_clients({"op": "subDays", "days": 3, "targets": targets(e)})
        got, want = expiry(e), now + 7 * DAY
        return got == want, f"expiry {got} want {want}", f"subDays 3 on now+10d -> {got}"

    def _add_traffic():
        e = mk({"totalGB": 1 * GB})
        panel.bulk_update_clients({"op": "addTraffic", "amountBytes": 5 * MB, "targets": targets(e)})
        got, want = total(e), 1 * GB + 5 * MB
        return got == want, f"totalGB {got} want {want}", f"addTraffic 5MB on 1GB -> {got}"

    def _sub_traffic_floor():
        e = mk({"totalGB": 50 * MB})
        # Subtract far more than present: must floor at 1 byte, NOT 0 (0 = unlimited).
        panel.bulk_update_clients({"op": "subTraffic", "amountBytes": 999 * GB, "targets": targets(e)})
        got = total(e)
        return got == 1, f"totalGB {got} want 1 (floored, not 0=unlimited)", f"subTraffic huge on 50MB -> {got}"

    def _enable():
        e = mk({"enable": False})
        panel.bulk_update_clients({"op": "enable", "targets": targets(e)})
        return enabled(e) is True, f"enable={enabled(e)} want True", "enable on disabled acct"

    def _disable():
        e = mk({"enable": True})
        panel.bulk_update_clients({"op": "disable", "targets": targets(e)})
        return enabled(e) is False, f"enable={enabled(e)} want False", "disable on enabled acct"

    # ---- skip toggles (each individually) ------------------------------
    def _skip_first_use():
        delayed = mk({"expiryTime": -3 * DAY})           # start-after-first-use
        normal = mk({"expiryTime": now + 10 * DAY})
        panel.bulk_update_clients({"op": "addDays", "days": 5, "skipFirstUse": True,
                                   "targets": targets(delayed, normal)})
        d_ok = expiry(delayed) == -3 * DAY               # untouched
        n_ok = expiry(normal) == now + 15 * DAY          # changed
        return (d_ok and n_ok,
                f"delayed_unchanged={d_ok} normal_changed={n_ok}",
                f"delayed {expiry(delayed)} (want {-3*DAY}); normal {expiry(normal)} (want {now+15*DAY})")

    def _skip_unlimited():
        unlim = mk({"totalGB": 0})                        # unlimited traffic
        lim = mk({"totalGB": 1 * GB})
        panel.bulk_update_clients({"op": "addTraffic", "amountBytes": 5 * MB, "skipUnlimited": True,
                                   "targets": targets(unlim, lim)})
        u_ok = total(unlim) == 0                          # untouched
        l_ok = total(lim) == 1 * GB + 5 * MB              # changed
        return (u_ok and l_ok,
                f"unlimited_unchanged={u_ok} limited_changed={l_ok}",
                f"unlim {total(unlim)} (want 0); lim {total(lim)} (want {1*GB+5*MB})")

    # ---- enforcement sync (client_traffics, not just settings) ---------
    def _enforced_total_sync():
        # AddClientStat sets client_traffics.total=100MB at creation; a bulk
        # addTraffic must propagate to that enforcement row, not just settings.
        e = mk({"totalGB": 100 * MB})
        panel.bulk_update_clients({"op": "addTraffic", "amountBytes": 50 * MB, "targets": targets(e)})
        got = int(panel.get_client_traffics(e).get("total", 0) or 0)
        want = 150 * MB
        return got == want, f"client_traffics.total {got} want {want}", f"getClientTraffics.total={got} (enforced value)"

    def _skip_disabled():
        dis = mk({"enable": False, "expiryTime": now + 10 * DAY})
        en = mk({"enable": True, "expiryTime": now + 10 * DAY})
        panel.bulk_update_clients({"op": "addDays", "days": 5, "skipDisabled": True,
                                   "targets": targets(dis, en)})
        d_ok = expiry(dis) == now + 10 * DAY              # untouched
        e_ok = expiry(en) == now + 15 * DAY               # changed
        return (d_ok and e_ok,
                f"disabled_unchanged={d_ok} enabled_changed={e_ok}",
                f"disabled {expiry(dis)} (want {now+10*DAY}); enabled {expiry(en)} (want {now+15*DAY})")

    log(f":: bulk-ops — bulk client operations on inbound {iid} ({ib.protocol})")
    subtest("bulk-add-days", _add_days)
    subtest("bulk-sub-days", _sub_days)
    subtest("bulk-add-traffic", _add_traffic)
    subtest("bulk-sub-traffic-floor", _sub_traffic_floor)
    subtest("bulk-enable", _enable)
    subtest("bulk-disable", _disable)
    subtest("bulk-enforced-total-sync", _enforced_total_sync)
    subtest("bulk-skip-first-use", _skip_first_use)
    subtest("bulk-skip-unlimited", _skip_unlimited)
    subtest("bulk-skip-disabled", _skip_disabled)
