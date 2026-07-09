"""DB backup & restore E2E (pure panel API — no tunnels).

Exercises the panel's own backup/restore endpoints:
  GET  /panel/api/server/getDb    -> raw SQLite bytes (download a backup)
  POST /panel/api/server/importDB -> replace the live DB (InitDB + MigrateDB
                                     in-process) and restart Xray/daemons.

Proves restore actually REVERTS state rather than just returning 200: take a
backup, mutate the DB (add a marker account that exists ONLY after the backup),
restore, and assert the marker is gone while the pre-existing inbound survived.

Runs after bulk-ops (importDB restarts daemons, so it must not race a live
protocol test) and before the systemd phase.
"""
from __future__ import annotations

import time

from .model import SubTest, Status, PHASE_BACKUP

MARKER_EMAIL = "backup-marker@t"


def run(panel, sc, cfg: dict, result, log=None) -> None:
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_BACKUP)

    ib = None
    for p in ("openvpn", "l2tp", "pptp"):
        if p in sc.inbounds:
            ib = sc.inbounds[p]
            break
    if ib is None:
        phase.add(SubTest("backup-restore", Status.SKIP, "no inbound available"))
        log("-> backup-restore [skip] no inbound available")
        return
    iid = ib.inbound_id

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

    # Shared state threaded through the ordered subtests below.
    state = {"backup": None, "marker_added": False}

    def _download():
        db = panel.download_db()          # raises unless it's a real SQLite file
        state["backup"] = db
        return len(db) > 0, f"downloaded {len(db)} bytes (SQLite verified)", f"getDb -> {len(db)}B"

    def _add_marker():
        # A marker account that exists ONLY after the backup was captured, so a
        # correct restore must make it disappear.
        client = {"id": "backupmarker", "password": "Pw-backup-marker-9k",
                  "email": MARKER_EMAIL, "enable": True, "totalGB": 0, "expiryTime": 0}
        panel.add_client(iid, client)
        present = bool(panel.get_client(iid, MARKER_EMAIL))
        state["marker_added"] = present
        return present, f"marker present after add={present}", "added post-backup marker account"

    def _restore_reverts():
        if not state["backup"]:
            return False, "no backup captured (download failed)", ""
        if not state["marker_added"]:
            return False, "marker not created (mutate failed)", ""
        panel.import_db(state["backup"])
        # importDB swaps the DB + restarts Xray/l2tp/pptp; give the panel a moment
        # to finish InitDB + daemon restarts, then re-login (session may drop).
        time.sleep(3)
        panel.login()
        marker_gone = not panel.get_client(iid, MARKER_EMAIL)
        inbound_survived = bool(panel.get_inbound(iid))
        ok = marker_gone and inbound_survived
        return (ok,
                f"marker_gone={marker_gone} inbound_survived={inbound_survived}",
                f"post-restore: marker gone={marker_gone}, inbound {iid} present={inbound_survived}")

    log(f":: backup-restore — db download + restore-reverts on inbound {iid} ({ib.protocol})")
    subtest("db-download", _download)
    subtest("db-add-marker", _add_marker)
    subtest("db-restore-reverts", _restore_reverts)
