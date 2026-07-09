"""Result model shared across the harness.

A run produces one JobResult per server distro. Each JobResult holds an ordered
list of Phases; each Phase holds SubTests. Everything serialises to plain dicts
for the JSON report; the HTML report renders the same structure.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"   # deliberately not run (e.g. dependency of a failed step)
    NA = "na"       # not applicable / external dependency unavailable
    ERROR = "error" # harness/infra blew up (not a product failure)


def worst(statuses) -> Status:
    """Roll a collection of statuses up to a single verdict.

    Precedence: ERROR > FAIL > PASS > NA > SKIP. Crucially PASS outranks NA/SKIP,
    so an otherwise-green phase with one inconclusive check (e.g. a flaky
    external dns-leak service = NA) still rolls up to PASS rather than being
    dragged down. NA/SKIP only surface when nothing actually passed."""
    seen = {Status(s) for s in statuses}
    if not seen:
        return Status.SKIP
    for level in (Status.ERROR, Status.FAIL, Status.PASS, Status.NA, Status.SKIP):
        if level in seen:
            return level
    return Status.SKIP


@dataclass
class SubTest:
    name: str
    status: Status = Status.SKIP
    detail: str = ""          # one-line human summary
    log: str = ""             # full captured output for the drilldown
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Phase:
    name: str
    subtests: list = field(default_factory=list)

    def add(self, sub: SubTest) -> SubTest:
        self.subtests.append(sub)
        return sub

    @property
    def status(self) -> Status:
        return worst(s.status for s in self.subtests)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "subtests": [s.to_dict() for s in self.subtests],
        }


@dataclass
class JobResult:
    distro: str
    image: str
    phases: list = field(default_factory=list)
    started_at: str = ""      # ISO8601, stamped by orchestrator
    finished_at: str = ""
    server_ip: str = ""
    notes: str = ""           # infra-level message (e.g. "image not found -> skipped")

    def phase(self, name: str) -> Phase:
        """Get-or-create a phase by name, preserving insertion order."""
        for p in self.phases:
            if p.name == name:
                return p
        p = Phase(name)
        self.phases.append(p)
        return p

    @property
    def status(self) -> Status:
        return worst(p.status for p in self.phases)

    def to_dict(self) -> dict:
        return {
            "distro": self.distro,
            "image": self.image,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "server_ip": self.server_ip,
            "notes": self.notes,
            "phases": [p.to_dict() for p in self.phases],
        }


# Canonical phase names (kept stable so the report columns line up).
PHASE_CORE = "core-init"
PHASE_SETUP = "server-setup"
PHASE_OPENVPN = "openvpn"
PHASE_L2TP = "l2tp"
PHASE_PPTP = "pptp"
PHASE_BULK = "bulk-ops"
PHASE_BACKUP = "backup-restore"
PHASE_WARP = "warp-socks"
PHASE_RANDOM = "random-cfg"
PHASE_SYSTEMD = "systemd"
PHASE_UNINSTALL = "uninstall"

ALL_PHASES = [PHASE_CORE, PHASE_SETUP, PHASE_OPENVPN, PHASE_L2TP, PHASE_PPTP,
              PHASE_BULK, PHASE_BACKUP, PHASE_WARP, PHASE_RANDOM, PHASE_SYSTEMD,
              PHASE_UNINSTALL]
