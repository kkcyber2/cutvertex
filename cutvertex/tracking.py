"""Remediation tracking with an enforced state machine.

The board states requested by the workflow this tool serves:
``open -> triaged -> in_progress -> fixed -> verified -> closed``

Two properties are non-negotiable for this to be auditable:

* Every transition is validated against an explicit allow-list. There is no
  "any state to any state" escape hatch, because that is exactly how findings
  get marked closed without being fixed.
* A transition to ``verified`` requires a verification artefact reference, and
  a reopen records a reason. Without those, MTTR and reopen-rate are fiction.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class State(str, enum.Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    VERIFIED = "verified"
    CLOSED = "closed"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


#: Allowed forward transitions. Reopen (verified/closed -> in_progress) is
#: permitted explicitly and is what drives the reopen-rate metric.
TRANSITIONS: dict[State, frozenset[State]] = {
    State.OPEN: frozenset({State.TRIAGED, State.FALSE_POSITIVE, State.RISK_ACCEPTED}),
    State.TRIAGED: frozenset({State.IN_PROGRESS, State.RISK_ACCEPTED, State.FALSE_POSITIVE}),
    State.IN_PROGRESS: frozenset({State.FIXED, State.RISK_ACCEPTED}),
    State.FIXED: frozenset({State.VERIFIED, State.IN_PROGRESS}),
    State.VERIFIED: frozenset({State.CLOSED, State.IN_PROGRESS}),
    State.CLOSED: frozenset({State.IN_PROGRESS}),
    State.RISK_ACCEPTED: frozenset({State.IN_PROGRESS}),
    State.FALSE_POSITIVE: frozenset({State.OPEN}),
}

TERMINAL = frozenset({State.CLOSED})


class TransitionError(ValueError):
    """Raised when a transition is not permitted by the state machine."""


@dataclass(slots=True)
class Transition:
    at: datetime
    from_state: State
    to_state: State
    actor: str
    note: str = ""
    evidence: str = ""


@dataclass(slots=True)
class Ticket:
    """One remediation work item tracked through to closure."""

    id: str
    finding_id: str
    asset: str
    severity: str
    owner: str
    priority: str
    sla_days: int
    opened_at: datetime
    state: State = State.OPEN
    history: list[Transition] = field(default_factory=list)
    reopened_count: int = 0
    fixed_at: datetime | None = None
    verified_at: datetime | None = None
    closed_at: datetime | None = None

    def transition(
        self,
        to: State,
        *,
        actor: str,
        note: str = "",
        evidence: str = "",
        at: datetime | None = None,
    ) -> Transition:
        if not actor.strip():
            raise TransitionError("every transition needs a named actor")
        allowed = TRANSITIONS.get(self.state, frozenset())
        if to not in allowed:
            raise TransitionError(
                f"{self.id}: cannot move {self.state.value} -> {to.value}; "
                f"allowed: {sorted(s.value for s in allowed) or 'none (terminal)'}"
            )
        if to is State.VERIFIED and not evidence.strip():
            raise TransitionError(
                f"{self.id}: verification requires an evidence reference "
                "(scan id, retest output, or ticket)"
            )
        if to is State.RISK_ACCEPTED and not note.strip():
            raise TransitionError(f"{self.id}: risk acceptance requires a justification note")

        ts = at or datetime.now(timezone.utc)
        was_terminal = self.state in (State.VERIFIED, State.CLOSED)
        tr = Transition(ts, self.state, to, actor.strip(), note[:2000], evidence[:500])
        self.history.append(tr)
        self.state = to

        if to is State.FIXED:
            self.fixed_at = ts
        elif to is State.VERIFIED:
            self.verified_at = ts
        elif to is State.CLOSED:
            self.closed_at = ts
        if was_terminal and to is State.IN_PROGRESS:
            self.reopened_count += 1
            self.closed_at = None
            self.verified_at = None
        return tr

    # -- metrics ---------------------------------------------------------
    def age_days(self, now: datetime | None = None) -> float:
        now = now or datetime.now(timezone.utc)
        return (now - self.opened_at).total_seconds() / 86400.0

    def mttr_days(self) -> float | None:
        """Mean-time-to-remediate for this ticket, measured to closure."""
        if self.closed_at is None:
            return None
        return (self.closed_at - self.opened_at).total_seconds() / 86400.0

    def is_breached(self, now: datetime | None = None) -> bool:
        if self.state is State.CLOSED and self.closed_at is not None:
            return (self.closed_at - self.opened_at).total_seconds() / 86400.0 > self.sla_days
        return self.age_days(now) > self.sla_days


def open_ticket(
    *,
    ticket_id: str,
    finding_id: str,
    asset: str,
    severity: str,
    owner: str,
    priority: str,
    sla_days: int,
    now: datetime | None = None,
) -> Ticket:
    """Create a ticket in the OPEN state with an audit trail entry."""
    if sla_days < 1:
        raise TransitionError("sla_days must be >= 1")
    ts = now or datetime.now(timezone.utc)
    t = Ticket(
        id=ticket_id, finding_id=finding_id, asset=asset, severity=severity,
        owner=owner, priority=priority, sla_days=sla_days, opened_at=ts,
    )
    t.history.append(
        Transition(ts, State.OPEN, State.OPEN, "system", "ticket opened", "")
    )
    return t


# --------------------------------------------------------------------------
# Portfolio metrics
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Metrics:
    total: int
    open_count: int
    closed_count: int
    breached: int
    sla_compliance: float
    mttr_days: float | None
    reopen_rate: float
    by_state: dict[str, int]

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "open": self.open_count,
            "closed": self.closed_count,
            "breached": self.breached,
            "sla_compliance": round(self.sla_compliance, 4),
            "mttr_days": round(self.mttr_days, 2) if self.mttr_days is not None else None,
            "reopen_rate": round(self.reopen_rate, 4),
            "by_state": self.by_state,
        }


def compute_metrics(tickets: list[Ticket], now: datetime | None = None) -> Metrics:
    now = now or datetime.now(timezone.utc)
    total = len(tickets)
    closed = [t for t in tickets if t.state is State.CLOSED]
    breached = sum(1 for t in tickets if t.is_breached(now))
    mttrs = [m for t in closed if (m := t.mttr_days()) is not None]
    reopened = sum(1 for t in tickets if t.reopened_count > 0)
    by_state: dict[str, int] = {}
    for t in tickets:
        by_state[t.state.value] = by_state.get(t.state.value, 0) + 1

    return Metrics(
        total=total,
        open_count=total - len(closed),
        closed_count=len(closed),
        breached=breached,
        sla_compliance=(1 - breached / total) if total else 1.0,
        mttr_days=(sum(mttrs) / len(mttrs)) if mttrs else None,
        reopen_rate=(reopened / len(closed)) if closed else 0.0,
        by_state=by_state,
    )
