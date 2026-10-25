"""Typed domain model for CutVertex.

The central design decision of this project lives here: an edge is not a
plain arc. Every edge carries a *precondition set* — the capabilities an
attacker must already hold to traverse it. Traversal is therefore a
satisfiability question over the attacker's capability set, not a reachability
walk. That distinction is what makes the resulting paths defensible and what
makes "fix one chokepoint, kill 400 paths" a computable answer rather than a
marketing claim.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterable
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------


class NodeKind(str, enum.Enum):
    """What a graph vertex represents."""

    INTERNET = "internet"
    SUBNET = "subnet"
    HOST = "host"
    IDENTITY = "identity"
    SECRET = "secret"
    DATASTORE = "datastore"
    SAAS = "saas"
    CONTROL = "control"
    AGENT = "agent"


class EdgeKind(str, enum.Enum):
    """The mechanism an attacker uses to move across an edge."""

    NETWORK = "network"
    IDENTITY = "identity"
    CREDENTIAL = "credential"
    TRUST = "trust"
    DATA_FLOW = "data_flow"
    AGENTIC = "agentic"
    #: Compromise of a node in place: reach it, exploit it, own it.
    LOCAL = "local"


class Exposure(str, enum.Enum):
    """Attacker reachability of a node, mirroring SSVC 'exposure'."""

    OPEN = "open"
    CONTROLLED = "controlled"
    SMALL = "small"


class Impact(str, enum.Enum):
    """SSVC technical impact of the destination asset."""

    TOTAL = "total"
    PARTIAL = "partial"
    LOW = "low"


class Priority(str, enum.Enum):
    """CISA SSVC-style decision outcome, widened for two extra tiers."""

    ACT = "act"
    ATTEND = "attend"
    TRACK_STAR = "track*"
    TRACK = "track"


class Confidence(str, enum.Enum):
    """Epistemic confidence in an edge or node assertion."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    ASSERTED = "asserted"


# --------------------------------------------------------------------------
# Capabilities
# --------------------------------------------------------------------------

_CAP_RE = re.compile(r"^[a-z0-9][a-z0-9_:.\-/]{0,63}$")


class Capability:
    """Namespace of well-known attacker capabilities.

    Capabilities are intentionally plain strings so that ingested data from
    cloud, IdP, EDR, and CMDB sources can be normalised into one vocabulary
    without a schema migration per source. The constants below are the built-in
    vocabulary; custom capabilities must still satisfy ``_CAP_RE``.
    """

    NETWORK = "net:reach"
    UNAUTH_HTTP = "net:unauth-http"
    TELNET = "net:telnet"
    SMB = "net:smb"
    MANAGEMENT = "net:mgmt-plane"

    SHELL = "exec:shell"
    CODE_EXEC = "exec:code"
    LOCAL_ADMIN = "exec:local-admin"

    HASH = "cred:hash"
    PLAINTEXT = "cred:plaintext"
    KERBEROS = "cred:ticket"
    CLOUD_KEY = "cred:cloud-key"
    TOKEN_OAUTH = "cred:oauth-token"

    DOMAIN_USER = "id:domain-user"
    PRIVILEGED = "id:privileged"
    TIER0 = "id:tier0"
    SECRET_READ = "secret:read"

    PROMPT_INJECT = "agent:prompt-inject"
    TOOL_INVOKE = "agent:tool-invoke"
    MEMORY_WRITE = "agent:memory-write"
    MCP_SERVER = "agent:mcp-server"


BUILTIN_CAPABILITIES: frozenset[str] = frozenset(
    v for k, v in vars(Capability).items() if not k.startswith("_") and isinstance(v, str)
)


class CapabilityError(ValueError):
    """Raised when a capability string violates the vocabulary contract."""


class PreconditionSet:
    """A small first-order constraint over capabilities.

    Semantics, evaluated against an attacker-held capability set ``H``:

    * ``all_of``  — every capability must be in ``H``.
    * ``any_of``  — at least one must be in ``H``; empty means "no all_of
      requirement is introduced by this clause".
    * ``none_of`` — none may be in ``H`` (hard blockers, e.g. MFA enforced).

    A set is satisfiable when ``all_of`` is a subset of ``H``, ``all_of`` is
    non-empty or ``any_of`` is empty or intersects ``H``, and ``none_of`` is
    disjoint from ``H``. Empty sets are satisfiable by anyone, which models a
    genuinely unauthenticated hop.

    Sets form a lattice: union combines requirements (harder), and the empty
    set is the identity. Path accumulation uses union, so a long chain is only
    as cheap as its combined prerequisites allow.
    """

    __slots__ = ("all_of", "any_of", "none_of")

    def __init__(
        self,
        all_of: Iterable[str] = (),
        any_of: Iterable[str] = (),
        none_of: Iterable[str] = (),
    ) -> None:
        self.all_of = frozenset(self._validate(c) for c in all_of)
        self.any_of = frozenset(self._validate(c) for c in any_of)
        self.none_of = frozenset(self._validate(c) for c in none_of)
        contradictions = self.all_of & self.none_of
        if contradictions:
            raise CapabilityError(
                "precondition requires and forbids the same capability: "
                + ", ".join(sorted(contradictions))
            )

    @staticmethod
    def _validate(cap: str) -> str:
        if not isinstance(cap, str) or not _CAP_RE.match(cap):
            raise CapabilityError(f"invalid capability identifier: {cap!r}")
        return cap

    # -- constructors ------------------------------------------------------
    @classmethod
    def require(cls, *caps: str) -> PreconditionSet:
        return cls(all_of=caps)

    @classmethod
    def any(cls, *caps: str) -> PreconditionSet:
        return cls(any_of=caps)

    @classmethod
    def forbid(cls, *caps: str) -> PreconditionSet:
        return cls(none_of=caps)

    # -- algebra ----------------------------------------------------------
    def union(self, other: PreconditionSet) -> PreconditionSet:
        """Combine two requirements: the result needs both satisfied."""
        return PreconditionSet(
            all_of=self.all_of | other.all_of,
            any_of=self.any_of | other.any_of,
            none_of=self.none_of | other.none_of,
        )

    def satisfiable(self, held: frozenset[str] | set[str]) -> bool:
        held_set = set(held)
        return (
            self.all_of.issubset(held_set)
            and not (self.none_of & held_set)
            # An any_of clause with no all_of anchor is still a requirement.
            and not (self.any_of and not (self.any_of & held_set))
        )

    def residual(self, held: frozenset[str] | set[str]) -> tuple[str, ...]:
        """Capabilities still missing before this set can be satisfied."""
        missing = [c for c in self.all_of if c not in held]
        if self.any_of and not (self.any_of & set(held)):
            missing.append("one-of(" + "|".join(sorted(self.any_of)) + ")")
        return tuple(sorted(missing))

    def blockers(self, held: frozenset[str] | set[str]) -> tuple[str, ...]:
        """Capabilities the attacker holds that hard-block this set."""
        return tuple(sorted(self.none_of & set(held)))

    @property
    def is_empty(self) -> bool:
        return not (self.all_of or self.any_of or self.none_of)

    def cost(self) -> int:
        """Heuristic difficulty in abstract capability units."""
        n = len(self.all_of)
        if self.any_of:
            n += 1
        n += 2 * len(self.none_of)  # bypassing a control is expensive
        return n

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> dict[str, list[str]]:
        return {
            "all_of": sorted(self.all_of),
            "any_of": sorted(self.any_of),
            "none_of": sorted(self.none_of),
        }

    @classmethod
    def from_dict(cls, raw: dict | None) -> PreconditionSet:
        if not raw:
            return cls()
        if not isinstance(raw, dict):
            raise CapabilityError("precondition must be an object")
        return cls(
            all_of=raw.get("all_of", ()),
            any_of=raw.get("any_of", ()),
            none_of=raw.get("none_of", ()),
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PreconditionSet) and (
            self.all_of == other.all_of
            and self.any_of == other.any_of
            and self.none_of == other.none_of
        )

    def __hash__(self) -> int:
        return hash((self.all_of, self.any_of, self.none_of))

    def __repr__(self) -> str:
        parts = []
        if self.all_of:
            parts.append("+" + ",".join(sorted(self.all_of)))
        if self.any_of:
            parts.append("?" + "|".join(sorted(self.any_of)))
        if self.none_of:
            parts.append("-" + ",".join(sorted(self.none_of)))
        return "Precondition(" + " ".join(parts) + ")" if parts else "Precondition()"


EMPTY_PRECONDITION = PreconditionSet()


# --------------------------------------------------------------------------
# Graph entities
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Control:
    """A security control that, if effective, blocks traversal.

    ``defeated_by`` names the capability an attacker needs to neutralise the
    control. When a control is modelled as *effective*, ingress edges that name
    it require that capability: holding the bypass is what opens the door.
    """

    id: str
    name: str
    kind: str  # e.g. "mfa", "edr", "network_acl", "waf", "segmentation"
    effective: bool = True
    defeated_by: str | None = None
    notes: str = ""


@dataclass(frozen=True, slots=True)
class Node:
    """A vertex in the environment graph."""

    id: str
    name: str
    kind: NodeKind
    criticality: int = 1
    exposure: Exposure = Exposure.SMALL
    impact: Impact = Impact.PARTIAL
    owner: str = "unassigned"
    tags: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    controls: tuple[str, ...] = ()
    confidence: Confidence = Confidence.OBSERVED
    attributes: tuple[tuple[str, str], ...] = ()
    #: What an attacker must satisfy to *own* this node once they can reach it.
    #: Populated from findings during ingest or declared explicitly.
    compromise: PreconditionSet = EMPTY_PRECONDITION
    #: Capabilities the attacker gains by owning this node. This is what lets a
    #: CVE on a jump host actually unlock the next hop, instead of findings
    #: being scored in isolation from the topology.
    grants: tuple[str, ...] = ()

    @property
    def is_crown_jewel(self) -> bool:
        return self.criticality >= 4 or self.impact is Impact.TOTAL

    @property
    def attr(self) -> dict[str, str]:
        return dict(self.attributes)


@dataclass(frozen=True, slots=True)
class Edge:
    """A directed traversal opportunity with an explicit precondition set."""

    src: str
    dst: str
    kind: EdgeKind
    precondition: PreconditionSet = EMPTY_PRECONDITION
    grants: tuple[str, ...] = ()
    confidence: Confidence = Confidence.OBSERVED
    control: str | None = None
    technique: str = ""
    weight: float = 1.0

    def traversable(self, held: frozenset[str] | set[str]) -> bool:
        return self.precondition.satisfiable(held)


@dataclass(frozen=True, slots=True)
class Finding:
    """A vulnerability observation to be chained into the graph."""

    id: str
    asset: str
    cve: str | None = None
    title: str = ""
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    patch_available: bool = False
    exploit_maturity: str = "unknown"
    grants: tuple[str, ...] = ()
    requires: PreconditionSet = EMPTY_PRECONDITION
    source: str = "manual"


# --------------------------------------------------------------------------
# Attack paths and ranking
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Step:
    """One edge traversed, with the capability state before and after."""

    src: str
    dst: str
    kind: EdgeKind
    precondition: PreconditionSet
    grants: tuple[str, ...]
    technique: str = ""
    blocked: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind.value,
            "precondition": self.precondition.to_dict(),
            "grants": list(self.grants),
            "technique": self.technique,
            "blocked": list(self.blocked),
        }


@dataclass(frozen=True, slots=True)
class AttackPath:
    """An ordered, satisfiable chain from an entry point to a target."""

    entry: str
    target: str
    steps: tuple[Step, ...]
    capabilities_required: frozenset[str]
    capabilities_gained: frozenset[str]
    entry_precondition: PreconditionSet
    residual_gaps: tuple[str, ...]
    technique_depth: int
    score: float = 0.0
    confidence: Confidence = Confidence.INFERRED

    @property
    def hops(self) -> int:
        return len(self.steps)

    @property
    def node_ids(self) -> tuple[str, ...]:
        return (self.entry, *(s.dst for s in self.steps))

    @property
    def edge_keys(self) -> tuple[tuple[str, str], ...]:
        return tuple((s.src, s.dst) for s in self.steps)

    def is_realizable(self) -> bool:
        """True when no external capability grant is needed to start."""
        return not self.residual_gaps

    def to_dict(self) -> dict:
        return {
            "entry": self.entry,
            "target": self.target,
            "hops": self.hops,
            "score": round(self.score, 2),
            "realizable": self.is_realizable(),
            "capabilities_required": sorted(self.capabilities_required),
            "capabilities_gained": sorted(self.capabilities_gained),
            "residual_gaps": list(self.residual_gaps),
            "technique_depth": self.technique_depth,
            "confidence": self.confidence.value,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass(slots=True)
class Chokepoint:
    """A single remediation whose removal breaks the most real path weight."""

    edge: tuple[str, str]
    technique: str
    paths_broken: int
    paths_total: int
    risk_removed: float
    risk_share: float
    cost_hint: str
    effort: int
    confidence: Confidence
    gates: tuple[str, ...] = ()
    rationale: str = ""

    def to_dict(self) -> dict:
        return {
            "edge": {"src": self.edge[0], "dst": self.edge[1]},
            "technique": self.technique,
            "paths_broken": self.paths_broken,
            "paths_total": self.paths_total,
            "risk_removed": round(self.risk_removed, 2),
            "risk_share": round(self.risk_share, 4),
            "cost_hint": self.cost_hint,
            "effort": self.effort,
            "confidence": self.confidence.value,
            "gates": list(self.gates),
            "rationale": self.rationale,
        }
