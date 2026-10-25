"""Risk scoring and prioritisation.

Three things are deliberately kept separate, because conflating them is the
root of most bad vulnerability queues:

1. **Severity** — how bad is it *if* exploited (CVSS).
2. **Likelihood** — how likely is exploitation (EPSS, KEV, exploit maturity).
3. **Exposure** — can an attacker actually reach it from where they stand,
   and what does it unlock (graph analysis from :mod:`cutvertex.graph`).

Only the combination is actionable. A CVSS 9.8 on an unreachable host behind
three controls is not the same work item as a CVSS 6.5 on the internet-facing
jump host that sits on a verified path to the domain controller, yet
severity-only queues rank them identically.

The decision layer implements a deployer-oriented variant of CISA's
Stakeholder-Specific Vulnerability Categorization (SSVC), which is the
approach CISA itself uses and recommends over CVSS-threshold triage.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from cutvertex.model import (
    AttackPath,
    Exposure,
    Finding,
    Impact,
    Node,
    Priority,
)

# --------------------------------------------------------------------------
# Individual signals
# --------------------------------------------------------------------------

# Reference points for EPSS. FIRST's own documentation puts the baseline
# exploitation rate across all scored CVEs at roughly 2-3%, so a 0.10 EPSS is
# already far above background; 0.50 is a coin flip.
EPSS_BACKGROUND = 0.03
EPSS_HIGH = 0.50


def severity_weight(cvss: float | None) -> float:
    """Map CVSS to a 0-1 severity weight, non-linearly.

    Linear mapping over-weights the 7-8 band, where most CVEs live. A cubic
    curve keeps low scores genuinely low while preserving the steep penalty at
    the top end.
    """
    if cvss is None:
        return 0.35  # unknown severity: assume moderate, never zero
    c = max(0.0, min(10.0, float(cvss)))
    return (c / 10.0) ** 3


def likelihood(cvss: float | None, epss: float | None, kev: bool, maturity: str) -> float:
    """Exploitation likelihood in 0-1, combining predictive and confirmed evidence.

    KEV is treated as near-certainty because it is *confirmed* in-the-wild
    exploitation — no model should be allowed to outvote observed reality.
    EPSS contributes on a log scale relative to the background rate. Exploit
    maturity is a coarse prior for CVEs EPSS has not yet scored well.
    """
    if kev:
        base = 0.97
    else:
        if epss is None:
            # No EPSS: fall back to maturity as a weak prior.
            base = {"weaponized": 0.55, "functional": 0.30, "proof": 0.12}.get(maturity, 0.05)
        else:
            e = max(0.0, min(1.0, float(epss)))
            # Normalise against background: e/background on a log curve.
            ratio = max(e, 1e-9) / EPSS_BACKGROUND
            base = min(0.95, 0.10 + 0.18 * math.log10(max(1.0, ratio)))
            base = max(base, e)  # never below the raw prediction
        base = max(
            base,
            {"weaponized": 0.55, "functional": 0.30, "proof": 0.12}.get(maturity, 0.0),
        )
    # Severity gates exploitability slightly: nobody weaponises a cosmetic bug.
    return min(1.0, base * (0.65 + 0.35 * severity_weight(cvss)))


def exposure_multiplier(node: Node, on_path: bool, path_score: float) -> float:
    """Environmental reachability multiplier.

    An unreachable asset is not zero risk (insiders, supply chain), but it is
    a fraction of a reachable one. A node sitting on a verified attack path
    gets a further boost proportional to how plausible that path is.
    """
    base = {
        Exposure.OPEN: 1.0,
        Exposure.CONTROLLED: 0.55,
        Exposure.SMALL: 0.25,
    }.get(node.exposure, 0.25)
    if on_path:
        base *= 1.0 + 0.6 * min(1.0, path_score / 100.0)
    return min(1.6, base)


def asset_criticality(node: Node) -> float:
    """Normalised business weight of the asset itself (0-1)."""
    impact_w = {Impact.TOTAL: 1.0, Impact.PARTIAL: 0.55, Impact.LOW: 0.2}.get(
        node.impact, 0.55
    )
    crit_w = min(1.0, max(0.2, node.criticality / 5.0))
    return round(0.6 * impact_w + 0.4 * crit_w, 4)


# --------------------------------------------------------------------------
# Composite score
# --------------------------------------------------------------------------


@dataclass(slots=True)
class RiskScore:
    """Explainable composite risk for one finding in one asset context."""

    finding_id: str
    asset: str
    score: float                       # 0-100
    severity: float
    likelihood: float
    exposure: float
    criticality: float
    path_factor: float
    on_verified_path: bool
    best_path_score: float
    contributing_paths: int
    reasons: tuple[str, ...] = ()


def composite_risk(
    finding: Finding,
    node: Node,
    *,
    paths: list[AttackPath] | None = None,
) -> RiskScore:
    """Score one finding against its asset and the verified path set."""
    relevant = [p for p in (paths or []) if finding.asset in p.node_ids]
    best = max((p.score for p in relevant), default=0.0)
    on_path = bool(relevant)

    sev = severity_weight(finding.cvss)
    like = likelihood(finding.cvss, finding.epss, finding.kev, finding.exploit_maturity)
    expo = exposure_multiplier(node, on_path, best)
    crit = asset_criticality(node)
    path_factor = 1.0 + 0.75 * min(1.0, best / 100.0) if on_path else 0.35

    # Weighted geometric-ish blend: no single weak dimension can carry a score.
    core = (sev**0.35) * (like**0.30) * (crit**0.20) * (expo**0.15)
    score = 100.0 * min(1.0, core * path_factor)

    reasons = []
    if finding.kev:
        reasons.append("listed in CISA KEV (confirmed in-the-wild exploitation)")
    if finding.epss is not None and finding.epss >= EPSS_HIGH:
        reasons.append(f"EPSS {finding.epss:.2f} — exploitation more likely than not")
    elif finding.epss is not None and finding.epss >= 0.10:
        reasons.append(f"EPSS {finding.epss:.2f} — well above the ~3% background rate")
    if finding.cvss is not None and finding.cvss >= 9.0:
        reasons.append(f"CVSS {finding.cvss:.1f} critical severity")
    if on_path:
        reasons.append(
            f"asset sits on {len(relevant)} verified path(s), strongest scoring "
            f"{best:.1f}/100 — reaching it advances an attacker toward a crown jewel"
        )
    else:
        reasons.append("asset not on a currently verified path to a crown jewel")
    if node.exposure is Exposure.OPEN:
        reasons.append("asset is internet-exposed")
    if not finding.patch_available:
        reasons.append("no vendor patch available — compensating control required")
    if node.criticality >= 4:
        reasons.append(f"business-criticality {node.criticality}/5")

    return RiskScore(
        finding_id=finding.id,
        asset=finding.asset,
        score=round(min(100.0, score), 2),
        severity=round(sev, 4),
        likelihood=round(like, 4),
        exposure=round(expo, 4),
        criticality=crit,
        path_factor=round(path_factor, 4),
        on_verified_path=on_path,
        best_path_score=round(best, 2),
        contributing_paths=len(relevant),
        reasons=tuple(reasons),
    )


# --------------------------------------------------------------------------
# SSVC deployer decision tree
# --------------------------------------------------------------------------


@dataclass(slots=True)
class SSVCDecision:
    """Outcome of the deployer decision tree plus the inputs used."""

    priority: Priority
    exploitation: str
    exposure: str
    automatability: str
    mission_impact: str
    rationale: str
    sla_days: int
    ticket_required: bool


def exploitation_status(finding: Finding) -> str:
    """Derive SSVC exploitation status from observable evidence."""
    if finding.kev:
        return "active"
    m = (finding.exploit_maturity or "unknown").lower()
    if m in {"weaponized", "functional"}:
        return "poc"
    if finding.epss is not None and finding.epss >= 0.10:
        return "poc"
    return "none"


def automatability(finding: Finding, path: AttackPath | None) -> str:
    """Can the exploit be driven automatically end-to-end?

    A path that needs no inherited capability and no human-in-the-loop control
    is automatable. Anything with residual gaps or an interactive gate is not.
    """
    if path is not None and path.residual_gaps:
        return "no"
    if finding.exploit_maturity.lower() == "weaponized":
        return "yes"
    if path is not None and path.technique_depth >= 2:
        return "yes"
    return "no"


def mission_impact(node: Node, finding: Finding) -> str:
    if node.impact is Impact.TOTAL or node.criticality >= 5:
        return "high"
    if node.impact is Impact.PARTIAL or node.criticality >= 3:
        return "medium"
    return "low"


_SLA = {
    Priority.ACT: 3,
    Priority.ATTEND: 14,
    Priority.TRACK_STAR: 30,
    Priority.TRACK: 90,
}


def ssvc_decide(
    finding: Finding,
    node: Node,
    *,
    paths: list[AttackPath] | None = None,
) -> SSVCDecision:
    """Evaluate the deployer decision tree.

    Decision order follows CISA's deployer tree: exploitation state first (it
    dominates everything), then exposure, then automatability, then mission
    impact. This ordering matters — it is what stops a theoretical CVSS 10 on
    an isolated lab box from outranking a KEV-listed bug on the VPN concentrator.
    """
    expl = exploitation_status(finding)
    expo = node.exposure.value
    relevant = [p for p in (paths or []) if finding.asset in p.node_ids]
    best_path = max(relevant, key=lambda p: p.score) if relevant else None
    auto = automatability(finding, best_path)
    impact = mission_impact(node, finding)

    if expl == "active":
        if expo == "open":
            priority, why = Priority.ACT, "actively exploited and internet-reachable"
        elif expo == "controlled":
            priority, why = (
                Priority.ACT,
                "actively exploited behind a partially-effective control",
            )
        else:
            priority, why = (
                Priority.ATTEND,
                "actively exploited but not externally reachable",
            )
    elif expl == "poc":
        if expo == "open" and auto == "yes":
            priority, why = Priority.ACT, "public exploit, automatable, internet-reachable"
        elif expo == "open":
            priority, why = Priority.ATTEND, "public exploit on an externally exposed asset"
        elif expo == "controlled" and auto == "yes":
            priority, why = Priority.ATTEND, "automatable exploit against a controlled asset"
        else:
            priority, why = Priority.TRACK_STAR, "exploit exists but requires a foothold"
    else:
        if expo == "open" and impact == "high":
            priority, why = Priority.ATTEND, "critical asset exposed without known exploitation"
        elif expo == "open":
            priority, why = Priority.TRACK_STAR, "exposed but no exploitation evidence"
        else:
            priority, why = Priority.TRACK, "no exploitation evidence and limited exposure"

    if best_path is not None and best_path.is_realizable() and expo != "small":
        # A realizable chain upgrades anything short of ACT one tier.
        if priority is Priority.TRACK:
            priority, why = Priority.TRACK_STAR, why + "; reachable on a realizable path"
        elif priority is Priority.TRACK_STAR:
            priority, why = Priority.ATTEND, why + "; reachable on a realizable path"

    return SSVCDecision(
        priority=priority,
        exploitation=expl,
        exposure=expo,
        automatability=auto,
        mission_impact=impact,
        rationale=why,
        sla_days=_SLA[priority],
        ticket_required=priority in (Priority.ACT, Priority.ATTEND),
    )


# --------------------------------------------------------------------------
# Portfolio aggregation
# --------------------------------------------------------------------------


@dataclass(slots=True)
class PrioritizedFinding:
    finding: Finding
    node: Node
    risk: RiskScore
    decision: SSVCDecision
    paths: list[AttackPath] = field(default_factory=list)

    @property
    def sort_key(self) -> tuple:
        order = {
            Priority.ACT: 0,
            Priority.ATTEND: 1,
            Priority.TRACK_STAR: 2,
            Priority.TRACK: 3,
        }
        return (order[self.decision.priority], -self.risk.score)

    def to_dict(self) -> dict:
        return {
            "id": self.finding.id,
            "asset": self.finding.asset,
            "asset_name": self.node.name,
            "cve": self.finding.cve,
            "title": self.finding.title,
            "cvss": self.finding.cvss,
            "epss": self.finding.epss,
            "kev": self.finding.kev,
            "patch_available": self.finding.patch_available,
            "risk_score": self.risk.score,
            "priority": self.decision.priority.value,
            "sla_days": self.decision.sla_days,
            "ssvc": {
                "exploitation": self.decision.exploitation,
                "exposure": self.decision.exposure,
                "automatability": self.decision.automatability,
                "mission_impact": self.decision.mission_impact,
                "rationale": self.decision.rationale,
            },
            "on_verified_path": self.risk.on_verified_path,
            "contributing_paths": self.risk.contributing_paths,
            "reasons": list(self.risk.reasons),
        }


def prioritize(
    findings: list[Finding],
    nodes: dict[str, Node],
    paths: list[AttackPath],
) -> list[PrioritizedFinding]:
    """Score and rank all findings. Unknown assets are skipped, not guessed."""
    out: list[PrioritizedFinding] = []
    for f in findings:
        node = nodes.get(f.asset)
        if node is None:
            continue
        risk = composite_risk(f, node, paths=paths)
        decision = ssvc_decide(f, node, paths=paths)
        related = [p for p in paths if f.asset in p.node_ids]
        out.append(PrioritizedFinding(f, node, risk, decision, related))
    out.sort(key=lambda p: p.sort_key)
    return out
