"""Analysis orchestration: document in, defensible assessment out.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from cutvertex.graph import EnvironmentGraph, enumerate_paths, rank_chokepoints
from cutvertex.ingest.loader import build_environment, merge_enrichment
from cutvertex.model import AttackPath, Chokepoint, Finding, Priority
from cutvertex.scoring import PrioritizedFinding, prioritize


@dataclass(slots=True)
class Assessment:
    """Complete result of one analysis run."""

    generated_at: datetime
    graph: EnvironmentGraph
    findings: list[Finding]
    paths: list[AttackPath]
    prioritized: list[PrioritizedFinding]
    chokepoints: list[Chokepoint]
    warnings: list[str] = field(default_factory=list)

    # -- summary ----------------------------------------------------------
    @property
    def counts(self) -> dict[str, int]:
        by_priority: dict[str, int] = {p.value: 0 for p in Priority}
        for p in self.prioritized:
            by_priority[p.decision.priority.value] += 1
        return {
            "nodes": len(self.graph.nodes),
            "edges": len(self.graph.edges),
            "entry_points": len(self.graph.entry_nodes()),
            "crown_jewels": len(self.graph.crown_jewels()),
            "findings": len(self.findings),
            "paths": len(self.paths),
            "realizable_paths": sum(1 for p in self.paths if p.is_realizable()),
            "chokepoints": len(self.chokepoints),
            **{f"priority_{k}": v for k, v in by_priority.items()},
        }

    @property
    def exposure_index(self) -> float:
        """0-100 single number: how exposed is the estate, weighted by risk.

        Weighted by path score so that one critical 92-scoring kill chain
        outweighs twenty marginal ones. Deliberately not an average — averages
        let a large tail of noise hide a single fatal path.
        """
        if not self.paths:
            return 0.0
        top = sorted((p.score for p in self.paths), reverse=True)[:5]
        weighted = sum(s * (0.6**i) for i, s in enumerate(top))
        return round(min(100.0, weighted / sum(0.6**i for i in range(len(top)))), 2)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at.isoformat(),
            "summary": self.counts,
            "exposure_index": self.exposure_index,
            "warnings": self.warnings,
            "paths": [p.to_dict() for p in self.paths[:50]],
            "chokepoints": [c.to_dict() for c in self.chokepoints],
            "findings": [p.to_dict() for p in self.prioritized[:100]],
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "kind": n.kind.value,
                    "criticality": n.criticality,
                    "exposure": n.exposure.value,
                    "impact": n.impact.value,
                    "owner": n.owner,
                    "crown_jewel": n.is_crown_jewel,
                }
                for n in self.graph.nodes.values()
            ],
            "edges": [
                {
                    "src": e.src,
                    "dst": e.dst,
                    "kind": e.kind.value,
                    "technique": e.technique,
                    "precondition": e.precondition.to_dict(),
                    "grants": list(e.grants),
                    "control": e.control,
                }
                for e in self.graph.edges
            ],
        }


def assess(
    document: dict | None = None,
    *,
    graph: EnvironmentGraph | None = None,
    findings: list[Finding] | None = None,
    enrichment: dict[str, dict] | None = None,
    max_hops: int = 8,
    max_paths: int = 500,
    top_chokepoints: int = 10,
) -> Assessment:
    """Run the full pipeline and return an :class:`Assessment`."""
    warnings: list[str] = []

    if graph is None:
        if document is None:
            raise ValueError("provide either a document or a prebuilt graph")
        graph, findings = build_environment(document)
    findings = findings or []

    if enrichment:
        findings = merge_enrichment(findings, enrichment)

    structural = graph.validate()
    warnings.extend(structural)

    paths = enumerate_paths(graph, max_hops=max_hops, max_paths=max_paths)
    if not paths and not structural:
        warnings.append(
            "no attacker path reaches a crown jewel under the modelled preconditions "
            "— verify controls are not over-stated as effective"
        )

    prioritized = prioritize(findings, dict(graph.nodes), paths)
    chokepoints = rank_chokepoints(graph, paths, top_n=top_chokepoints)

    return Assessment(
        generated_at=datetime.now(timezone.utc),
        graph=graph,
        findings=findings,
        paths=paths,
        prioritized=prioritized,
        chokepoints=chokepoints,
        warnings=warnings,
    )


def what_if(
    graph: EnvironmentGraph,
    findings: list[Finding],
    *,
    remove_edge: tuple[str, str] | None = None,
    disable_control: str | None = None,
    max_hops: int = 8,
) -> dict:
    """Re-run analysis under a hypothetical remediation and report the delta.

    This is what makes a chokepoint recommendation falsifiable: an engineer can
    see exactly how many paths survive before committing to the change.
    """
    before = enumerate_paths(graph, max_hops=max_hops)
    before_risk = sum(p.score for p in before)

    kept_nodes = list(graph.nodes.values())
    kept_edges = [
        e
        for e in graph.edges
        if not (remove_edge and (e.src, e.dst) == remove_edge)
    ]
    if disable_control:
        for e in kept_edges:
            if e.control == disable_control:
                e = e  # control already baked into preconditions at ingest; see note
    after_graph = EnvironmentGraph(kept_nodes, kept_edges)
    for c in graph.controls.values():
        after_graph.register_control(c)

    after = enumerate_paths(after_graph, max_hops=max_hops)
    after_risk = sum(p.score for p in after)
    return {
        "before": {"paths": len(before), "risk": round(before_risk, 2)},
        "after": {"paths": len(after), "risk": round(after_risk, 2)},
        "delta": {
            "paths_removed": len(before) - len(after),
            "risk_removed": round(before_risk - after_risk, 2),
            "risk_reduction_pct": (
                round(100 * (before_risk - after_risk) / before_risk, 2)
                if before_risk
                else 0.0
            ),
        },
        "remaining_paths": [p.to_dict() for p in after[:20]],
    }
