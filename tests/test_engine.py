"""Test suite for the CutVertex engine.

Covers the four behaviours the tool's claims actually rest on:
path enumeration, control-bypass semantics, finding-to-capability coupling,
and prioritisation decisions.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved.
"""

from __future__ import annotations

import pytest

from cutvertex.analysis import assess, what_if
from cutvertex.graph import EnvironmentGraph, GraphError, enumerate_paths, rank_chokepoints
from cutvertex.ingest.loader import IngestError, build_environment, load_document
from cutvertex.model import (
    CapabilityError,
    Edge,
    EdgeKind,
    Exposure,
    Finding,
    Impact,
    Node,
    NodeKind,
    PreconditionSet,
)
from cutvertex.scoring import (
    Priority,
    composite_risk,
    likelihood,
    prioritize,
    severity_weight,
    ssvc_decide,
)

# --------------------------------------------------------------------------
# Precondition algebra
# --------------------------------------------------------------------------


class TestPreconditionSet:
    def test_empty_is_satisfiable_by_anyone(self):
        assert PreconditionSet().satisfiable(set())

    def test_all_of_requires_every_capability(self):
        p = PreconditionSet.require("a:b", "c:d")
        assert not p.satisfiable({"a:b"})
        assert p.satisfiable({"a:b", "c:d"})

    def test_any_of_requires_one(self):
        p = PreconditionSet.any("x:one", "x:two")
        assert not p.satisfiable({"x:three"})
        assert p.satisfiable({"x:two"})

    def test_none_of_blocks(self):
        p = PreconditionSet.forbid("exec:local-admin")
        assert not p.satisfiable({"exec:local-admin"})
        assert p.satisfiable({"net:reach"})

    def test_contradiction_rejected_at_construction(self):
        with pytest.raises(CapabilityError):
            PreconditionSet(all_of=["net:reach"], none_of=["net:reach"])

    def test_invalid_identifier_rejected(self):
        with pytest.raises(CapabilityError):
            PreconditionSet(all_of=["Not Valid!"])

    def test_union_combines_requirements(self):
        a = PreconditionSet.require("a:a")
        b = PreconditionSet.require("b:b")
        u = a.union(b)
        assert u.satisfiable({"a:a", "b:b"})
        assert not u.satisfiable({"a:a"})

    def test_residual_reports_gaps(self):
        p = PreconditionSet.require("a:a", "b:b")
        assert p.residual({"a:a"}) == ("b:b",)

    def test_roundtrip_serialisation(self):
        p = PreconditionSet(all_of=["a:a"], none_of=["b:b"])
        assert PreconditionSet.from_dict(p.to_dict()) == p


# --------------------------------------------------------------------------
# Graph construction
# --------------------------------------------------------------------------


def _simple_graph() -> EnvironmentGraph:
    nodes = [
        Node("web", "Web", NodeKind.HOST, criticality=3, exposure=Exposure.OPEN),
        Node("app", "App", NodeKind.HOST, criticality=3),
        Node("db", "DB", NodeKind.DATASTORE, criticality=5, impact=Impact.TOTAL),
    ]
    edges = [
        Edge("web", "app", EdgeKind.NETWORK, PreconditionSet(), grants=("net:reach",)),
        Edge(
            "app",
            "db",
            EdgeKind.NETWORK,
            PreconditionSet.require("net:reach"),
            grants=("cred:plaintext",),
        ),
    ]
    return EnvironmentGraph(nodes, edges)


class TestGraph:
    def test_duplicate_node_rejected(self):
        with pytest.raises(GraphError):
            EnvironmentGraph(
                [Node("a", "A", NodeKind.HOST), Node("a", "A", NodeKind.HOST)], []
            )

    def test_edge_to_unknown_node_rejected(self):
        with pytest.raises(GraphError):
            EnvironmentGraph(
                [Node("a", "A", NodeKind.HOST)], [Edge("a", "ghost", EdgeKind.NETWORK)]
            )

    def test_self_loop_rejected(self):
        with pytest.raises(GraphError):
            EnvironmentGraph([Node("a", "A", NodeKind.HOST)], [Edge("a", "a", EdgeKind.NETWORK)])

    def test_entry_and_jewel_detection(self):
        g = _simple_graph()
        assert g.entry_nodes() == ["web"]
        assert g.crown_jewels() == ["db"]

    def test_validate_flags_missing_entry(self):
        g = EnvironmentGraph([Node("a", "A", NodeKind.HOST, criticality=5)], [])
        issues = g.validate()
        assert any("no entry nodes" in i for i in issues)


# --------------------------------------------------------------------------
# Path enumeration
# --------------------------------------------------------------------------


class TestEnumeration:
    def test_finds_kill_chain(self):
        paths = enumerate_paths(_simple_graph())
        assert len(paths) == 1
        assert paths[0].entry == "web"
        assert paths[0].target == "db"
        assert paths[0].hops == 2
        assert paths[0].is_realizable()

    def test_capability_gate_blocks_path(self):
        """An edge needing an ungranted capability is not walkable by default."""
        nodes = [
            Node("web", "Web", NodeKind.HOST, exposure=Exposure.OPEN),
            Node("vault", "Vault", NodeKind.DATASTORE, criticality=5, impact=Impact.TOTAL),
        ]
        g = EnvironmentGraph(
            nodes,
            [Edge("web", "vault", EdgeKind.NETWORK, PreconditionSet.require("id:tier0"))],
        )
        # Default (strict) mode: an outside attacker cannot walk this, so it is
        # not reported as a path at all.
        assert enumerate_paths(g) == []

        # Assume-breach mode surfaces it, flagged with the capability needed.
        gapped = enumerate_paths(g, allow_gaps=True)
        assert gapped
        assert not gapped[0].is_realizable()
        assert "id:tier0" in gapped[0].residual_gaps

    def test_max_hops_respected(self):
        paths = enumerate_paths(_simple_graph(), max_hops=1)
        assert paths == []

    def test_target_override(self):
        g = _simple_graph()
        assert enumerate_paths(g, targets=["app"])[0].target == "app"

    def test_no_targets_returns_empty(self):
        g = EnvironmentGraph([Node("a", "A", NodeKind.HOST, exposure=Exposure.OPEN)], [])
        assert enumerate_paths(g) == []


# --------------------------------------------------------------------------
# Control semantics
# --------------------------------------------------------------------------


class TestControls:
    def test_effective_control_without_bypass_removes_edge(self):
        doc = {
            "controls": [{"id": "seg", "name": "Seg", "kind": "segmentation", "effective": True}],
            "nodes": [
                {"id": "i", "kind": "internet"},
                {"id": "h", "kind": "host"},
                {"id": "d", "kind": "datastore", "criticality": 5, "impact": "total"},
            ],
            "edges": [
                {"src": "i", "dst": "h", "kind": "network"},
                {"src": "h", "dst": "d", "kind": "network", "control": "seg"},
            ],
        }
        g, _ = build_environment(doc)
        assert g.blocked_by_control == (("h", "d", "seg"),)
        assert enumerate_paths(g) == []

    def test_effective_control_with_bypass_requires_bypass_capability(self):
        doc = {
            "controls": [
                {
                    "id": "mfa",
                    "name": "MFA",
                    "kind": "mfa",
                    "effective": True,
                    "defeated_by": "cred:oauth-token",
                }
            ],
            "nodes": [
                {"id": "i", "kind": "internet"},
                {"id": "h", "kind": "host"},
                {"id": "d", "kind": "datastore", "criticality": 5, "impact": "total"},
            ],
            "edges": [
                {"src": "i", "dst": "h", "kind": "network", "grants": ["net:reach"]},
                {"src": "h", "dst": "d", "kind": "network", "control": "mfa"},
            ],
        }
        g, _ = build_environment(doc)
        # The control does not forbid the bypass — it demands it, so a strict
        # external-only search cannot traverse it.
        assert enumerate_paths(g) == []
        # Under assume-breach the cost of bypassing MFA is made explicit.
        gapped = enumerate_paths(g, allow_gaps=True)
        assert len(gapped) == 1
        assert "cred:oauth-token" in gapped[0].residual_gaps
        assert not gapped[0].is_realizable()

    def test_ineffective_control_does_not_constrain(self):
        doc = {
            "controls": [
                {
                    "id": "edr",
                    "name": "EDR",
                    "kind": "edr",
                    "effective": False,
                    "defeated_by": "exec:local-admin",
                }
            ],
            "nodes": [
                {"id": "i", "kind": "internet"},
                {"id": "h", "kind": "host"},
                {"id": "d", "kind": "datastore", "criticality": 5, "impact": "total"},
            ],
            "edges": [
                {"src": "i", "dst": "h", "kind": "network"},
                {"src": "h", "dst": "d", "kind": "network", "control": "edr"},
            ],
        }
        g, _ = build_environment(doc)
        paths = enumerate_paths(g)
        assert len(paths) == 1
        assert paths[0].is_realizable()


# --------------------------------------------------------------------------
# Findings grant capabilities
# --------------------------------------------------------------------------


class TestFindingCoupling:
    def test_finding_grants_unlock_next_hop(self):
        """A CVE on the jump host must make the downstream edge traversable."""
        doc = {
            "nodes": [
                {"id": "i", "kind": "internet"},
                {"id": "jump", "kind": "host", "exposure": "open"},
                {"id": "dc", "kind": "host", "criticality": 5, "impact": "total"},
            ],
            "edges": [
                {"src": "i", "dst": "jump", "kind": "network"},
                {
                    "src": "jump",
                    "dst": "dc",
                    "kind": "identity",
                    "precondition": {"all_of": ["exec:shell"]},
                },
            ],
            "findings": [
                {
                    "id": "F1",
                    "asset": "jump",
                    "cve": "CVE-2026-9999",
                    "cvss": 9.8,
                    "grants": ["exec:shell"],
                }
            ],
        }
        g, _ = build_environment(doc)
        assert "exec:shell" in g.node("jump").grants
        # jump is exposure=open, so it is itself an entry point; the only path
        # that starts from the internet and reaches the DC must be realizable.
        paths = [p for p in enumerate_paths(g) if p.entry == "i"]
        assert len(paths) == 1
        assert paths[0].target == "dc"
        assert paths[0].is_realizable()

    def test_without_finding_path_is_blocked(self):
        doc = {
            "nodes": [
                {"id": "i", "kind": "internet"},
                {"id": "jump", "kind": "host"},
                {"id": "dc", "kind": "host", "criticality": 5, "impact": "total"},
            ],
            "edges": [
                {"src": "i", "dst": "jump", "kind": "network"},
                {
                    "src": "jump",
                    "dst": "dc",
                    "kind": "identity",
                    "precondition": {"all_of": ["exec:shell"]},
                },
            ],
        }
        g, _ = build_environment(doc)
        assert enumerate_paths(g) == []

    def test_finding_for_unknown_asset_rejected(self):
        with pytest.raises(IngestError):
            build_environment(
                {
                    "nodes": [{"id": "a", "kind": "host"}],
                    "edges": [],
                    "findings": [{"id": "F1", "asset": "nope"}],
                }
            )


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


class TestScoring:
    def test_severity_is_monotonic_and_curved(self):
        assert severity_weight(0) < severity_weight(5) < severity_weight(10)
        assert severity_weight(10) == pytest.approx(1.0)
        # Curve, not line: 9.8 should be far above 5, not 2x it.
        assert severity_weight(9.8) > 3 * severity_weight(5)

    def test_unknown_severity_is_not_zero(self):
        assert severity_weight(None) > 0

    def test_kev_dominates_model_prediction(self):
        """Confirmed exploitation must outrank a low EPSS prediction."""
        assert likelihood(9.0, 0.001, True, "unknown") > likelihood(9.0, 0.001, False, "unknown")

    def test_cvss_alone_does_not_win(self):
        """High CVSS on an unreachable asset must lose to a reachable one."""
        dark = Node("dark", "Dark", NodeKind.HOST, criticality=3, exposure=Exposure.SMALL)
        exposed = Node("exp", "Exp", NodeKind.HOST, criticality=3, exposure=Exposure.OPEN)
        f_big = Finding("F1", "dark", cvss=9.8, epss=0.02)
        f_small = Finding("F2", "exp", cvss=7.5, epss=0.5)
        assert composite_risk(f_small, exposed).score > composite_risk(f_big, dark).score

    def test_ssvc_kev_open_act(self):
        n = Node("n", "N", NodeKind.HOST, criticality=4, exposure=Exposure.OPEN)
        d = ssvc_decide(Finding("F", "n", cvss=9.0, kev=True), n)
        assert d.priority is Priority.ACT
        assert d.sla_days == 3

    def test_ssvc_low_signal_is_track(self):
        n = Node("n", "N", NodeKind.HOST, criticality=2, exposure=Exposure.SMALL)
        d = ssvc_decide(Finding("F", "n", cvss=4.0, epss=0.001), n)
        assert d.priority in (Priority.TRACK, Priority.TRACK_STAR)
        assert d.ticket_required is False

    def test_prioritize_sorts_act_first(self):
        nodes = {
            "a": Node(
                "a", "A", NodeKind.HOST, criticality=5, exposure=Exposure.OPEN, impact=Impact.TOTAL
            ),
            "b": Node("b", "B", NodeKind.HOST, criticality=2, exposure=Exposure.SMALL),
        }
        fs = [
            Finding("low", "b", cvss=3.0, epss=0.001),
            Finding("hot", "a", cvss=9.8, epss=0.9, kev=True),
        ]
        ranked = prioritize(fs, nodes, [])
        assert ranked[0].finding.id == "hot"
        assert ranked[0].decision.priority is Priority.ACT


# --------------------------------------------------------------------------
# Chokepoints and what-if
# --------------------------------------------------------------------------


class TestChokepoints:
    def test_chokepoint_breaks_documented_paths(self):
        g = _simple_graph()
        paths = enumerate_paths(g)
        cps = rank_chokepoints(g, paths)
        assert cps
        worst = cps[0]
        assert worst.paths_total == len(paths)
        assert 0 < worst.risk_share <= 1.0

    def test_what_if_reports_zero_after_removal(self):
        g = _simple_graph()
        result = what_if(g, [], remove_edge=("web", "app"))
        assert result["after"]["paths"] == 0
        assert result["delta"]["risk_reduction_pct"] == 100.0


# --------------------------------------------------------------------------
# End-to-end on the shipped example
# --------------------------------------------------------------------------


class TestExampleEstate:
    def test_example_parses_and_assesses(self):
        doc = load_document("examples/acme-estate.json")
        a = assess(document=doc)
        assert a.counts["nodes"] == 11
        assert a.counts["paths"] >= 1
        assert 0 <= a.exposure_index <= 100
        assert a.chokepoints
        assert a.prioritized

    def test_example_has_a_realizable_path(self):
        a = assess(document=load_document("examples/acme-estate.json"))
        assert any(p.is_realizable() for p in a.paths)

    def test_assessment_serialises(self):
        a = assess(document=load_document("examples/acme-estate.json"))
        d = a.to_dict()
        assert "summary" in d and "paths" in d and "chokepoints" in d


# --------------------------------------------------------------------------
# Adversarial / hostile input
# --------------------------------------------------------------------------


class TestHostileInput:
    def test_malformed_json_raises_ingest_error(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(IngestError):
            load_document(p)

    def test_missing_file_raises(self):
        with pytest.raises(IngestError):
            load_document("/nonexistent/file.json")

    def test_missing_nodes_key_raises(self):
        with pytest.raises(IngestError):
            build_environment({"edges": []})

    def test_bad_enum_rejected(self):
        with pytest.raises(IngestError):
            build_environment({"nodes": [{"id": "a", "kind": "not-a-kind"}], "edges": []})

    def test_bad_cve_rejected(self):
        with pytest.raises(IngestError):
            build_environment(
                {
                    "nodes": [{"id": "a", "kind": "host"}],
                    "edges": [],
                    "findings": [{"id": "F", "asset": "a", "cve": "NOT-A-CVE"}],
                }
            )

    def test_cvss_out_of_range_rejected(self):
        with pytest.raises(IngestError):
            build_environment(
                {
                    "nodes": [{"id": "a", "kind": "host"}],
                    "edges": [],
                    "findings": [{"id": "F", "asset": "a", "cvss": 42}],
                }
            )

    def test_cycle_does_not_hang(self):
        """A -> B -> A must terminate rather than loop forever."""
        nodes = [
            Node("i", "I", NodeKind.INTERNET, exposure=Exposure.OPEN),
            Node("a", "A", NodeKind.HOST),
            Node("b", "B", NodeKind.HOST, criticality=5, impact=Impact.TOTAL),
        ]
        edges = [
            Edge("i", "a", EdgeKind.NETWORK),
            Edge("a", "b", EdgeKind.NETWORK),
            Edge("b", "a", EdgeKind.NETWORK),
        ]
        g = EnvironmentGraph(nodes, edges)
        paths = enumerate_paths(g, max_hops=6)
        assert len(paths) >= 1
        for p in paths:
            assert len(set(p.node_ids)) == len(p.node_ids)  # simple paths only

    def test_large_linear_graph_is_bounded(self):
        nodes = [Node("n0", "N0", NodeKind.INTERNET, exposure=Exposure.OPEN)]
        edges = []
        for i in range(1, 200):
            nodes.append(Node(f"n{i}", f"N{i}", NodeKind.HOST))
            edges.append(Edge(f"n{i-1}", f"n{i}", EdgeKind.NETWORK))
        nodes[-1] = Node("n199", "N199", NodeKind.HOST, criticality=5, impact=Impact.TOTAL)
        g = EnvironmentGraph(nodes, edges)
        paths = enumerate_paths(g, max_hops=10, max_paths=50)
        assert len(paths) <= 50
        for p in paths:
            assert p.hops <= 10
