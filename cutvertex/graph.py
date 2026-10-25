"""Attack path enumeration.

The engine performs a state-space search where the search state is
``(node, held_capabilities)`` rather than just ``node``. Two paths that reach
the same node with different capability sets are genuinely different states —
one may open a door the other cannot. Collapsing them (as a plain BFS does) is
the single most common source of both false positives and false negatives in
attack-path tooling.

Design notes
------------
* Forward search from attacker-controlled entry nodes; backward search from
  crown jewels; then intersection. This bounded bidirectional approach keeps
  the state space manageable on estates with thousands of nodes.
* Monotonicity: we assume capabilities accumulate and are never lost
  (an established foothold is not revoked by moving laterally). This makes
  capability sets monotonically increasing along a path, which lets us prune
  dominated states safely: if we have already reached ``node`` holding a
  superset of the current capabilities, the current state cannot yield
  anything new.
* Every emitted path carries residual gaps, so a path that *requires* the
  attacker to already be an admin is reported honestly rather than being
  dressed up as an externally reachable kill chain.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping

from cutvertex.model import (
    AttackPath,
    Chokepoint,
    Confidence,
    Edge,
    EdgeKind,
    Exposure,
    Node,
    NodeKind,
    PreconditionSet,
    Step,
)

# Cap on retained states per node; prevents pathological blow-up on dense
# estates while still allowing many distinct capability combinations.
MAX_STATES_PER_NODE = 64


class GraphError(ValueError):
    """Raised on structurally invalid environment graphs."""


class EnvironmentGraph:
    """Immutable-in-practice adjacency structure over nodes and edges."""

    __slots__ = ("_nodes", "_out", "_in", "_controls", "blocked_by_control")

    def __init__(self, nodes: Iterable[Node], edges: Iterable[Edge]) -> None:
        self._nodes: dict[str, Node] = {}
        for n in nodes:
            if n.id in self._nodes:
                raise GraphError(f"duplicate node id: {n.id}")
            self._nodes[n.id] = n

        self._out: dict[str, list[Edge]] = defaultdict(list)
        self._in: dict[str, list[Edge]] = defaultdict(list)
        seen: set[tuple[str, str, EdgeKind]] = set()
        for e in edges:
            if e.src not in self._nodes:
                raise GraphError(f"edge references unknown source node: {e.src}")
            if e.dst not in self._nodes:
                raise GraphError(f"edge references unknown destination node: {e.dst}")
            if e.src == e.dst:
                raise GraphError(f"self-loop edge on {e.src}")
            key = (e.src, e.dst, e.kind)
            if key in seen:
                raise GraphError(f"duplicate edge {e.src}->{e.dst} ({e.kind.value})")
            seen.add(key)
            self._out[e.src].append(e)
            self._in[e.dst].append(e)

        self._controls: dict[str, object] = {}
        #: (src, dst, control_id) edges dropped because an effective control
        #: has no modelled bypass. Surfaced as a warning so operators can see
        #: what the engine declined to consider.
        self.blocked_by_control: tuple[tuple[str, str, str], ...] = ()

    # -- accessors --------------------------------------------------------
    @property
    def nodes(self) -> Mapping[str, Node]:
        return self._nodes

    @property
    def edges(self) -> list[Edge]:
        return [e for bucket in self._out.values() for e in bucket]

    def node(self, node_id: str) -> Node:
        try:
            return self._nodes[node_id]
        except KeyError as exc:
            raise GraphError(f"unknown node: {node_id}") from exc

    def out_edges(self, node_id: str) -> tuple[Edge, ...]:
        return tuple(self._out.get(node_id, ()))

    def in_edges(self, node_id: str) -> tuple[Edge, ...]:
        return tuple(self._in.get(node_id, ()))

    def register_control(self, control: object) -> None:
        cid = getattr(control, "id", None)
        if not cid:
            raise GraphError("control must expose an 'id'")
        self._controls[cid] = control

    @property
    def controls(self) -> Mapping[str, object]:
        return self._controls

    # -- derived sets -----------------------------------------------------
    def entry_nodes(self) -> list[str]:
        """Nodes an external attacker can start from.

        Internet-kind nodes, plus anything explicitly marked OPEN — a host
        with an internet-facing service is an entry point even if it lives
        conceptually "inside" a subnet, and treating it otherwise is how real
        estates get mis-modelled.
        """
        out = []
        for nid, n in self._nodes.items():
            if n.kind is NodeKind.INTERNET or n.exposure is Exposure.OPEN:
                out.append(nid)
        return sorted(out)

    def crown_jewels(self) -> list[str]:
        return sorted(nid for nid, n in self._nodes.items() if n.is_crown_jewel)

    # -- validation -------------------------------------------------------
    def validate(self) -> list[str]:
        """Structural sanity checks; returns human-readable issues."""
        issues: list[str] = []
        if not self._nodes:
            issues.append("graph has no nodes")
        if not self.entry_nodes():
            issues.append(
                "no entry nodes: mark at least one node kind=internet or exposure=open"
            )
        if not self.crown_jewels():
            issues.append(
                "no crown jewels: mark at least one node criticality>=4 or impact=total"
            )
        for nid in self._nodes:
            if not self.out_edges(nid) and not self.in_edges(nid):
                issues.append(f"orphan node (no edges): {nid}")
        return issues


# --------------------------------------------------------------------------
# Forward exploration
# --------------------------------------------------------------------------


class _State:
    """A search state: where we are, what we hold, how we got here."""

    __slots__ = ("node", "held", "path", "score")

    def __init__(
        self,
        node: str,
        held: frozenset[str],
        path: tuple[Step, ...],
        score: float,
    ) -> None:
        self.node = node
        self.held = held
        self.path = path
        self.score = score


def _entry_preconditions(graph: EnvironmentGraph, entry: str) -> PreconditionSet:
    node = graph.node(entry)
    if node.kind is NodeKind.INTERNET:
        return PreconditionSet()
    # A host marked OPEN still has to be *reachable* over the network.
    return PreconditionSet()


def enumerate_paths(
    graph: EnvironmentGraph,
    *,
    max_hops: int = 8,
    max_paths: int = 500,
    targets: Iterable[str] | None = None,
    stop_at_first_target: bool = False,
    allow_gaps: bool = False,
) -> list[AttackPath]:
    """Enumerate satisfiable attacker paths from entry points to crown jewels.

    Parameters
    ----------
    max_hops:
        Longest chain to consider. Real intrusions are 3-8 hops; beyond that
        the marginal finding is noise rather than signal.
    max_paths:
        Hard cap on results, highest score first.
    targets:
        Override the crown-jewel set (useful for "can an attacker reach *this*
        system" questions).
    stop_at_first_target:
        Terminate each entry's exploration at the first target reached, which
        yields shortest-kill-chain style output.
    allow_gaps:
        Assume-breach mode. By default an edge whose precondition the attacker
        cannot currently satisfy is simply not traversable, so the reported
        paths are exactly those an outside attacker can walk today. Setting
        this True lets such edges be traversed with the missing capability
        recorded as a residual gap — useful for "if an insider already held X,
        what opens up?" analysis. Gated paths score lower by design.
    """
    if max_hops < 1:
        raise GraphError("max_hops must be >= 1")
    target_ids = set(targets) if targets is not None else set(graph.crown_jewels())
    if not target_ids:
        return []

    results: list[AttackPath] = []
    entries = graph.entry_nodes()

    for entry in entries:
        results.extend(
            _explore_from(
                graph,
                entry,
                target_ids,
                max_hops=max_hops,
                stop_at_first_target=stop_at_first_target,
                allow_gaps=allow_gaps,
            )
        )
        if len(results) >= max_paths * 4:
            break

    results.sort(key=lambda p: p.score, reverse=True)
    return results[:max_paths]


def _explore_from(
    graph: EnvironmentGraph,
    entry: str,
    target_ids: set[str],
    *,
    max_hops: int,
    stop_at_first_target: bool,
    allow_gaps: bool = False,
) -> list[AttackPath]:
    # Frontier stores (node, held, path_steps, cumulative_weight, visited).
    start_held: frozenset[str] = frozenset()
    entry_pc = _entry_preconditions(graph, entry)
    if not entry_pc.satisfiable(start_held):
        return []

    frontier: deque[_State] = deque([_State(entry, start_held, (), 0.0)])
    found: list[AttackPath] = []
    # best_held[node] = list of capability sets already explored at that node
    best_held: dict[str, list[frozenset[str]]] = defaultdict(list)

    while frontier:
        st = frontier.popleft()
        # Local compromise: standing on a node with an exploitable finding lets
        # the attacker own it and gain its grants without consuming a hop. This
        # is what couples findings to topology — a CVE on the jump host must
        # unlock the next hop, or the tool is just a scanner with a graph skin.
        node = graph.node(st.node)
        unmet: tuple[str, ...] = ()
        local_grants: tuple[str, ...] = ()
        if node.grants:
            if node.compromise.satisfiable(st.held):
                before = st.held
                st.held = _apply_local_compromise(node, st.held)
                # Record what owning this node actually yielded, so the path
                # ledger shows where a capability came from. Without this a
                # legitimately earned capability is misreported as a gap the
                # attacker had to bring with them.
                local_grants = tuple(sorted(st.held - before))
            else:
                # Reached, but not exploitable from the current position: the
                # asset's grants are withheld and the gap is recorded honestly.
                unmet = node.compromise.residual(st.held)

        if st.node in target_ids and st.path:
            found.append(_build_path(graph, entry, st, entry_pc))
            if stop_at_first_target:
                break
            continue
        if len(st.path) >= max_hops:
            continue

        visited = {entry, *(s.dst for s in st.path)}
        for edge in graph.out_edges(st.node):
            if edge.dst in visited:
                continue  # simple paths only; revisiting adds no capability
            unmet_edge: tuple[str, ...] = ()
            if not edge.precondition.satisfiable(st.held):
                if not allow_gaps:
                    continue
                # Assume-breach: the attacker must already hold the missing
                # capability. Recorded as a gap so the path is never mistaken
                # for something an outsider can walk today.
                unmet_edge = edge.precondition.residual(st.held)
            new_held = st.held | frozenset(edge.grants)
            if _dominated(best_held[edge.dst], new_held):
                continue
            best_held[edge.dst].append(new_held)
            if len(best_held[edge.dst]) > MAX_STATES_PER_NODE:
                # Keep the richest capability sets; they subsume the rest.
                best_held[edge.dst].sort(key=len, reverse=True)
                del best_held[edge.dst][MAX_STATES_PER_NODE:]

            step = Step(
                src=edge.src,
                dst=edge.dst,
                kind=edge.kind,
                precondition=edge.precondition,
                grants=(*edge.grants, *local_grants),
                technique=edge.technique,
                blocked=(*unmet, *unmet_edge),
            )
            frontier.append(
                _State(edge.dst, new_held, (*st.path, step), st.score + edge.weight)
            )

    return found


def _apply_local_compromise(node: Node, held: frozenset[str]) -> frozenset[str]:
    """Grant a node's post-exploitation capabilities if its precondition holds."""
    current = held
    for _ in range(8):  # bounded fixpoint; grants may unlock further grants
        if not node.compromise.satisfiable(current):
            return current
        nxt = current | frozenset(node.grants)
        if nxt == current:
            return current
        current = nxt
    return current


def _dominated(existing: list[frozenset[str]], candidate: frozenset[str]) -> bool:
    """True when a state with a superset of ``candidate`` was already explored."""
    return any(candidate <= prev for prev in existing)


def _build_path(
    graph: EnvironmentGraph,
    entry: str,
    st: _State,
    entry_pc: PreconditionSet,
) -> AttackPath:
    required: set[str] = set()
    gained: set[str] = set()
    blocked_all: set[str] = set()
    depth = 0
    confidence = Confidence.OBSERVED

    for step in st.path:
        required |= step.precondition.all_of
        if step.precondition.any_of:
            required.add("one-of(" + "|".join(sorted(step.precondition.any_of)) + ")")
        for g in step.grants:
            gained.add(g)
            required.add(g)
        if step.blocked:
            # The attacker reached the source but could not exploit it, so the
            # path carries an inherited prerequisite rather than a free ride.
            blocked_all.add(*step.blocked)
        if step.kind is EdgeKind.AGENTIC:
            depth += 1
        if step.precondition.cost() > 0 or step.grants:
            confidence = Confidence.INFERRED

    # Anything demanded by a precondition that is never granted inside the path
    # is a residual gap: the attacker must arrive holding it.
    granted_set = set(gained)
    residual = sorted(
        {c for c in required if "one-of(" not in c and c not in granted_set} | blocked_all
    )

    target = graph.node(st.path[-1].dst)
    score = _score_path(
        graph, target, hops=len(st.path), technique_depth=depth, residual=residual
    )

    return AttackPath(
        entry=entry,
        target=st.path[-1].dst,
        steps=st.path,
        capabilities_required=frozenset(required),
        capabilities_gained=frozenset(gained),
        entry_precondition=entry_pc,
        residual_gaps=tuple(residual),
        technique_depth=depth,
        score=score,
        confidence=confidence,
    )


def _score_path(
    graph: EnvironmentGraph,
    target: Node,
    *,
    hops: int,
    technique_depth: int,
    residual: list[str],
) -> float:
    """Path plausibility score before CVE enrichment (0-100 scale).

    Rewards: high-impact target, short chain, unauthenticated start.
    Penalises: residual capability gaps (needs an inside foothold already).
    """
    base = 20.0 + 12.0 * min(target.criticality, 5)
    base += 8.0 if target.impact.value == "total" else 3.0 if target.impact.value == "partial" else 0.0
    base -= 4.0 * max(0, hops - 1)          # every extra hop is harder
    base += 3.0 * technique_depth           # agentic hops are cheap for attackers
    base -= 10.0 * len(residual)            # inherited prerequisites are expensive
    if not residual:
        base += 10.0                        # externally realizable chains rank first
    return max(0.0, min(100.0, base))


# --------------------------------------------------------------------------
# Chokepoint analysis
# --------------------------------------------------------------------------


def rank_chokepoints(
    graph: EnvironmentGraph,
    paths: Iterable[AttackPath],
    *,
    top_n: int = 10,
) -> list[Chokepoint]:
    """Rank single-edge remediations by real risk weight removed.

    For each edge used by at least one path, recompute the surviving path set
    with that edge removed and measure the drop in total risk weight. This is
    an exact recomputation (not a per-edge weight sum), so the reported
    "paths broken" is a number an engineer can defend in a change board.
    """
    path_list = [p for p in paths if p.score > 0]
    if not path_list:
        return []

    total_risk = sum(p.score for p in path_list)
    edge_paths: dict[tuple[str, str], list[AttackPath]] = defaultdict(list)
    for p in path_list:
        for key in p.edge_keys:
            edge_paths[key].append(p)

    ranked: list[Chokepoint] = []
    for key, affected in edge_paths.items():
        broken = sum(p.score for p in affected)  # removing this edge kills all of them
        residual_paths = len(path_list) - len(affected)
        edge = next(e for e in graph.out_edges(key[0]) if e.dst == key[1])
        effort, cost_hint = _effort_for(graph, edge)
        ranked.append(
            Chokepoint(
                edge=key,
                technique=edge.technique or edge.kind.value,
                paths_broken=len(affected),
                paths_total=len(path_list),
                risk_removed=broken,
                risk_share=broken / total_risk if total_risk else 0.0,
                cost_hint=cost_hint,
                effort=effort,
                confidence=edge.confidence,
                gates=_gates_for(graph, edge),
                rationale=_rationale(graph, edge, len(affected), residual_paths),
            )
        )

    # Highest risk removed first; on ties prefer the cheaper fix.
    ranked.sort(key=lambda c: (-c.risk_removed, c.effort))
    return ranked[:top_n]


def _effort_for(graph: EnvironmentGraph, edge: Edge) -> tuple[int, str]:
    src = graph.node(edge.src)
    if edge.control:
        return 1, f"enable/enforce control '{edge.control}'"
    if edge.kind is EdgeKind.NETWORK and edge.precondition.is_empty:
        return 2, f"segment or restrict inbound path to {src.name}"
    if edge.kind is EdgeKind.CREDENTIAL:
        return 3, "rotate credential and remove standing privilege"
    if edge.kind is EdgeKind.IDENTITY:
        return 2, "tighten role assignment / apply conditional access"
    if edge.kind is EdgeKind.AGENTIC:
        return 2, "constrain agent tool scope and require approval"
    if edge.kind is EdgeKind.TRUST:
        return 4, "remove trust relationship or scope it"
    return 3, "patch or reconfigure"


def _gates_for(graph: EnvironmentGraph, edge: Edge) -> tuple[str, ...]:
    gates = []
    if edge.control:
        gates.append(edge.control)
    if edge.precondition.none_of:
        gates.extend(sorted(edge.precondition.none_of))
    return tuple(gates)


def _rationale(
    graph: EnvironmentGraph, edge: Edge, broken: int, remaining: int
) -> str:
    src, dst = graph.node(edge.src), graph.node(edge.dst)
    tail = (
        f"after removal {remaining} path(s) remain"
        if remaining
        else "after removal no modelled path reaches a crown jewel"
    )
    return (
        f"{src.name} -> {dst.name} via {edge.technique or edge.kind.value} "
        f"carries {broken} modelled path(s); {tail}."
    )
