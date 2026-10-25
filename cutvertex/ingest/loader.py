"""Ingest of environment graphs, findings and CVE enrichment.

Everything entering the engine passes through here and is validated before it
can influence a finding. A tool that silently accepts malformed inventory and
then emits a confident risk ranking is worse than no tool: it launders bad
data into a change board.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cutvertex.graph import EnvironmentGraph, GraphError
from cutvertex.model import (
    CapabilityError,
    Confidence,
    Control,
    Edge,
    EdgeKind,
    Exposure,
    Finding,
    Impact,
    Node,
    NodeKind,
    PreconditionSet,
)

MAX_NODES = 50_000
MAX_EDGES = 250_000
MAX_FILE_BYTES = 32 * 1024 * 1024
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class IngestError(ValueError):
    """Raised when ingested data violates the documented schema."""


# --------------------------------------------------------------------------
# Primitive parsers
# --------------------------------------------------------------------------


def _need(obj: dict, key: str, ctx: str) -> Any:
    if key not in obj:
        raise IngestError(f"{ctx}: missing required field '{key}'")
    return obj[key]


def _enum(value: Any, enum_cls: type, ctx: str) -> Any:
    try:
        return enum_cls(str(value).lower())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in enum_cls)
        raise IngestError(f"{ctx}: '{value}' is not one of [{allowed}]") from exc


def _num(value: Any, ctx: str, lo: float, hi: float) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError) as exc:
        raise IngestError(f"{ctx}: expected a number, got {value!r}") from exc
    if not (lo <= n <= hi):
        raise IngestError(f"{ctx}: {n} outside allowed range [{lo}, {hi}]")
    return n


def _str_list(value: Any, ctx: str, limit: int = 64) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise IngestError(f"{ctx}: expected a list")
    if len(value) > limit:
        raise IngestError(f"{ctx}: at most {limit} entries allowed")
    return tuple(str(v) for v in value)


def _id(value: Any, ctx: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IngestError(f"{ctx}: id must be a non-empty string")
    if len(value) > 128:
        raise IngestError(f"{ctx}: id longer than 128 characters")
    return value.strip()


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------


def parse_node(raw: dict, idx: int) -> Node:
    ctx = f"nodes[{idx}]"
    if not isinstance(raw, dict):
        raise IngestError(f"{ctx}: expected an object")
    nid = _id(_need(raw, "id", ctx), f"{ctx}.id")
    ctx = f"node '{nid}'"
    crit = _num(raw.get("criticality", 1), f"{ctx}.criticality", 1, 5)
    try:
        return Node(
            id=nid,
            name=str(raw.get("name", nid))[:200],
            kind=_enum(_need(raw, "kind", ctx), NodeKind, f"{ctx}.kind"),
            criticality=int(crit),
            exposure=_enum(raw.get("exposure", "small"), Exposure, f"{ctx}.exposure"),
            impact=_enum(raw.get("impact", "partial"), Impact, f"{ctx}.impact"),
            owner=str(raw.get("owner", "unassigned"))[:120],
            tags=_str_list(raw.get("tags"), f"{ctx}.tags"),
            cves=tuple(
                c.upper()
                for c in _str_list(raw.get("cves"), f"{ctx}.cves")
                if _CVE_RE.match(c)
            ),
            controls=_str_list(raw.get("controls"), f"{ctx}.controls"),
            confidence=_enum(
                raw.get("confidence", "observed"), Confidence, f"{ctx}.confidence"
            ),
            attributes=tuple(
                (str(k)[:64], str(v)[:256])
                for k, v in (raw.get("attributes") or {}).items()
            ),
        )
    except CapabilityError as exc:
        raise IngestError(f"{ctx}: {exc}") from exc


def parse_edge(raw: dict, idx: int) -> Edge:
    ctx = f"edges[{idx}]"
    if not isinstance(raw, dict):
        raise IngestError(f"{ctx}: expected an object")
    src = _id(_need(raw, "src", ctx), f"{ctx}.src")
    dst = _id(_need(raw, "dst", ctx), f"{ctx}.dst")
    ctx = f"edge '{src}'->'{dst}'"
    try:
        pre = PreconditionSet.from_dict(raw.get("precondition"))
    except CapabilityError as exc:
        raise IngestError(f"{ctx}: {exc}") from exc
    weight = raw.get("weight", 1.0)
    return Edge(
        src=src,
        dst=dst,
        kind=_enum(_need(raw, "kind", ctx), EdgeKind, f"{ctx}.kind"),
        precondition=pre,
        grants=_str_list(raw.get("grants"), f"{ctx}.grants"),
        confidence=_enum(raw.get("confidence", "observed"), Confidence, f"{ctx}.confidence"),
        control=(str(raw["control"])[:120] if raw.get("control") else None),
        technique=str(raw.get("technique", ""))[:200],
        weight=_num(weight, f"{ctx}.weight", 0.0, 100.0),
    )


def parse_control(raw: dict, idx: int) -> Control:
    ctx = f"controls[{idx}]"
    if not isinstance(raw, dict):
        raise IngestError(f"{ctx}: expected an object")
    cid = _id(_need(raw, "id", ctx), f"{ctx}.id")
    return Control(
        id=cid,
        name=str(raw.get("name", cid))[:200],
        kind=str(raw.get("kind", "other"))[:64],
        effective=bool(raw.get("effective", True)),
        defeated_by=(str(raw["defeated_by"])[:64] if raw.get("defeated_by") else None),
        notes=str(raw.get("notes", ""))[:1000],
    )


def parse_finding(raw: dict, idx: int) -> Finding:
    ctx = f"findings[{idx}]"
    if not isinstance(raw, dict):
        raise IngestError(f"{ctx}: expected an object")
    fid = _id(_need(raw, "id", ctx), f"{ctx}.id")
    asset = _id(_need(raw, "asset", ctx), f"{ctx}.asset")
    ctx = f"finding '{fid}'"
    cve = raw.get("cve")
    if cve is not None and not _CVE_RE.match(str(cve)):
        raise IngestError(f"{ctx}: '{cve}' is not a valid CVE identifier")
    cvss = raw.get("cvss")
    epss = raw.get("epss")
    try:
        pre = PreconditionSet.from_dict(raw.get("requires"))
    except CapabilityError as exc:
        raise IngestError(f"{ctx}: {exc}") from exc
    return Finding(
        id=fid,
        asset=asset,
        cve=(str(cve).upper() if cve else None),
        title=str(raw.get("title", ""))[:300],
        cvss=(_num(cvss, f"{ctx}.cvss", 0, 10) if cvss is not None else None),
        epss=(_num(epss, f"{ctx}.epss", 0, 1) if epss is not None else None),
        kev=bool(raw.get("kev", False)),
        patch_available=bool(raw.get("patch_available", False)),
        exploit_maturity=str(raw.get("exploit_maturity", "unknown")).lower()[:32],
        grants=_str_list(raw.get("grants"), f"{ctx}.grants"),
        requires=pre,
        source=str(raw.get("source", "manual"))[:64],
    )


# --------------------------------------------------------------------------
# Document loading
# --------------------------------------------------------------------------


def load_document(path: str | Path) -> dict:
    """Read and size-check a JSON environment document."""
    p = Path(path)
    if not p.is_file():
        raise IngestError(f"no such file: {p}")
    size = p.stat().st_size
    if size > MAX_FILE_BYTES:
        raise IngestError(
            f"{p.name} is {size / 1e6:.1f} MB, above the {MAX_FILE_BYTES / 1e6:.0f} MB limit"
        )
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IngestError(f"{p.name}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise IngestError(f"{p.name}: not valid UTF-8") from exc
    if not isinstance(data, dict):
        raise IngestError(f"{p.name}: top level must be a JSON object")
    return data


def apply_findings_to_nodes(nodes: list[Node], findings: list[Finding]) -> list[Node]:
    """Attach each asset's findings to its node as post-exploitation capability.

    A node's ``grants`` become everything its findings can yield, and its
    ``compromise`` precondition is the *cheapest* finding's requirement — the
    attacker will take the easiest door. Findings whose requirement cannot be
    met simply never contribute, because the local-compromise step checks
    satisfiability at traversal time rather than assuming success.
    """
    from collections import defaultdict
    from dataclasses import replace

    by_asset: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_asset[f.asset].append(f)

    out: list[Node] = []
    for n in nodes:
        fs = by_asset.get(n.id)
        if not fs:
            out.append(n)
            continue
        grants = set(n.grants)
        for f in fs:
            grants.update(f.grants)
        cheapest = min(fs, key=lambda f: (f.requires.cost(), f.id))
        out.append(
            replace(
                n,
                grants=tuple(sorted(grants)),
                compromise=cheapest.requires,
            )
        )
    return out


def build_environment(doc: dict) -> tuple[EnvironmentGraph, list[Finding]]:
    """Validate a document and construct the graph plus findings."""
    raw_nodes = _need(doc, "nodes", "document")
    raw_edges = doc.get("edges", [])
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise IngestError("'nodes' and 'edges' must be arrays")
    if len(raw_nodes) > MAX_NODES:
        raise IngestError(f"too many nodes ({len(raw_nodes)} > {MAX_NODES})")
    if len(raw_edges) > MAX_EDGES:
        raise IngestError(f"too many edges ({len(raw_edges)} > {MAX_EDGES})")

    nodes = [parse_node(n, i) for i, n in enumerate(raw_nodes)]
    edges = [parse_edge(e, i) for i, e in enumerate(raw_edges)]
    controls = [parse_control(c, i) for i, c in enumerate(doc.get("controls", []))]

    # Control efficacy, modelled honestly:
    #
    # * effective control WITH a known bypass  -> the edge becomes gated: the
    #   attacker must hold the bypass capability (e.g. a stolen OAuth token
    #   makes MFA moot). Required, not forbidden — holding the bypass is what
    #   opens the door, so it belongs in all_of.
    # * effective control WITHOUT a known bypass -> the edge is genuinely
    #   impassable under the current model. It is dropped, counted, and
    #   reported, rather than silently pretending a path exists.
    by_id = {c.id: c for c in controls}
    patched: list[Edge] = []
    blocked_by_control: list[tuple[str, str, str]] = []
    for e in edges:
        ctrl = by_id.get(e.control) if e.control else None
        if ctrl is not None and ctrl.effective and ctrl.defeated_by:
            pre = e.precondition.union(PreconditionSet.require(ctrl.defeated_by))
            patched.append(
                Edge(
                    src=e.src, dst=e.dst, kind=e.kind, precondition=pre,
                    grants=e.grants, confidence=e.confidence, control=e.control,
                    technique=e.technique, weight=e.weight,
                )
            )
        elif ctrl is not None and ctrl.effective:
            blocked_by_control.append((e.src, e.dst, ctrl.id))
        else:
            patched.append(e)

    try:
        graph = EnvironmentGraph(nodes, patched)
    except GraphError as exc:
        raise IngestError(str(exc)) from exc
    for c in controls:
        graph.register_control(c)

    findings = [parse_finding(f, i) for i, f in enumerate(doc.get("findings", []))]
    known = set(graph.nodes)
    orphans = sorted({f.asset for f in findings if f.asset not in known})
    if orphans:
        raise IngestError(
            "findings reference assets that are not in the graph: " + ", ".join(orphans[:10])
        )

    # Findings grant capabilities. Rebuild with enriched nodes so that a CVE on
    # one host actually unlocks the next hop in the chain.
    if findings:
        enriched = apply_findings_to_nodes(nodes, findings)
        try:
            graph = EnvironmentGraph(enriched, patched)
        except GraphError as exc:
            raise IngestError(str(exc)) from exc
        for c in controls:
            graph.register_control(c)

    graph.blocked_by_control = tuple(blocked_by_control)
    return graph, findings


def merge_enrichment(
    findings: list[Finding], enrichment: dict[str, dict]
) -> list[Finding]:
    """Overlay CVE enrichment (EPSS/KEV) onto findings by CVE id.

    Ingested data wins where it already carries a value: an operator who has
    manually verified exploitation status should not have it silently
    overwritten by a feed.
    """
    out: list[Finding] = []
    for f in findings:
        if not f.cve or f.cve not in enrichment:
            out.append(f)
            continue
        e = enrichment[f.cve]
        out.append(
            Finding(
                id=f.id, asset=f.asset, cve=f.cve, title=f.title,
                cvss=f.cvss if f.cvss is not None else e.get("cvss"),
                epss=f.epss if f.epss is not None else e.get("epss"),
                kev=f.kev or bool(e.get("kev", False)),
                patch_available=f.patch_available,
                exploit_maturity=e.get("exploit_maturity", f.exploit_maturity),
                grants=f.grants, requires=f.requires, source=f.source,
            )
        )
    return out
