# CutVertex — Architecture

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.

---

## 1. The problem, stated precisely

Given an estate of assets, a set of vulnerabilities on those assets, and the trust and
network relationships between them, determine:

1. Which assets an external attacker can reach, and by what chain.
2. Which *single* remediation removes the most risk.
3. In what order the rest should be fixed, defensibly.

Naive approaches fail in specific, predictable ways.

**Naive approach A — scan and sort by CVSS.** Ignores topology entirely. A CVSS 9.8 on an
air-gapped build box outranks a 6.5 on the VPN concentrator. This is the default failure
mode of the industry and the reason security teams distrust their own dashboards.

**Naive approach B — graph reachability.** Better, but wrong. Reachability asks "is there a
path?" when the real question is "is there a path *this attacker* can walk?" An edge that
requires domain credentials is not available to an external attacker, yet plain BFS walks it
happily and produces a kill chain that a competent engineer will dismiss — correctly — as
fiction. One debunked finding discredits the whole report.

**Naive approach C — per-edge risk sum.** To rank fixes, sum the risk of paths through each
edge. This double-counts and misranks: two edges on the same path each appear to carry the
full risk, so a trivial fix on a redundant path outranks a structural one.

CutVertex addresses all three: preconditions (B), exact recomputation for ranking (C), and
graph exposure in the score (A).

---

## 2. Core abstraction: capabilities

The central design decision is that traversal is a **satisfiability question over a
capability set**, not a reachability question.

```python
PreconditionSet(all_of={"net:reach"}, any_of=set(), none_of={"exec:local-admin"})
```

A capability is a namespaced string. The built-in vocabulary:

| Namespace | Examples | Meaning |
|---|---|---|
| `net:` | `net:reach`, `net:smb`, `net:mgmt-plane` | network positions |
| `exec:` | `exec:shell`, `exec:code`, `exec:local-admin` | code execution |
| `cred:` | `cred:hash`, `cred:plaintext`, `cred:cloud-key`, `cred:oauth-token` | credential material |
| `id:` | `id:domain-user`, `id:privileged`, `id:tier0` | identity position |
| `secret:` | `secret:read` | data access |
| `agent:` | `agent:prompt-inject`, `agent:tool-invoke`, `agent:mcp-server` | AI-agent surface |

Capabilities are plain strings rather than an enum for one reason: data from Entra ID, AWS,
CrowdStrike, and a CMDB has to normalise into one vocabulary without a schema migration per
source. Validation is a regex (`^[a-z0-9][a-z0-9_:.\-/]{0,63}$`) plus a contradiction check
— requiring and forbidding the same capability is rejected at construction, which caught a
real modelling error in the author's own example data during development.

### The lattice

Sets form a lattice under `union`. Path accumulation uses union, so a chain is only as cheap
as its combined prerequisites. `cost()` gives a heuristic difficulty in abstract units, used
to pick the cheapest door when an asset has multiple findings.

### Why not just use a weight?

A weight is a scalar and cannot express "needs a hash *or* a plaintext credential, but not
while EDR is enforcing". Disjunctions and hard blockers are not compressible into a number
without lying. The price of the richer model is that you must declare the capabilities — and
that declaration is exactly the work that makes the output defensible.

---

## 3. Graph model

```
Node(id, name, kind, criticality, exposure, impact, owner, cves,
     grants,          # what owning this asset yields
     compromise)      # what exploiting it requires
Edge(src, dst, kind, precondition, grants, control, technique, confidence)
```

`EdgeKind`: `network`, `identity`, `credential`, `trust`, `data_flow`, `agentic`.

Construction validates hard: duplicate node ids, edges to unknown nodes, self-loops, and
duplicate `(src, dst, kind)` triples all raise. An adjacency structure built on malformed
inventory produces confident nonsense, so it is rejected early rather than tolerated.

### Control semantics

Two distinct behaviours, both deliberate:

```python
if control.effective and control.defeated_by:
    precondition |= require(control.defeated_by)   # gated: bypass is the key
elif control.effective:
    drop_edge(); record_in(blocked_by_control)     # impassable under this model
else:
    pass                                           # control not enforced
```

The first case is the counter-intuitive one. Holding the bypass capability does not *forbid*
traversal — it *enables* it. A stolen OAuth token makes MFA moot, so the edge requires the
token. Getting this backwards (forbidding the bypass) silently deletes every path through a
protected edge, which is precisely the bug this project hit and fixed during development.

The second case is honesty: if you believe a control is effective and no bypass is modelled,
there is no path. Saying so — and listing exactly which edges were dropped — is better than
inventing plausible chains through a wall you trust.

---

## 4. The search algorithm

State is `(node, held_capabilities)`. Two paths reaching the same node with different
capability sets are genuinely different states: one may open a door the other cannot.
Collapsing them — as plain BFS does — causes both false positives and false negatives.

```
frontier = [(entry, {}, [])]
while frontier:
    state = pop(frontier)
    # local compromise: owning this node may yield its grants
    if node.grants and node.compromise.satisfiable(state.held):
        state.held |= node.grants
    elif node.grants:
        record_gap(node.compromise.residual(state.held))

    if node is a target: emit path; continue
    for edge in out_edges(node):
        if not edge.precondition.satisfiable(state.held):   # strict mode
            continue
        new_held = state.held | edge.grants
        if dominated(best_held[edge.dst], new_held):        # pruning
            continue
        push((edge.dst, new_held, path + [step]))
```

### Monotonicity and safe pruning

Capabilities accumulate and are never lost — an established foothold is not revoked by
moving laterally. Sets are therefore monotonically increasing along a path, which makes
domination pruning sound: if we already reached `node` holding a **superset** of the current
capabilities, the current state yields nothing new and is dropped. This is what keeps the
search tractable on dense estates.

Bounds: `MAX_STATES_PER_NODE = 64` (richest sets retained), `max_hops` (default 8 — real
intrusions are 3-8 hops; beyond that marginal findings are noise), `max_paths` (500).

Cycles: simple paths only. Revisiting a node adds no capability, so cycles are pure
explosion. This is verified by test (`test_cycle_does_not_hang`).

### Local compromise — the coupling that matters

Without a local-compromise step, findings and topology are unrelated: a CVE adds a row, but
the graph never learns that exploiting it yields a shell. The step above is what makes the
tool an *attack path* analyser rather than a scanner with a graph skin.

Grants earned this way are recorded in `Step.grants` alongside edge grants. Omitting them
was a real bug: a legitimately earned capability then appeared in `residual_gaps`, marking a
walkable path as gated. The path ledger must show *where* each capability came from.

---

## 5. Chokepoint ranking

For each edge used by at least one path, recompute the surviving path set with that edge
removed:

```
risk_removed(edge) = Σ score(path) for path containing edge
paths_broken(edge) = |{path : edge ∈ path}|
```

This is exact recomputation, not a per-edge weight sum, so "breaks 3 of 4 paths, 71% of
risk" is a number an engineer can defend in a change board. `what_if()` exposes the same
mechanism as a first-class CLI command so a recommendation is falsifiable *before* the change
is made.

Ranking: `(-risk_removed, effort)`. Effort is derived from edge kind and existing controls —
enabling an already-present control is cheaper than restructuring a trust relationship.

---

## 6. Scoring pipeline

```
Finding ──┐
          ├─► severity_weight(cvss)      (cvss/10)^3
          ├─► likelihood(epss,kev,maturity)
          ├─► exposure_multiplier(node, on_path, path_score)
          └─► asset_criticality(node)
                    │
                    ▼
      risk = 100 · sev^.35 · like^.30 · crit^.20 · expo^.15 · path_factor
```

Geometric weighting is deliberate: an arithmetic sum lets a high severity on an unreachable
asset beat a moderate severity on a verified kill chain. With a product, every factor must be
non-trivial. Verified by test (`test_cvss_alone_does_not_win`).

`path_factor` is `1 + 0.75·(best_path/100)` when the asset is on a verified path, `0.35`
otherwise — a 3x swing that encodes the central claim of the project.

### SSVC deployer tree

Ordering follows CISA's deployer tree, and the ordering is the substance:

```
exploitation == active?
  ├─ exposure == open        → ACT     (3 days)
  ├─ exposure == controlled  → ACT     (3 days)
  └─ exposure == small       → ATTEND  (14 days)
exploitation == poc?
  ├─ open + automatable      → ACT
  ├─ open                    → ATTEND
  ├─ controlled + automatable→ ATTEND
  └─ else                    → TRACK*
else
  ├─ open + high impact      → ATTEND
  ├─ open                    → TRACK*
  └─ else                    → TRACK   (90 days)
```

Exploitation state comes first because it dominates: it is what stops a theoretical CVSS 10
on an isolated lab box from outranking a KEV-listed bug on the VPN concentrator. A realizable
path upgrades anything short of `act` by one tier.

---

## 7. Ingest: validation first

Every document is size-checked (32 MB), encoding-checked, schema-checked, and range-checked
before it can influence a finding. Enum values are validated against the real enum, so an
error message names the accepted values. CVE ids are regex-checked. Findings referencing
assets absent from the graph are rejected outright — silently dropping them would hide
inventory drift, which is itself a finding.

This layer exists because a tool that accepts malformed input and then emits a confident
ranking launders bad data into a change board, and the damage lands on whoever acted on it.

---

## 8. Report rendering

`report_html.py` emits a single self-contained file: no CDN, no external fonts, no JS
dependencies. A security report that phones home to a third party — or cannot be opened on
an air-gapped review laptop — is not a usable report.

Safety: the JSON payload is escaped (`<`, `>`, `&`, U+2028, U+2029) before embedding in a
`<script type="application/json">` block, so an asset named `</script><img onerror=...>`
cannot break out. All dynamic content is inserted with `textContent`/DOM APIs, never
`innerHTML`. Verified by rendering in headless Chromium with zero console errors.

---

## 9. Remediation tracking

The state machine is the audit trail. `TRANSITIONS` is an explicit allow-list; anything not
listed raises. `verified` requires an evidence reference. `risk_accepted` requires a
justification. Reopen is permitted only from `verified`/`closed` → `in_progress` and
increments `reopened_count`.

That last detail is what makes the reopen rate honest. A workflow that lets you mark
something closed and then quietly reopen it as a new ticket has no reopen rate at all — it
has two tickets and a fiction.

---

## 10. What is deliberately absent

- **Collection.** No connectors. The graph is provided.
- **Probabilistic capabilities.** Boolean, not Bayesian.
- **Time.** No drift, no trending, no snapshots.
- **Exploit validation.** Structural exposure only; no proof of exploitability.
- **Persistence.** Reports are files. There is no database.

Each is a deliberate boundary, not an oversight. The value of the current design is that the
reasoning is inspectable end to end; adding collection without that clarity would produce
another dashboard nobody trusts.
