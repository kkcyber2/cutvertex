# CutVertex

**Precondition-aware attack path analysis and remediation chokepoint ranking.**

CutVertex answers one question that most exposure-management tools answer badly:

> *If we fix exactly one thing this sprint, which change removes the most real attacker risk?*

It does so by modelling an environment as a directed graph where every edge carries the
capabilities an attacker must already hold to traverse it. Paths are then *satisfiability*
problems over capability sets, not reachability walks. The difference matters: a plain
climb from the internet to the domain controller will happily route through a firewall rule
that only works for an authenticated insider, and report it as an external kill chain.

Author: **kk ([kkdev9715](https://github.com/kkcyber2))**
License: **Proprietary — All Rights Reserved.** See [LICENSE](LICENSE).

---

## Why this exists

CVSS-only queues rank a 9.8 on an isolated lab box above a 6.5 on the internet-facing jump
host that sits on a verified path to Tier 0. Every security team knows this is wrong, and
most still ship it, because the alternative — manually reasoning about topology — does not
scale past a few dozen assets.

Existing tools solve adjacent problems:

| Category | What it does well | What it does not do |
|---|---|---|
| Vulnerability scanners | Find CVEs on assets | Know whether the asset is reachable, or what compromising it unlocks |
| CVSS/EPSS/KEV feeds | Score severity and likelihood | Know anything about *your* topology |
| Attack-path platforms | Graph your estate, find paths | Are closed, expensive, cloud-first, and treat preconditions implicitly |
| AD attack-path tools (BloodHound) | Excellent for Active Directory | Are single-domain, with no cross-cloud or AI-agent coverage |
| SOAR | Automate response | Assume the prioritisation decision is already made |

CutVertex sits in the gap: **open-data, model-agnostic, precondition-explicit**, and small
enough to read in an afternoon.

---

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Requires Python 3.10+. Runtime dependencies: `fastapi`, `uvicorn`, `pydantic`.

## Use

```bash
# Full assessment, console summary
cutvertex assess examples/acme-estate.json

# Machine-readable plus a self-contained HTML report (no CDN, no JS deps)
cutvertex assess examples/acme-estate.json --out reports/report.json --html reports/report.html

# Structural validation only
cutvertex validate examples/acme-estate.json

# Counterfactual: what happens if we close exactly this edge?
cutvertex what-if examples/acme-estate.json --remove "internet->vpn"
```

Example output from the bundled estate:

```
CutVertex 0.1.0 — examples/acme-estate.json
  graph          11 nodes / 12 edges
  entry points   2   crown jewels 5
  paths          4 (4 realizable)
  exposure index 84.85/100
  findings       7  [act 1, attend 3]

  top chokepoints
   1. internet -> vpn: breaks 4/4 paths, 100% of risk (segment or restrict inbound path)
   2. vpn -> legacy-jump: breaks 3/4 paths, 71% of risk (enable/enforce control 'mfa-vpn')
   3. legacy-jump -> build01: breaks 2/4 paths, 46% of risk (rotate credential, remove standing privilege)
```

As a library:

```python
from cutvertex.analysis import assess, what_if
from cutvertex.ingest.loader import load_document

assessment = assess(document=load_document("examples/acme-estate.json"))
print(assessment.exposure_index)
for cp in assessment.chokepoints[:3]:
    print(cp.edge, cp.paths_broken, cp.cost_hint)
```

---

## The model in one page

### Nodes

An asset: host, identity, datastore, subnet, SaaS app, control, or AI agent. Carries
`criticality` (1-5), `exposure` (`open` / `controlled` / `small`), `impact`
(`total` / `partial` / `low`), an owner, and CVEs.

A node is a **crown jewel** when `criticality >= 4` or `impact == total`.

### Edges

An edge is not a plain arc. It carries:

```json
{
  "src": "vpn", "dst": "legacy-jump", "kind": "network",
  "technique": "VPN-authenticated pivot",
  "precondition": { "all_of": ["net:reach"], "none_of": ["exec:local-admin"] },
  "grants": ["net:reach"],
  "control": "mfa-vpn"
}
```

- **`precondition.all_of`** — every capability required to traverse.
- **`precondition.any_of`** — at least one required.
- **`precondition.none_of`** — hard blockers.
- **`grants`** — capabilities gained on arrival.

Capabilities are namespaced strings (`net:reach`, `exec:shell`, `cred:cloud-key`,
`agent:prompt-inject`, …) so data from cloud, IdP, EDR, and CMDB sources normalises into one
vocabulary without a schema migration per source.

### Findings grant capabilities

This is the part most tools skip. A CVE on the jump host does not merely add a row to a
table — it *unlocks the next hop*, because exploiting it yields `exec:shell`. Ingest folds
each asset's findings into the node's `grants` (what owning it yields) and `compromise`
(what is needed to own it). A CVE therefore changes the topology the engine explores.

### Controls are modelled honestly

An **effective** control with a known bypass makes the edge *gated*: traversal requires the
bypass capability. A stolen OAuth token makes MFA moot, so `cred:oauth-token` belongs in
`all_of` — holding it is what opens the door.

An effective control *without* a modelled bypass removes the edge entirely, and the removal
is reported in `graph.blocked_by_control`. Silently pretending a path exists through a
control you believe in is how a tool loses its audience.

### Two search modes

- **Strict (default).** Only edges the attacker can satisfy *now* are traversable. Output is
  exactly what an outside attacker can walk today. A capability nobody grants makes the path
  invisible.
- **Assume-breach (`allow_gaps=True`).** Gated edges are traversable with the missing
  capability recorded as a `residual_gap`. Useful for *"if an insider already held X, what
  opens up?"*. Gated paths score lower by design and are labelled non-realizable.

Without the second mode you cannot see a chain that needs a foothold you have not yet
modelled; without the first you drown in paths that only exist for someone who is already
domain admin.

---

## Scoring

Three dimensions are kept separate, because conflating them is the root of most bad queues:

1. **Severity** — CVSS, mapped non-linearly (`(cvss/10)^3`). Linear mapping over-weights the
   7-8 band where most CVEs live.
2. **Likelihood** — KEV is treated as near-certainty (observed exploitation outranks any
   model), EPSS contributes on a log scale against FIRST's ~3% background rate, exploit
   maturity fills gaps.
3. **Exposure** — reachability × whether the asset sits on a verified path × how plausible
   that path is.

Composite risk is a weighted geometric blend, so no single weak dimension can carry a score.
Each finding then goes through an **SSVC deployer decision tree** (exploitation status →
exposure → automatability → mission impact), yielding `act` / `attend` / `track*` / `track`
with SLA days (3 / 14 / 30 / 90).

---

## Remediation tracking

`open → triaged → in_progress → fixed → verified → closed`

Every transition is checked against an explicit allow-list. There is no any-to-any escape
hatch, because that is exactly how findings get closed without being fixed. Specifically:

- Moving to `verified` **requires** an evidence reference (scan id, retest output).
- `risk_accepted` **requires** a justification note.
- Reopening from `verified`/`closed` records a reason and increments `reopened_count`, which
  is what makes the reopen rate a real metric rather than a decoration.

Metrics: SLA compliance, MTTD, MTTR, reopen rate, breached count, per-state distribution.

---

## Repository layout

```
cutvertex/
├── cutvertex/
│   ├── model.py         typed domain model; precondition algebra
│   ├── graph.py         enumeration, chokepoints, domination pruning
│   ├── scoring.py       CVSS/EPSS/KEV fusion + SSVC decision tree
│   ├── ingest/loader.py validation-first parsing of environment documents
│   ├── tracking.py      remediation state machine + portfolio metrics
│   ├── analysis.py      orchestration, what-if, assessment serialisation
│   ├── report_html.py   dependency-free HTML report renderer
│   └── cli.py           assess / what-if / validate
├── tests/test_engine.py 45 tests
├── examples/            illustrative hybrid enterprise
├── ARCHITECTURE.md
└── SECURITY_REPORT.md
```

---

## Honest limitations

Stated plainly, because a security tool that oversells itself is worse than a blunt one:

1. **It does not collect data.** There is no scanner, no cloud connector, no EDR integration.
   You supply the graph. A collector suite is the obvious next build.
2. **Inventory quality bounds output quality.** Garbage in, confident-looking nonsense out.
   Mitigation: `confidence` on every node and edge (`observed` / `inferred` / `asserted`),
   surfaced rather than hidden.
3. **Precondition modelling is manual.** Getting `grants` and `precondition` right for 5,000
   assets is real work. The payoff is that the resulting paths are defensible.
4. **No probabilistic reasoning.** Capabilities are boolean. A capability an attacker "might"
   have is either modelled as held or not.
5. **No temporal dimension.** It models the estate now, not drift over time.
6. **Search is bounded.** `max_hops`, `max_paths`, and `MAX_STATES_PER_NODE` keep it
   tractable; on very dense estates some valid paths will be truncated.
7. **Not a pentest.** It finds *structural* exposure. It does not test whether an exploit
   works.

---

## Comparison

| Capability | CutVertex | Wiz | XM Cyber | Pentera | BloodHound | CyCognito |
|---|---|---|---|---|---|---|
| Explicit precondition sets on edges | **Yes** | Implicit | Implicit | n/a | Partial (ACL) | No |
| Findings grant topology capabilities | **Yes** | Partial | Partial | No | No | No |
| Control-bypass semantics | **Yes** | Partial | Partial | n/a | No | No |
| Flagged gated paths (assume-breach) | **Yes** | No | No | n/a | Partial | No |
| Counterfactual what-if per edge | **Yes** | Partial | Yes | No | Partial | No |
| AI-agent / MCP hops modelled | **Yes** | Emerging | No | No | No | No |
| Self-hosted, no cloud dependency | **Yes** | No | No | No | Yes | No |
| Open data model you can audit | **Yes** | No | No | No | Yes | No |
| Agentless discovery | No | **Yes** | Yes | Yes | n/a | **Yes** |
| Validated exploitation | No | No | No | **Yes** | No | No |
| Managed cloud coverage | No | **Yes** | Yes | Yes | No | **Yes** |
| Enterprise support/SLA | No | **Yes** | Yes | Yes | Paid tier | **Yes** |

Where CutVertex leads: explicitness and auditability of the model, finding-to-topology
coupling, honest gated-path reporting, agent/MCP coverage, and self-hosting.
Where it lags: everything about data collection, scale of managed coverage, and support.

---

## License

Proprietary. **All Rights Reserved.** Copyright (c) 2026 kk (kkdev9715).

No use, copy, modification, distribution, or derivative work is permitted without prior
written permission from the copyright holder. Public visibility of this repository grants no
license. See [LICENSE](LICENSE) for the full terms.
