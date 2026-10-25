# Project Portfolio Plan
### Seven builds, sequenced honestly

**For:** kkdev9715 (GitHub: kkcyber2)
**Date:** 2026-10-26
**Companion to:** `RESEARCH_REPORT.md`

---

## 0. The honest capacity question first

The brief asks for a ranked portfolio and asks me to be honest about how many can realistically
be built to a high standard. Answering that first, because it should shape the list:

**Two, not seven, can be built to a genuinely high standard by one engineer in a reasonable
timeframe.** Not "seven thin versions" — two real ones, plus at most one more in a reduced
scope. The reasoning:

- A "deep and differentiated" security tool needs a *model* that is correct, a *test suite*
  that proves it, a *UI* that makes the argument visual, and *documentation* that survives
  scrutiny. The flagship in this portfolio took a substantial portion of one working session
  for the engine alone, with three semantic bugs found by tests before it was presentable.
- Projects 3-7 in this list all depend on project 1 or 2 existing first. They are extensions of
  a graph model, an agent event schema, or a detection corpus. Building them standalone means
  building the substrate twice.
- The failure mode to avoid is seven half-finished repositories. A single repo where the
  reasoning is airtight is worth more than seven where it is not.

**Recommended sequencing: build 1, then 2, then stop and reassess.** If 1 and 2 land well, 3
becomes cheap because it reuses 1's graph. If they do not, adding five more does not help.

| Realistic outcome | Projects | Timeframe (solo, part-time) |
|---|---|---|
| **Committed** | 1 (done), 2 | ~6-10 weeks |
| **Stretch, if 1-2 land** | 3 | +3-4 weeks |
| **Opportunistic** | 4, 5 | only with collaborators |
| **Deliberately not planned** | 6, 7 | listed for completeness; do not start |

---

## 1. Ranked portfolio

Ranking criteria, weighted:

- **Differentiation (35%)** — does it beat existing tools on something they structurally cannot do?
- **Depth (25%)** — is there real engineering, or is it a wrapper?
- **Feasibility (25%)** — can one competent engineer finish it to a high standard?
- **Leverage (15%)** — does it make later projects cheaper?

---

### #1 — CutVertex: precondition-aware attack path analysis ✅ SHIPPED

**Score: 9.4 / 10**

**Problem.** Security teams have mature severity scoring (CVSS), likelihood scoring (EPSS), and
confirmed-exploitation data (KEV), yet still rank work by severity alone — because connecting a
CVE to *reachability* and to *what compromising the asset unlocks* requires a graph most teams
do not have. The consequence is that a CVSS 9.8 on an isolated build box outranks a 6.5 on the
internet-facing jump host sitting on a verified path to Tier 0.

**Why it beats existing tools.** Three specific claims, each defensible:

1. **Preconditions are explicit, and traversal is satisfiability, not reachability.** An edge
   carries `all_of` / `any_of` / `none_of` capability sets. A path requiring domain credentials
   is not reported as an external kill chain — the failure that gets attack-path tools
   dismissed by the engineers who have to act on them.
2. **Findings grant capabilities.** A CVE on the jump host does not add a row; it unlocks the
   next hop. This is what makes it an attack-path analyser rather than a scanner with a graph.
3. **Chokepoints are exact, not estimated.** For each edge, the surviving path set is
   recomputed. "Breaks 3 of 4 paths, 71% of risk" is a number you can defend in a change board,
   and `what-if` lets you verify it *before* making the change.

Plus two market-position differences: it models **AI-agent and MCP hops** as first-class edges
(`agent:prompt-inject` → `agent:tool-invoke` → `exec:code`), and it runs **fully self-hosted
with an air-gapped-capable report** — a single HTML file with zero external requests.

**Architecture.** Validated JSON ingest → graph (nodes with post-exploitation `grants`,
edges with precondition sets) → bidirectional state-space search over `(node, held_caps)` with
domination pruning → exact chokepoint recomputation → CVSS/EPSS/KEV fusion + SSVC deployer
decision tree → self-contained HTML report + remediation state machine.

**Difficulty.** High on modelling, moderate on algorithms, moderate on UI.
**Build scope.** ~2,200 lines Python, 45 tests, CLI, library, HTML report. **Done.**

**What it still lacks (honest).** No data collection — you supply the graph. No connectors to
cloud/IdP/EDR. Boolean capabilities, no probability. No temporal dimension. Search is bounded.
Not production-hardened.

---

### #2 — Sentinel Trace: agent execution security & hijack replay

**Score: 8.7 / 10**

**Problem.** Agents now hold credentials, call tools, and read untrusted content. Every serious
agent incident reduces to the same shape — the agent had a tool it did not need, scoped wider
than the task required, with no approval gate — but there is no tooling to *see* this. Agent
traces are JSON blobs with no canonical schema; a tool call is not an EDR event; memory is a
vector store. Detection engineering for agents cannot exist until the event model does.

**Why it beats existing tools.** Prompt firewalls try to detect injection; this project assumes
detection fails and instead answers *"given this trace, what could the agent have done, and was
it authorised to?"*. Concretely:

- **Declarative capability manifest per agent** — which tools, which scopes, which data
  classes, which actions require human approval.
- **Trace replay against the manifest** — feed a real execution trace, get every action that
  exceeded declared authority, ranked by blast radius.
- **Injection-path reconstruction** — walk back from a dangerous tool call through the
  untrusted content that influenced it (poisoned document → poisoned tool description →
  hijacked goal).
- **Regression CI for prompt/tool changes** — a corpus of adversarial traces; a prompt or tool
  scope change that widens authority fails the build. This is the "no CI for agent safety" gap
  from the research, and nobody ships it.

**Architecture.** OpenTelemetry-compatible trace schema for agent events (`llm.call`,
`tool.invoke`, `memory.read/write`, `content.ingest`) → authority model (declared vs actual) →
blast-radius scorer → replay engine → CI harness with adversarial corpus. Shares CutVertex's
graph engine for the injection-path reconstruction step, which is why it is project #2 — it is
much cheaper once #1 exists.

**Difficulty.** High — the event schema is the hard part, and it must be opinionated enough to
be useful without being wrong.
**Build scope.** 6-9 weeks part-time. Needs: schema + spec doc, replay engine, blast-radius
model, adversarial corpus (~40 traces), CLI + report, CI GitHub Action.

**Risk.** Adoption depends on teams adopting the trace schema. Mitigation: emit OTel-native
spans so existing collectors work unchanged.

---

### #3 — CutVertex Collectors + Control Efficacy

**Score: 8.1 / 10**

**Problem.** CutVertex's honest limitation is that it does not collect data. Every prospective
user's first question is "where does the graph come from?". Today the answer is "you write
JSON".

**Why it matters.** This is the highest-leverage extension: it converts a modelling framework
into a usable product. Collectors for AWS/Azure/GCP (IAM roles, security groups, trust
policies), Entra ID / AD (group nesting, delegation, service accounts), CI systems (GitHub
Actions secrets, runner scope), and MCP server inventories. Plus **control-efficacy testing** —
rather than an operator asserting "EDR is effective", probe it and record evidence.

**Architecture.** Plugin interface (`collect() -> partial graph`), per-source normalisers into
the existing capability vocabulary, merge with conflict resolution, provenance on every
node/edge. Runs standalone or as a scheduled job.

**Difficulty.** Moderate technically, high on breadth — each connector is its own permission
model and API surface.
**Build scope.** 3-4 weeks for three connectors done well (AWS, Entra ID, GitHub). Do not
attempt full multi-cloud coverage.

**Why not higher.** Breadth work, not differentiation work. It makes #1 usable but does not
advance the state of the art.

---

### #4 — Detection Coverage Ledger

**Score: 7.3 / 10**

**Problem.** Detection-as-code is established practice (Sigma + CI), but nobody reports
*coverage*: "which ATT&CK techniques do we detect, which rules have never fired, which rules
fire 400 times a day and are therefore noise". The data exists — rule metadata, technique
mappings, SIEM hit counts — and no first-class tool joins it.

**Why it beats existing tools.** Sigma tooling validates and converts rules; it does not close
the loop to production telemetry. This would: rule corpus → ATT&CK technique coverage map →
per-rule hit rate from SIEM query logs → drift detection when a rule silently stops firing →
coverage-over-time trend.

**Architecture.** Sigma rule parser → ATT&CK mapper → telemetry adapter (Elastic/Splunk/Sentinel
query log) → coverage model → dashboard.

**Difficulty.** Moderate. The hard part is SIEM telemetry access, which varies wildly per org.
**Build scope.** 3 weeks, but only worth starting with a real SIEM to point it at.

---

### #5 — Non-Human Identity Ledger

**Score: 7.0 / 10**

**Problem.** Service accounts, CI tokens, and agent credentials accumulate standing privilege
with no owner and no expiry. Overlaps with #1's credential edges but is an inventory and
lifecycle problem rather than an attack-path problem.

**Why it is ranked lower.** The identity vendors (Astrix, Token Security) and the cloud
platforms are actively moving here, so the window narrows every quarter. Differentiation would
have to come from the agent-credential angle specifically.

**Build scope.** 3-4 weeks, and requires connectors — so it depends on #3.

---

### #6 — Threat-Intel Correlation Engine

**Score: 6.2 / 10**

**Problem.** TI feeds are noisy, indicator-heavy, and disconnected from asset context. A
correlation engine that joins indicators to *your* topology ("this C2 domain resolves to an
asset on a verified path to Tier 0") would be valuable.

**Why it is ranked low.** The space is crowded (Recorded Future, Anomali, OpenCTI, MISP), the
open-source options are good, and differentiation would be thin. The *only* interesting angle is
the join to CutVertex's graph — and that is a feature of #1, not a standalone product.

**Recommendation: do not build as a standalone project.** Add it to #1 as an enrichment plugin
if demand appears.

---

### #7 — SOAR Replacement / AI-SOC Triage Agent

**Score: 5.5 / 10**

**Problem.** SOAR automates response while leaving decision manual; the playbooks are brittle
and the maintenance burden is real. An agent that makes the triage *decision* well is valuable.

**Why it is ranked last.** This is the most crowded and most capital-intensive category in the
list. Dropzone, Qevlar, Microsoft, CrowdStrike and others are all shipping it with large teams.
A solo engineer cannot win on model quality, integration breadth, or sales. Building it would
burn the time that #2 needs.

**Recommendation: do not build.** Study it, do not compete with it.

---

## 2. Summary table

| # | Project | Score | Differentiation | Depth | Feasibility | Status |
|---|---|---|---|---|---|---|
| 1 | **CutVertex** — precondition-aware attack paths | **9.4** | Very high | High | Done | ✅ **Shipped** |
| 2 | **Sentinel Trace** — agent hijack replay & authority CI | **8.7** | Very high | High | 6-9 wk | Next |
| 3 | CutVertex Collectors + control efficacy | 8.1 | Moderate | Moderate | 3-4 wk | Stretch |
| 4 | Detection Coverage Ledger | 7.3 | High | Moderate | 3 wk | Opportunistic |
| 5 | Non-Human Identity Ledger | 7.0 | Moderate | Moderate | 3-4 wk | Opportunistic |
| 6 | Threat-Intel Correlation | 6.2 | Low | Moderate | 3 wk | Do not build |
| 7 | AI-SOC / SOAR replacement | 5.5 | Low | High | 6+ mo | Do not build |

---

## 3. What makes these deep rather than thin wrappers

The brief specifically warned against thin wrappers. The test applied to every entry:

**A thin wrapper** calls an API, reshapes the output, and adds a UI. It has no model of its own.
Remove the upstream service and it has nothing to say.

**A deep tool** has an internal representation that makes a claim the upstream data cannot make
on its own. CutVertex's claim — "closing this one edge removes 71% of attacker risk" — is not
present in any CVE feed, any scanner output, or any cloud API. It is computed from a model
(precondition sets + exact recomputation) that the tool itself defines and defends with tests.

Apply the same test to #2: "this trace shows the agent exceeded its declared authority on
three actions, and the influence path traces back to a poisoned document" is not present in any
trace, any log, or any prompt-firewall verdict. It requires the authority model.

Projects 6 and 7 fail this test — which is why they are marked "do not build".

---

## 4. Recommended next 30 days

1. **Publish CutVertex.** Clean repo, README with the honest limitations section intact, and a
   short write-up of the three bugs the tests caught — that narrative is more credible than a
   feature list.
2. **Get one real graph.** Run it against a real estate (own lab, a cloud sandbox account, or a
   willing team). The model's weak points only appear against real inventory — expect the
   `grants` vocabulary to need revision.
3. **Write the agent-hop spec.** The `agent:` capability namespace in CutVertex is the seed of
   project #2. Document the event schema before writing the engine; it is the part that is hard
   to change later.
4. **Do not start #3 yet.** Connectors are breadth; they will consume the time #2 needs, and #1
   is not yet validated against a real estate.

---

**License note.** All projects here are intended for proprietary "All Rights Reserved" release
under kk (kkdev9715), requiring written permission for use. Where a project depends on an
open-source library (Sigma rules, OTel SDKs, BloodHound's published techniques), the dependency
and its license are to be declared explicitly in the repository — using a library is fine;
copying its code or stripping attribution is not.
