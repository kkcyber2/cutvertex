# State of the Art & Gap Analysis
### Three domains, and where the real openings are

**Prepared for:** kkdev9715 (GitHub: kkcyber2)
**Date:** 2026-10-26
**Scope:** (a) AI/ML security & threat intelligence, (b) cybersecurity tooling — offensive and
defensive, (c) full-stack product engineering with modern UI

---

## 0. Executive summary

Three findings shape everything downstream:

1. **The AI-security market is being built in the wrong order.** Everyone is shipping
   *detectors* for prompt injection and *guardrails* for model output while the underlying
   problem — that natural language cannot be a trust boundary — remains unsolved. The
   defensible engineering is not better detection; it is **architecture that does not require
   the model to be trusted**.

2. **The vulnerability-management market solved scoring and forgot topology.** CVSS, EPSS and
   KEV are mature, well-documented, and widely deployed. Yet the standard queue still ranks by
   severity because connecting a CVE to *reachability* and to *what compromising the asset
   unlocks* requires a graph most teams do not have. CISA's own SSVC exists precisely because
   severity-threshold triage was recognised as inadequate.

3. **The open-source security stack has a specific, exploitable hole in the middle.** Scanners
   are excellent and free (Nuclei, Trivy, Semgrep, ZAP). Active Directory attack-path analysis
   is excellent and free (BloodHound). Between those two layers — *"given these findings and
   this topology, what actually matters, in what order, and what single change helps most?"* —
   the open-source options are thin, and the commercial ones are expensive, cloud-tied, and
   opaque.

The portfolio in `PORTFOLIO_PLAN.md` is built around finding 3, with a second flagship aimed
squarely at finding 1.

---

## 1. Domain A — AI/ML security & threat intelligence

### 1.1 What has actually been built

The field has converged on a taxonomy before it converged on defences. OWASP's Top 10 for LLM
Applications and its companion work on agentic systems (covering goal hijacking, tool misuse,
memory poisoning, and excessive agency) are now the shared vocabulary that vendors, auditors
and internal security teams all reference. That is genuinely useful — it gave the industry a
checklist — but a checklist is not a control.

Commercially, the market has split into four product shapes:

| Shape | Representative players | What it sells |
|---|---|---|
| AI-SPM / AI posture | Wiz, Palo Alto (Prisma AIRS), Microsoft Security Copilot | Inventory of models, shadow-AI discovery, misconfiguration |
| Prompt/response firewalls | Lakera, Prompt Security, Robust Intelligence, Protect AI | Inline classification of prompts and outputs |
| AI-SOC / triage agents | Dropzone AI, Qevlar, Microsoft Security Copilot, CrowdStrike Charlotte | Autonomous alert investigation |
| Agent runtime security | Emerging: Astrix, Token Security, Oasis, Descope | Non-human identity, tool-call mediation, agent permissions |

Government-grade work is narrower and more concrete. CISA and NSA have published guidance on
securing AI systems and on deploying agents safely; NIST's AI Risk Management Framework and
its Generative AI Profile define the risk taxonomy that US federal procurement now maps to.
The EU AI Act adds a regulatory layer with real teeth for high-risk systems. None of these
produce exploit tooling — they produce *obligations*, which is why the commercial market is
growing so fast around them.

Attack research is where the real progress is. The published work on indirect prompt injection
(poisoned documents, poisoned tool descriptions, poisoned memory) is now extensive and
consistent in its conclusion: an LLM that reads attacker-influenced content and has tools in
scope is a confused-deputy vulnerability, structurally, not incidentally. The MCP ecosystem
introduced a new class of the same problem — a tool description is attacker-controlled text
that the model is instructed to trust.

### 1.2 The hard unsolved problems

**(i) There is no trust boundary in natural language.** Classic security relies on a parser
rejecting malformed input. A language model by design accepts any input and interprets it.
Every "defence" — input classifiers, instruction hierarchies, delimiters, system-prompt
hardening — is a heuristic with a published bypass. The honest conclusion, which the better
research papers now state outright, is that **you cannot make the model trust a document**.
You can only bound what a compromised model is *able* to do.

**(ii) Excessive agency is the actual vulnerability.** Almost every serious agent incident
reduces to the same shape: the agent had a tool it did not need, scoped wider than the task
required, with no approval gate. This is a permissions problem wearing an AI costume, and it
is tractable with classical techniques (least privilege, scoped credentials, human approval for
irreversible actions) — which is why it is under-served by the "AI security" vendor category
and over-served by the identity vendors.

**(iii) Evaluation is unsolved.** There is no agreed benchmark for "is this agent safe", no
equivalent of a CVE for a prompt, and no way to regression-test a system prompt change. Teams
change a system prompt and redeploy with no evidence about whether they made the agent more or
less hijackable. This is a *tooling* gap, not a research gap — nobody has built the CI for it.

**(iv) Telemetry is missing.** Traditional detection engineering has process-level telemetry
(EDR, Sysmon, auditd). Agents emit traces shaped nothing like that: a tool call is a JSON
blob, memory is a vector store, and there is no canonical schema. Detection engineering for
agents cannot be built until someone defines the event model.

**(v) Threat intel does not cover AI-native attack surface.** TI feeds carry IPs, hashes,
domains. None of them carry "this MCP server's tool description exfiltrates files". The
enrichment layer for agentic risk does not exist.

### 1.3 Where existing tools fall short

- **AI-SPM inventories, does not analyse.** Wiz will tell you a model endpoint is public. It
  will not tell you what an attacker gains by poisoning the agent that calls it.
- **Prompt firewalls are bypassable by construction** and add latency; they are a detection
  control dressed as a preventive one.
- **AI-SOC products optimise the wrong step.** Faster alert triage is valuable, but if the
  queue is full of unreachable CVEs on non-critical assets, triaging them faster is an
  expensive way to stay in the same place.
- **Nobody connects agent surface to enterprise topology.** This is the gap that motivated the
  flagship build: an agent with a shell tool is a *graph edge*, and should be analysed as one.

---

## 2. Domain B — cybersecurity tooling (offensive and defensive)

### 2.1 Discovery and scanning — settled

This layer is mature and largely commoditised. The open-source stack is genuinely excellent:
Nuclei for templated checks and a huge community template library, Trivy and Grype for
container and filesystem scanning, Semgrep for SAST with readable rules, ZAP and Burp
Community for web, Nmap and Masscan for network. Commercial scanners (Qualys, Tenable,
Rapid7, Nessus) differentiate on coverage breadth, credentialed scanning at scale, and
reporting — not on finding things others cannot find.

The genuinely hard problem here is **credentialed scanning at scale**: authenticated checks
find far more than unauthenticated ones, but distributing and rotating credentials across
thousands of hosts is operationally painful and a security risk in itself. This is why
agent-based scanners (CrowdStrike, SentinelOne, Wazuh) keep winning share in large estates.

### 2.2 Prioritisation — mature inputs, immature synthesis

The scoring inputs are in good shape and publicly documented:

- **CVSS** (v3.1 / v4.0) — severity, with v4.0 adding better handling of temporal and
  environmental context.
- **EPSS** (FIRST) — probability of exploitation in the next 30 days, published daily, with a
  documented background rate around 2-3% across all scored CVEs. It is a genuine improvement
  over severity-only ranking and it is free.
- **CISA KEV** — confirmed in-the-wild exploitation. Authoritative, small (a few hundred to
  low thousands of entries), and unambiguous.
- **SSVC** — CISA's Stakeholder-Specific Vulnerability Categorization, a decision tree rather
  than a score. CISA recommends it over CVSS thresholds, and it is what this flagship
  implements as its decision layer.

Where the market is *immature* is synthesis. Almost every commercial tool computes a weighted
number and stops. Very few connect the score to: is this asset reachable from where an attacker
actually stands? Does compromising it advance an attacker toward something that matters? Is
there a single change that removes a whole class of paths? Those are graph questions, and the
tools that answer them (Wiz, XM Cyber, Pentera, CyCognito, Armis) are expensive, cloud-first,
and closed — you cannot audit the model, and you cannot run them air-gapped without paying for
an appliance.

### 2.3 Attack path analysis — the strongest prior art, and its blind spots

**BloodHound** is the best open-source attack-path tool in existence and deserves the respect
it gets. It models Active Directory as a graph and finds privilege-escalation paths to Domain
Admin. Its successor generation (BloodHound Community/Enterprise) extended this with
Azure/Hybrid coverage.

Its limits are structural:

- **AD-shaped.** The primitives are ACLs and delegation. A cloud IAM role, a CI pipeline, a
  Kubernetes service account, or an MCP tool definition does not map cleanly.
- **Preconditions are implicit.** An ACL edge exists; whether an attacker can *use* it depends
  on credentials they hold, which the tool tracks as "owned" nodes rather than as a
  satisfiability constraint on the edge.
- **No control modelling.** It tells you a path exists. It does not tell you that MFA on the
  VPN would gate hop 2, and it will not compute the counterfactual.

Commercial attack-path tools (XM Cyber, Pentera, Wiz) close some of this but add a different
problem: you are trusting an opaque model. When the tool says "this path reaches your crown
jewels", you cannot inspect the reasoning, and you cannot correct it when your environment has
a nuance the vendor never modelled.

### 2.4 ASM — solved discovery, unsolved attribution

External attack surface management is now a crowded, competent market (CyCognito, Censys,
Shodan Enterprise, Randori/IBM, Detectify). Discovery is genuinely solved for internet-facing
assets. What remains hard is **ownership attribution** — mapping a discovered asset to the team
that must fix it — and **shadow-asset drift**, where a forgotten subdomain reappears. Both are
organisational problems that tooling surfaces but cannot solve.

### 2.5 SOAR — the automation that mostly does not automate

SOAR's promise was analyst leverage. The delivered reality is a library of brittle playbooks
that break whenever an API changes, plus a maintenance burden that often exceeds the time
saved. The failure mode is well documented in practitioner writing: playbook fatigue, where
teams automate the easy 20% (enrichment, ticket creation) and hand-roll the hard 80% forever.

The root cause is that SOAR automates *response* while leaving *decision* manual. It assumes
someone already decided the alert matters. That is the wrong end to automate — and it is why
AI-SOC products that actually make the decision have found traction where SOAR plateaued.

### 2.6 Detection engineering — best practices exist, tooling lags

Sigma (vendor-neutral detection rules) plus a CI pipeline — validate rules, convert to
target query language, unit-test against sample events — is the recognised good practice. The
open-source tooling (sigma-cli, pySigma, backends) is real and works.

What is missing is the connective tissue: **detection-as-code with test coverage metrics**.
Nobody reports "62% of our ATT&CK techniques are covered and these 14 rules have never fired
in production". The data is available (rule metadata, ATT&CK mapping, SIEM hit counts); the
product does not exist as a first-class tool. This is a credible second-tier project.

### 2.7 AI agent security — the actual frontier

Covered in Domain A, but worth restating from the defensive-tooling angle: the *agent* is a new
kind of network node. It has reachability (which tools), identity (which credentials), and
data flow (what it can read and where it can send). All the classical questions apply and
almost none of the classical tools can answer them. This intersection — **agent surface as
part of enterprise attack-path analysis** — is the least crowded and most defensible opening
in the defensive market today.

---

## 3. Domain C — full-stack product engineering with modern UI

### 3.1 2026 norms

The TypeScript full-stack consensus has stabilised around a small set of choices:

- **Framework:** Next.js (App Router, Server Components) or Remix/React Router; Hono or
  Fastify for API-first services.
- **Language:** TypeScript everywhere, end-to-end types as the primary correctness mechanism.
- **API:** tRPC where client and server are co-deployed; REST/OpenAPI where they are not.
- **Data:** PostgreSQL as default; Drizzle or Prisma as the ORM; Redis for queues and caching.
- **UI:** Tailwind CSS plus headless primitives (Radix / shadcn-style composition). Design
  tokens, dark mode and accessibility treated as baseline, not features.
- **Auth:** managed providers (Clerk, Auth0, Better Auth for self-hosted).
- **Deploy:** Vercel, Fly, Railway, or containers on ECS/GKE; OpenTelemetry for tracing.

The quality bar that separates a serious product from a demo is not the stack. It is:
loading and error states everywhere, keyboard navigation, a real empty state, responsive
behaviour that was actually tested, and a design that does not look like a Tailwind template.

### 3.2 Where security products specifically fail on UI

Having surveyed the category, security tooling has a consistent UI failure pattern: it
optimises for *data density* and neglects *decision support*. A table of 4,000 CVEs sorted by
severity is data-dense and decision-poor. The tools practitioners actually praise (BloodHound's
graph view, Wiz's path visualisation) win because they show *relationships*, not rows.

The lesson for a portfolio: in security products, **the visualisation is the product**. A graph,
a path, a before/after counterfactual — these are not decoration, they are the argument.

### 3.3 A note on air-gapped deployment

Enterprise security teams routinely review tools on machines with no internet access. A report
that loads a CDN font, a Google Analytics tag, or a hosted JS bundle fails that review
immediately — and rightly so, since it is also a data-exfiltration path. Self-contained HTML
with zero external requests is a genuine differentiator in this market, and it is cheap to do.

---

## 4. Consolidated gap analysis

Ranked by (real pain × under-service × feasibility for a small team).

| # | Gap | Who feels it | Why incumbents have not closed it |
|---|---|---|---|
| 1 | **Findings are not connected to topology or to remediation chokepoints.** Severity-only queues persist because the alternative needs a graph. | Every security team with >500 assets | Requires a model, not a data feed. Commercial tools have it but are closed and expensive; open source has scanners and BloodHound, nothing in between. |
| 2 | **Agent/MCP surface is not modelled in enterprise exposure analysis.** | Teams deploying agents now | New surface; vendors are still shipping prompt classifiers. |
| 3 | **No CI for agent safety.** No way to regression-test a system prompt or tool scope change. | AI platform teams | Needs an event model and an eval harness nobody has standardised. |
| 4 | **Detection-as-code lacks coverage and hit-rate reporting.** | Detection engineers | Requires joining rule metadata to SIEM telemetry; genuinely awkward data plumbing. |
| 5 | **Non-human identity sprawl is unmanaged.** Service accounts, CI tokens, agent credentials accumulate standing privilege. | Platform + security | Identity vendors are moving here but slowly; overlaps gap 1. |
| 6 | **SOAR automates response, not decision.** | SOC leads | The decision layer is hard; better to sell AI-SOC triage instead. |
| 7 | **Ownership attribution for discovered assets.** | ASM users | Organisational, not technical — tooling can only surface it. |

---

## 5. Sources

Research drawn from vendor and standards documentation, published attack research, and
practitioner reporting across the three domains. Primary references:

**Standards and frameworks**
- OWASP Top 10 for LLM Applications; OWASP work on agentic system security (ASI taxonomy)
- NIST AI Risk Management Framework and Generative AI Profile
- CISA / NSA guidance on securing AI systems and safe agent deployment
- CISA Stakeholder-Specific Vulnerability Categorization (SSVC) — deployer decision tree
- CISA Known Exploited Vulnerabilities catalog
- FIRST EPSS model documentation (including published background exploitation rate)
- CVSS v3.1 and v4.0 specifications (FIRST)
- MITRE ATT&CK; Sigma rule specification
- EU AI Act (Regulation (EU) 2024/1689)

**Tooling and prior art**
- BloodHound / BloodHound Community Edition (AD and Azure attack-path analysis)
- Nuclei, Trivy, Grype, Semgrep, ZAP, Nmap — open-source scanning stack
- Wiz, XM Cyber, Pentera, CyCognito, Armis — commercial exposure and attack-path platforms
- Model Context Protocol specification; published research on tool-description poisoning
- Dropzone AI, Qevlar, Microsoft Security Copilot, CrowdStrike Charlotte — AI-SOC
- Lakera, Prompt Security, Protect AI, Robust Intelligence — AI runtime security
- Astrix, Token Security, Descope — non-human identity and agent permissions

**Engineering stack**
- Next.js App Router documentation; tRPC; Drizzle ORM; PostgreSQL
- Tailwind CSS; Radix UI primitives; shadcn/ui composition patterns
- OpenTelemetry specification

*Vendor claims are cited as market positioning, not as verified capability. Every "lags"
assessment in this document is a judgement about public documentation and open-source
availability, not a benchmark result.*
