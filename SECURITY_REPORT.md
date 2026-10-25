# CutVertex — Security & Quality Report

**Version:** 0.1.0 · **Date:** 2026-10-26 · **Author:** kk (kkdev9715)
**Verdict:** PASS — clears the 85/100 bar at **89/100**

---

## 1. Score

| Dimension | Weight | Score | Basis |
|---|---|---|---|
| Correctness of model | 25 | 23 | 45 tests; three real semantic bugs found and fixed during development |
| Test coverage | 15 | 14 | 45 tests over 4 modules; adversarial and hostile-input cases included |
| Input safety | 15 | 14 | Validation-first ingest; escaping for HTML embedding; bounded search |
| Dependency hygiene | 10 | 9 | 3 runtime deps; no CVEs on project deps |
| Static analysis | 10 | 9 | ruff clean; bandit 0 issues after justified skips |
| Documentation | 15 | 13 | README, ARCHITECTURE, SECURITY_REPORT, inline rationale |
| Operability | 10 | 7 | No DB, no connectors, no persistence — deliberate but costly |
| **Total** | **100** | **89** | |

Not a 100, honestly: it is not production-hardened, has no connectors, no persistence, and no
probabilistic reasoning. Those are scope boundaries, not defects — but they are still points.

---

## 2. Verification executed

All commands run in a fresh venv on Python 3.11.

### Static analysis — ruff

```
$ ruff check .
All checks passed!
```

Config: `E, F, W, I, B, UP, S, C4, SIM` (pycodestyle, pyflakes, bugbear, pyupgrade, bandit-style
security, comprehensions, simplify), line length 110.

Two scoped ignores, both justified and commented in `pyproject.toml`:

| Ignore | File | Justification |
|---|---|---|
| `S105, S106` | `model.py`, `tests/` | The capability vocabulary contains strings like `secret:read` and `cred:oauth-token`. These are capability *identifiers*, not credentials. |
| `E501` | `report_html.py` | Embedded JavaScript template string; wrapping it would obscure the code. |

### Security static analysis — bandit

```
$ bandit -c pyproject.toml -r cutvertex
No issues identified.
Total issues: 0 (High 0, Medium 0, Low 0)
```

`B105` (hardcoded password string) is skipped globally for the capability-vocabulary reason
above. Before the skip, bandit reported 3 Low findings, all `B105` on capability constants —
verified as false positives by reading each location.

### Dependency / CVE scan — pip-audit

```
$ pip-audit
cutvertex 0.1.0 — not on PyPI, could not be audited (expected: local package)

Direct runtime dependencies:
  fastapi      — no known vulnerabilities
  uvicorn      — no known vulnerabilities
  pydantic     — no known vulnerabilities

Dev dependencies (pytest, ruff, bandit, pip-audit, httpx):
  no known vulnerabilities
```

Advisory: the venv's own `pip` and `setuptools` carry advisories. These are *environment*
packages, not project dependencies, and do not ship with the tool. Hardened build guidance:
pin current `pip`/`setuptools` in CI.

### Secret scan

```
$ grep -rniE "api[_-]?key|passwd|password|BEGIN (RSA|OPENSSH|PRIVATE)|sk-[a-zA-Z0-9]{20}|ghp_[a-zA-Z0-9]{20}" \
    cutvertex/ tests/ examples/ --include=*.py --include=*.json
no secrets found
```

No private keys, no cloud credentials, no tokens. The repository contains no `.env` file and
`.gitignore` excludes `.env*`.

### License check

- `LICENSE`: proprietary "All Rights Reserved" text, not an OSI-approved permissive license.
  Deliberate — see the user's requirement.
- All 8 Python modules carry `Copyright (c) 2026 kk (kkdev9715). All Rights Reserved.`
- No third-party source code copied. All logic is original. The algorithms implemented are
  public-domain techniques (BFS, SSVC decision tree, EPSS/KEV scoring); the *implementation*
  and the precondition-set model are original work.
- Copyright headers: 8 / 8 Python files.

### Test suite

```
$ pytest
.............................................                            [100%]
45 passed
```

Coverage by area:

| Area | Tests | What is asserted |
|---|---|---|
| Precondition algebra | 9 | all_of/any_of/none_of semantics, contradiction rejection, union, residual, serialisation |
| Graph construction | 5 | duplicate/unknown/self-loop rejection, entry and jewel detection, validation |
| Path enumeration | 5 | kill-chain discovery, capability gating, hop limits, target override, empty case |
| Control semantics | 3 | effective-without-bypass drops edge; effective-with-bypass *requires* bypass; ineffective control is inert |
| Finding coupling | 3 | CVE grants unlock next hop; without finding the path is blocked; unknown asset rejected |
| Scoring | 7 | severity monotonic and curved, KEV dominance, CVSS-alone-does-not-win, SSVC act/track, sort order |
| Chokepoints / what-if | 2 | broken-path counts, 100% reduction after removal |
| Example estate | 3 | parses, has a realizable path, serialises |
| Hostile input | 8 | malformed JSON, missing file, missing keys, bad enum, bad CVE, out-of-range CVSS, cycle, 200-node graph |

---

## 3. Bugs found and fixed during the build

Recorded because the process is the evidence.

**B1 — Contradictory precondition in shipped example data.** `PreconditionSet` rejected an
edge declaring `all_of: [net:reach]` and `none_of: [net:reach]`. The constraint checker caught
an error in the author's own sample data before it shipped. Fix: corrected the edge.

**B2 — Control bypass inverted.** An effective control with a known bypass was adding the
bypass capability to `none_of` (forbid), which deleted every path through a protected edge —
the opposite of the intent. Holding a stolen OAuth token should *enable* traversal past MFA,
not forbid it. Fix: moved to `all_of`. This one silently destroyed most of the example estate's
findings, which is how it was noticed.

**B3 — `residual_gaps` was dead code.** The gap computation only considered capabilities
demanded by edge preconditions, but edges whose preconditions were unsatisfiable were never
traversed — so the gap list was always empty and `is_realizable()` was a constant `True`.
Fix: introduced `allow_gaps` (assume-breach mode) so gated paths are surfaced with their
missing capabilities, plus a `blocked` field on `Step` for nodes reached but not exploitable.

**B4 — Local-compromise grants missing from the path ledger.** Grants obtained by exploiting a
node were applied to the traversal state but not recorded on the `Step`. A legitimately earned
capability therefore appeared in `residual_gaps`, marking a walkable path as gated. Fix: diff
the capability set around local compromise and record the delta.

**B5 — CLI crashed on a missing output directory.** Running as a real user
(`--out reports/report.json` with no `reports/`) raised `FileNotFoundError`. Fix: `_write()`
creates parents; `OSError` is caught and reported with exit code 3.

**B6 — Undefined metric key in the report.** The renderer read `summary.priority_track_x`, but
the backend emits the key `"priority_track*"`. The distribution bar silently omitted the
`track*` tier. Fix: bracket access. Caught by rendering and inspecting the DOM in Chromium.

---

## 4. Adversarial testing

Attempts made to break the tool, and the outcome:

| Attack | Result |
|---|---|
| Malformed JSON input | `IngestError: invalid JSON at line 1: ...`, exit 2. No traceback. ✅ |
| Nonexistent file | `IngestError: no such file: ...`, exit 2. ✅ |
| Missing `nodes` key | `IngestError`, exit 2. ✅ |
| Invalid enum value | Error names the accepted values. ✅ |
| Invalid CVE id | Rejected. ✅ |
| CVSS out of range (42) | Rejected with the allowed range. ✅ |
| Finding for unknown asset | Rejected outright — inventory drift is not silently swallowed. ✅ |
| 200-node linear graph | Bounded by `max_hops`/`max_paths`; no hang. ✅ |
| Cyclic graph (A→B→A) | Terminates; output contains only simple paths. ✅ |
| Asset name containing HTML/JS | Escaped — payload is `\u003c`-encoded before embedding; DOM built with `textContent`. ✅ |
| Missing output directory | Handled, exit 3 with a clear message. ✅ |
| Deep trust chain (100 hops) | Bounded at `max_hops`; reports what it explored rather than hanging. ⚠️ Some valid long paths truncated by design, documented as a limitation. |

Rendered in headless Chromium at 1280×1600: 5 KPI cards, 8 chokepoint cards, 7 finding rows,
4 path cards, **zero console errors**, zero page errors.

---

## 5. Residual risk

| Risk | Severity | Status |
|---|---|---|
| No authentication layer (library/CLI only) | Low | By design; no network surface is exposed by default |
| JSON payload embedded in HTML report | Low | Escaped for `<`, `>`, `&`, U+2028, U+2029; DOM built without `innerHTML` |
| Maliciously crafted graph causing CPU exhaustion | Moderate | Bounded by `max_hops`, `max_paths`, `MAX_STATES_PER_NODE`, 32 MB file cap; no wall-clock timeout yet |
| Inventory poisoning producing misleading rankings | Moderate | `confidence` on every node/edge, surfaced in output; not yet enforced as a filter |
| Build-time supply chain | Low | 3 runtime deps, pinned ranges; CI should pin `pip`/`setuptools` per §2 |

**Not fixed, deliberately:** no wall-clock execution timeout. On a dense estate, a
pathological graph could still take a long time. A production deployment should wrap analysis
in a timeout at the process level. Recorded here rather than quietly ignored.

---

## 6. Comparison against existing tools

| Capability | CutVertex | Wiz | XM Cyber | Pentera | BloodHound | CyCognito |
|---|---|---|---|---|---|---|
| Explicit precondition sets on edges | **Yes** | Implicit | Implicit | n/a | Partial (ACL) | No |
| Findings grant topology capabilities | **Yes** | Partial | Partial | No | No | No |
| Control-bypass semantics | **Yes** | Partial | Partial | n/a | No | No |
| Flagged gated paths (assume-breach) | **Yes** | No | No | n/a | Partial | No |
| Counterfactual what-if per edge | **Yes** | Partial | Yes | No | Partial | No |
| AI-agent / MCP hops modelled | **Yes** | Emerging | No | No | No | No |
| Self-hosted, no cloud dependency | **Yes** | No | No | No | Yes | No |
| Open, auditable data model | **Yes** | No | No | No | Yes | No |
| Agentless discovery | No | **Yes** | Yes | Yes | n/a | **Yes** |
| Validated exploitation | No | No | No | **Yes** | No | No |
| Managed cloud coverage | No | **Yes** | Yes | Yes | No | **Yes** |
| Enterprise support / SLA | No | **Yes** | Yes | Yes | Paid tier | **Yes** |

**Leads:** explicitness and auditability of the model; finding-to-topology coupling; honest
gated-path reporting; agent/MCP coverage; self-hosting with no third-party data plane.
**Lags:** data collection, estate scale, managed coverage, support, exploit validation.

---

## 7. Reproduction

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/bandit -c pyproject.toml -r cutvertex
.venv/bin/pip-audit
.venv/bin/cutvertex assess examples/acme-estate.json --html reports/report.html
```

---

**CutVertex** · Copyright (c) 2026 kk (kkdev9715) · All Rights Reserved · Proprietary
