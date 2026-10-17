# Phase 5 — Detection Algorithm: Implementation and Validation

**Status:** complete, awaiting approval before Phase 6. Committed locally, **not pushed**.
**Date:** 2026-10-17

Labels: **[PAPER]** paper-faithful · **[PROPOSAL]** our correction (research extension, not an established result) · **[VERIFIED]** measured by a test or a deterministic run in this phase · **[EXPERIMENTAL]** a value chosen by us, not taken from the paper · **[INFERENCE]**.

> **Scope and honesty notes.**
> - No packet is blocked and no mitigation command is sent. The engine only lists what a mitigation step *would* act on (`would_mitigate`). Enforcement is Phase 6.
> - **The paper gives no numeric thresholds.** Every threshold here is experimental. The reference setting E1 (τ_ratio = 5, τ_min = τ_rate = 50 pps) was fixed *before* any result was computed, and chosen above the synthetic benign client's 100:30 request:reply ratio, i.e. **with knowledge of the benign traffic profile**. It is not a validated operating point and is not "the paper's threshold".
> - Results come from synthetic traffic: a deterministic simulation running the real C++ MULTOPS tree and V1 exporter, and controlled Click runs on loopback. They say nothing about real-world accuracy. None of them reproduces the paper's reported 100% / 0% figures. Those remain claims made under an unspecified setup.

---

## 1. Decisions implemented (from your Phase 4 review)

| # | Decision | Implementation |
|---|---|---|
| 1 | Decide at the finest *demonstrably exact* prefix; evaluate the paper's per-prefix algorithm alongside, as separate baselines | `CorrectedDetector` on a non-overlapping partition of exact nodes (§3.2); `PaperDetector` on the paper aggregator (§3.3); plus two ablations isolating rule vs. aggregation |
| 2 | Abstain on incomplete windows; no mitigation; abstentions are not correct predictions | Label `abstain` with the missing routers. Excluded from TP/FP/TN/FN, reported separately, never counted as benign. |
| 3 | Systematic threshold sensitivity; no invented "original" threshold | 7 τ_ratio × 6 volume values per method per scenario (§5.3). All labelled experimental. |
| 4 | (prefix, window) as primary unit; independently generated ground truth; host-level results where attribution is exact | §4. Truth comes only from the generated packets and their attack labels. Host-level scoring is done only for /32 units. |

## 2. Rules

| Rule | Definition | Notes |
|---|---|---|
| `PAPER_LITERAL` [PAPER] | Ratio = R_in/R_out (∞ if R_out = 0); malicious iff Ratio > τ_ratio **or** (R_out = 0 ∧ R_in > τ_rate) | Exactly Algorithm 2, lines 5–6. Because Ratio = ∞ whenever R_out = 0, the τ_rate clause can never change a decision. Every zero-return unit is flagged, **even one with R_in = 0** (Phase 1, P3). Verified: across the whole sweep the paper's results are identical for every τ_rate (`test_paper_rule_ignores_tau_rate`). |
| `CORRECTED` [PROPOSAL] | R_in < τ_min → benign; else R_out = 0 → malicious; else R_in/R_out > τ_ratio → malicious; else benign | A volume gate before the ratio. The gate is exactly what trades low-rate attacks against low-rate benign one-way traffic (§6). |

R_in and R_out are in units per second: reported rates for the paper method; exact window counts ÷ window length for the proposal.

## 3. Engine (`aggregator/detection.py`)

### 3.1 Labels: detection is separated from identification

| Label | Meaning |
|---|---|
| `malicious_host` | Flagged /32: attack detected **and** source identified |
| `malicious_ambiguous` | Flagged prefix coarser than /32: attack traffic detected, **attribution unresolved**. The prefix may also hold benign hosts, and mitigating it would hit them. |
| `benign` | Classified, not malicious |
| `abstain` | Not classified (`missing_router:<ids>`). Never benign. |

The engine cannot see whether a coarse prefix is really mixed; only ground truth can. It therefore marks **every** coarse flag as ambiguous. The evaluation then reports how many of those were truly mixed and how many benign hosts they would have hit ("collateral").

### 3.2 Proposal: non-overlapping exact units

`decision_nodes()` starts at each /8, which is always exact. It descends to a node's children only if no router reported a record *at* that node. In that case every child is exact and the children together hold all of the node's traffic. Otherwise the node itself is the unit. Every telemetry record therefore lands in exactly one unit: no overlap and no loss (unit-tested on asymmetric, mixed-granularity and residual cases).

### 3.3 Paper baseline without double counting

Algorithm 2 flags every key independently, and the paper's "every active node" export produces nested keys (10/8, 10.0/16, …, 10.0.0.1/32). Counting each flagged key would count one flood four times. Units are therefore the **most specific keys** in the fused map. A unit counts as flagged if its own key **or any ancestor key** is flagged, since Algorithm 2 would send a block command for that ancestor, covering the unit. `flagged_keys()` still exposes the raw per-key flags.

### 3.4 Opt-in variant `proposal_hier` [PROPOSAL]

Units that individually fall below τ_min are re-examined as groups under their exact common ancestor (/24, then /16, then /8). If the group's sum passes the rule, members that are themselves one-sided or above τ_ratio are flagged (`aggregate:<prefix>`). Members with adequate return traffic are never flagged this way. It was added because the plain proposal misses distributed low-rate attacks (D6). Its cost is measured in D9.

## 4. Evaluation method (`experiments/phase5/`)

- **Unit:** (prefix, window), using each method's own non-overlapping units.
- **Ground truth for a unit:**
  - *attack* if the prefix held ≥ 1 packet of a malicious flow in the window; *clean* otherwise, including units with no true traffic.
  - *mixed* if it was an attack unit that also held benign traffic.
  - Arrival-aligned methods (the paper's) are scored against the previous truth window, the inherent one-window lag established in Phase 4.
- **Metrics** (classified units only), always with explicit denominators:
  - TP = flagged ∧ attack; FP = flagged ∧ clean; FN = benign ∧ attack; TN = benign ∧ clean.
  - Precision = TP/(TP+FP); Recall = DR = TP/(TP+FN); F1; FPR = FP/(FP+TN).
- **Reported separately:**
  - abstention rate = abstained / (abstained + classified);
  - abstained units that held attack traffic;
  - window coverage = windows with ≥ 1 classified unit / windows with traffic.
- **Host level:** attacker host-windows are counted as *identified* (flagged /32), *unresolved* (inside a flagged coarser unit), *missed* or *abstained*. Also counted: false identifications (benign /32 flagged) and collateral (benign host-windows inside flagged coarse units). Host recall = identified / (identified + unresolved + missed).
- **Simulation:** 60 s per scenario, 1 s windows, windows 2–58 scored. Traffic is the Phase 4 client (on/off, 100 req/s, 30 rep/s); routing is asymmetric (requests via R1, replies via R2) unless stated.

## 5. Results [VERIFIED]

Full tables, including the sweep: `experiments/results/phase5/phase5_results.md` (generated; `phase5_results.json` is checked for exact reproduction by a test).

### 5.1 Simulation at E1: paper vs. proposal

Cells: TP / FP / TN / FN.

| Scenario | What it tests | Paper | Proposal | Proposal-hier | Key observation |
|---|---|---|---|---|---|
| D0 standalone | Only R1 monitored (paper's baseline) | 57/46/0/0 | 57/46/0/0 | 57/46/0/0 | Without return-path telemetry, **every** benign client window is an FP (FPR 46/46) for every method |
| D1 cooperative | Flood + asymmetric session, THRESH 20 | 57/0/46/0 | 57/0/46/0 | 57/0/46/0 | Both correct when granularity matches |
| **D2 granularity** | Same, THRESH 50 | **57/46/0/0** | **57/0/46/0** | 57/0/46/0 | Paper FPR 46/46; proposal 0/46 |
| D3 legitimate one-way | + benign 200 pps stream, no replies | 57/57/46/0 | 57/57/46/0 | 57/57/46/0 | **No method can separate one-way benign traffic from a flood** |
| D4 low-rate attack | 20 pps, zero return | 57/0/46/0 | 0/0/46/57 | 0/0/46/57 | The paper flags it only because it flags *any* zero-return traffic |
| D5 proportional attack | 1000 req/s eliciting 800 replies/s | 0/0/46/57 | 0/0/46/57 | 0/0/46/57 | **Missed by every method** (ratio 1.25) |
| D6 distributed low-rate | 50 hosts × 40 pps | 2850/0/46/0 | **0/0/46/2850** | **2850/0/46/0** | Finest-level decisions miss it; hierarchical views catch it |
| D7 mixed prefix | Attacker 192.168.1.66 in client's /24, THRESH 50 | 57/46/0/0 | 57/0/0/0 | 57/0/0/0 | Proposal: 46 flags are **ambiguous and truly mixed**; 46 collateral benign host-windows |
| D8 telemetry loss | 20% of R2 datagrams lost | 57/9/37/0 | 48/0/37/0 + **18 abstained** | same | Loss → paper FPs; proposal abstains (9 of the abstained units held attack traffic) |
| D9 benign sensors | + 30 benign one-way sensors × 20 pps | **57/1710/46/0** | **57/0/1756/0** | **57/1710/46/0** | The hierarchical variant pays for D6 with 1710 FPs here |

Derived metrics at E1 (from the same counts):

- **D2:** paper precision 57/103 = 0.55, FPR 46/46 = 1.00. Proposal precision 57/57 = 1.00, FPR 0/46 = 0.00.
- **D8:** proposal abstention rate 18/103 = 0.17; window coverage 48/57 = 0.84. The paper never abstains (abstention 0/103 in every scenario).
- **D9:** proposal-hier precision 57/1767 = 0.03, FPR 1710/1756 = 0.97.

**Host level at E1 (proposal):**

- D1 and D2: 57 of 57 attacker host-windows identified, 0 false identifications.
- D7: 11 identified (windows when the client was idle) and 46 unresolved (attacker detected only inside the mixed /8), with 46 collateral benign host-windows.
- D8: 48 identified and 9 abstained.
- D0: 35 false identifications of the benign client at /32, plus 11 coarse flags with 11 collateral host-windows.

### 5.2 Ablations at E1 (TP / FP / TN / FN)

| Scenario | Paper aggregation + corrected rule | Windowed aggregation + paper rule |
|---|---|---|
| D2 granularity | 57/34/12/0 | **57/0/46/0** |
| D7 mixed prefix | 57/46/0/0 | 57/0/0/0 |
| D8 loss | 57/7/39/0 | 48/0/37/0 (+18 abstained) |
| D4 low-rate | 0/0/46/57 | 57/0/46/0 |
| D6 distributed | 2850/0/46/0 | 2850/0/46/0 |

**What the ablations show:**

- **Aggregation fixes the false positives.** In D2 and D7 the corrected rule alone leaves 34 and 46 FPs; the windowed aggregation alone removes them. In D8, abstention comes from the aggregator.
- **The rule's volume gate decides low-rate behaviour.** It decides D4 and D9.
- **The paper's nested keys detect D6.** Applied to them, even the corrected rule catches the distributed attack via the /24 key, which is why `proposal_hier` was added.

### 5.3 Threshold sensitivity (pooled TP/FP/TN/FN over all scenarios **except D6**)

D6's 2850 attack units would otherwise dominate the pooled counts; tables including it are in the results file. Cells: F1 / FPR / DR.

| τ_ratio | Paper (any τ_rate) | Proposal τ_min = 0 | 10 | 25 | 50 (E1) | 100 | 250 |
|---|---|---|---|---|---|---|---|
| 1.5 – 3 | 0.29 / 1.00 / 0.89 | 0.29 / 1.00 / 0.89 | 0.29 / 1.00 / 0.89 | 0.60 / 0.20 / 0.77 | 0.60 / 0.20 / 0.77 | 0.70 / 0.11 / 0.77 | 0.87 / 0.00 / 0.77 |
| 4 – 20 | 0.32 / 0.88 / 0.89 | 0.32 / 0.85 / 0.89 | 0.32 / 0.85 / 0.89 | 0.78 / 0.05 / 0.77 | 0.78 / 0.05 / 0.77 | 0.80 / 0.04 / 0.77 | 0.87 / 0.00 / 0.77 |

**How to read this:**

- **The results move in steps.** The synthetic traffic has only three distinct ratios (benign client 3.3, zero-return ∞, proportional 1.25), so τ_ratio 1.5–3 behave identically, as do 4–20. **This is not a smooth sensitivity curve.** Real traffic has a spread of ratios.
- **τ_ratio ≤ 3 flags the benign client** (its 3.3 ratio exceeds the threshold) under every method.
- **Paper:** FPR stays ≥ 0.88 for every setting, because τ_rate has no effect.
- **Proposal:** raising τ_min lowers FPR to 0.00 at 250 pps. DR stays at 0.77 from τ_min = 25 upward, because the 20 pps low-rate attack (D4) is lost at that point and nothing else is lost until higher volumes. At 250 pps the one-way benign stream (200 pps) also stops being flagged.
- **Proposal-hier** (pooled without D6): FPR ≥ 0.80 for every setting, driven by D9.

### 5.4 Controlled Click runs (live, loopback, E1)

`tests/click/run_phase5_click.py`; results file `experiments/results/phase5/click/phase5_click_results.json`. Two routers, asymmetric path, constant flows: flood 2000 pps, client 100/30 pps. Ground truth is by construction. Each run lasts 10 s; 7–8 windows were scored after warm-up.

| Run | Paper TP/FP/TN/FN | Proposal TP/FP/TN/FN | Proposal would mitigate | Host level (proposal) |
|---|---|---|---|---|
| C1 THRESH 20 | 8/0/8/0 | 8/0/8/0 | 10.0.0.1/32 | 8/8 identified |
| C2 THRESH 50 (granularity) | 7/**7**/0/0 | 7/**0**/7/0 | 10.0.0.1/32 | 7/7 identified |
| C3 THRESH 50, attacker in client's /24 | 8/8/0/0 | 8/0/0/0 | **192.0.0.0/8** (ambiguous) | 0 identified, 8 unresolved, **8 collateral** |

These are results from the run whose file is committed. Three further repetitions gave the same qualitative outcome; the window counts varied between 7 and 8 with timing.

## 6. Findings

| ID | Finding |
|---|---|
| **D-1** | **The paper's τ_rate does nothing.** Literal Algorithm 2 flags every zero-return unit regardless of volume, so its FPR cannot be tuned below the level set by benign one-way and one-sided units (pooled FPR ≥ 0.88 at every setting). |
| **D-2** | **Cooperation is necessary but not sufficient.** Standalone monitoring (D0) gave FPR 46/46 for every method. Cooperative fusion removed those FPs only when granularity matched (D1), or when the windowed aggregation reconciled it (D2, C2). The paper's aggregation kept FPR at 46/46 (simulation) and 7/7 (live) under mismatch. |
| **D-3** | **Ratio detectors cannot separate some benign and malicious patterns at all:** one-way benign streams vs. floods (D3); proportional attacks vs. sessions (D5); many low-rate benign senders vs. a distributed low-rate attack (D6 vs. D9). Every threshold that catches one side flags the other. This is a limit of the traffic features, not of tuning. |
| **D-4** | **The volume gate is a trade-off, not a fix.** It removes low-rate benign FPs (D9: 0 FP) and loses low-rate attacks (D4, D6). The hierarchical variant reverses both (D6 caught, D9 1710 FPs). |
| **D-5** | **Abstention prevents loss-induced false positives at the cost of coverage.** D8: 0 FP and 18 abstained units, 9 of which held attack traffic. Those 9 are unexamined, **not** correct. |
| **D-6** | **Detection ≠ identification.** In D7 and C3 the attack was detected in every window, but only as a coarse, truly mixed prefix. The attacker could not be identified there, and acting on the prefix would hit the benign client (46 and 8 collateral host-windows). |
| **D-7** | **Even when the decision is correct, the paper's design over-acts.** Algorithm 2 flags nested keys, and blocking an ancestor key covers every host beneath it. The paper does not address which flagged key to act on [INFERENCE: relevant to Phase 6]. |

## 7. Tests [VERIFIED]

| Suite | Result |
|---|---|
| `tests/python/test_detection.py`: both rules (incl. the inert τ_rate), partition (non-overlap, completeness, coarse stop, residual), labels, abstention, rate conversion, hierarchical variant (flags group, spares replied hosts, needs group volume), paper units and ancestor propagation, scorer (TP/FP/TN/FN, denominators, abstention, mixed, host metrics, lag, empty denominators) | 16/16 |
| `tests/python/test_phase5_sim.py`: committed results reproduce exactly; τ_rate invariance across the whole sweep; every qualitative claim in §5–6 | 8/8 |
| `tests/click/run_phase5_click.py`: 3 live runs | 10/10 checks |
| Regression: all Phase 2–4 suites (C++ release and ASan+UBSan, valgrind, 74 Python tests with 0 skipped, Click Phases 2–4) | pass |

**Bugs found and fixed during this phase:**

1. The live harness scored paper windows (relative indices) against absolute-time proposal windows, which gave all-zero paper counts. Fixed by making `PaperAggregator` start lazily at the first datagram's absolute window, like `WindowedAggregator`. This did not change Phase 4 results (still reproduces exactly).
2. The live scoring range included trailing empty windows, which produced one spurious FN in C3. The range is now derived from windows that hold data.
3. Evaluation took 99 s. `mask()` and unit truth are now memoized, with byte-identical results, and it takes about 12 s.

## 8. Limitations

- Synthetic traffic with very few distinct ratios, so the sensitivity analysis is coarse (§5.3). One benign client profile. No realistic mixtures, TCP dynamics or spoofed sources.
- Scoring is per (prefix, window) unit. Methods produce different unit sets, so unit counts are not identical across methods. Host-level results complement this.
- E1 was chosen knowing the benign profile. Any metric at E1 is optimistic for a deployment that lacks that knowledge.
- Clean units are only those the methods produced. Benign traffic that never reaches a unit, such as an unmonitored path, is not counted as TN.
- Click runs are short (10 s), on loopback, with constant flows and one host clock.
- Nothing here measures detection latency or resource use (Phase 8).

## 9. Reproduction

```bash
cmake -S . -B build && cmake --build build -j
python3 -m experiments.phase5.run_phase5 --build build --out experiments/results/phase5
python3 tests/click/run_phase5_click.py /path/to/click/userlevel/click experiments/results/phase5/click
scripts/run_all_tests.sh /path/to/click            # everything, Phases 2-5
```

## 10. Questions for Phase 6 [OPEN]

1. **What to enforce:** only `malicious_host` (/32) decisions, or also `malicious_ambiguous` prefixes, accepting the measured collateral?
2. **Expiry:** should a block persist after the flood stops? Algorithm 3 never removes entries.
3. **Command authentication:** the drop channel is unauthenticated (Phase 1, P8). Should Phase 6 add at least a shared-key MAC, as a labelled extension?
4. **Abstained windows:** should existing blocks be kept or released during abstention?
