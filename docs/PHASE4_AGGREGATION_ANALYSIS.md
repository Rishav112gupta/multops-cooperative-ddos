# Phase 4 — Global State Aggregation: Analysis

**Status:** complete, awaiting approval before Phase 5.
**Date:** 2026-10-17

Labels: **[PAPER]** paper-faithful · **[PROPOSAL]** our proposed correction (a research extension, *not* an established result) · **[VERIFIED]** shown by a test or by the deterministic simulation in this phase · **[ASSUMPTION]** · **[INFERENCE]**.

> **Scope.** This phase asks one question: *does summing per-router statistics reconstruct the global traffic state?* It makes **no detection decision** (Phase 5) and measures no detection rate or false-positive rate. "One-sided window" below means a window in which the fused state shows a benign prefix sending traffic with **zero** return traffic, although return traffic really existed. Algorithm 2 would compute `Ratio = ∞` for that prefix. It is a precondition for a false positive, not a false positive itself.
>
> All results come from (a) a deterministic simulation that runs the real C++ MULTOPS tree and V1 exporter on generated traffic, and (b) live Click runs on loopback. Nothing here reproduces a result from the paper.

---

## 1. Decisions taken for this phase [ASSUMPTION]

You approved Phase 3 without answering its four open questions, so I adopted my recommendations as **configurable defaults**:

| Question | Default | Alternative implemented |
|---|---|---|
| Window alignment | Router's own interval timestamps (`align="sender"`) | Arrival time (`align="arrival"`, the paper's method) |
| Mixed granularity | Compare at the **finest exact prefix**: no router may hold a coarser record with traffic covering it | — |
| Counts vs. rates | Exact counts (V1) | Rates (paper aggregator) |
| Missing router | Window marked **incomplete**; the Phase 4 analysis does not score it | Phase 5 can choose to decide on partial data |

## 2. What the paper's aggregation does [PAPER]

Algorithm 2 and §4.3: for every received record, `M[p].in += to_rate; M[p].out += from_rate`. A `threading.Timer` periodically analyses `M` and then resets it. Implemented exactly in `aggregator/aggregator.py::PaperAggregator`. It reproduces the paper's own worked example, (B,1000,10) + (B,10,1000) = (1010,1010) (`test_paper_example_sec_4_3`).

**Implicit assumptions in this design [INFERENCE, each tested below]:**

- **A1:** every packet is observed by exactly one monitor.
- **A2:** each router sends exactly one report per analysis period.
- **A3:** reports describing the same time span arrive in the same period.
- **A4:** no report is lost or duplicated.
- **A5:** routers report a prefix at the same granularity (the key `p` means the same thing everywhere).

## 3. The proposal [PROPOSAL]

`WindowedAggregator` uses the Phase 3 receiver, which de-duplicates and reassembles intervals, and then:

1. **Sums exact counts, not rates.** Counts are increments and add across routers and across sub-intervals. EWMA rates are levels: adding two reports of the same router double counts.
2. **Assigns each router interval to one global window** using the midpoint of the router's own interval, or alternatively the arrival time.
3. **Records which routers reported.** A window missing an expected router is flagged *incomplete*, not decided.
4. **Reconciles granularity.** Every record contributes to all its ancestor nodes (/8 … own length). A node is **exact** only if no router reported a coarser record with traffic covering it. Such a coarser record holds traffic that cannot be split among its children; this is the PARTITION residual from Phase 3 §5. `finest_exact(address)` returns the deepest exact node on an address's path.
5. **Optional observation roles** (`RouterRole`): designate which routers count which direction. This works only if the operator knows the topology.

## 4. Method

**Simulation** (`experiments/phase4/netsim.py`, `run_phase4.py`):

- Traffic and ground truth:
  - Python generates every packet. Ground truth counts each packet **once** per 1 s window: requests go to fwd of their source, replies to rev of their destination.
  - Traffic uses the paper's addresses: client 192.168.1.1 ↔ server 192.168.1.2, sending 100 requests/s and 30 replies/s in an **on/off session** (3.3 s on, 1.7 s off). Flood 10.0.0.1 → 18.0.0.1 at 2000 pps.
  - The session is on/off on purpose: constant flows hide timing errors, because misattributed counts look alike.
- Each router's packets (in its local clock, through its input port) run through the **real C++ tree and V1 exporter** (`multops_replay --dump`).
- A network model adds a 5 ms delay, and seeded loss and duplication.
- The paper aggregator gets `ALL`-mode telemetry ("every node with active traffic", rates). The proposal gets `PARTITION`-mode telemetry (counts).
- 60 s per scenario. Windows 2–58 are scored, and only windows where the client has traffic (46 per scenario).
- Arrival-aligned results are scored against the *previous* truth window. A report for [k−1, k) is sent at k, so arrival windows inherently lag the data by one window.
- The run is fully deterministic: the committed results file is regenerated and compared in a test.

**Scenario design:**

- S2 isolates granularity mismatch (`THRESH 50`: R1 expands the 100 pps client to /32, while R2 never expands the 30 pps replies).
- S3 is the matched-granularity baseline (`THRESH 20` on both routers).
- S4–S9 each change **one** factor relative to S3.

## 5. Results [VERIFIED]

Full tables: `experiments/results/phase4/phase4_results.md` (generated). Benign client:

| Scenario | Tests assumption | Paper: one-sided windows | Paper /8 ratio rel. err (median / max) | Proposal: withheld | Proposal: one-sided | Proposal: windows with exact counts | Proposal: max count err |
|---|---|---|---|---|---|---|---|
| S1 single router (symmetric) | — | 0/46 | 0.01 / 0.03 | 0 | 0 | 46/46 | 0 |
| **S2 granularity mismatch** | A5 | **46/46** | 0.01 / 0.03 | 0 | **0** | 46/46 (at /8) | 0 |
| S3 asymmetric baseline | — | 0/46 | 0.01 / 0.03 | 0 | 0 | 46/46 | 0 |
| **S4 R1 reports every 0.5 s** | A2 | 0/46 | **0.99** / 1.08 | 0 | 0 | 46/46 | 0 |
| S5 R2 boundaries +0.5 s | A3 | 12/46 | 0.10 / ∞ | 0 | 0 | **23/46** | 15 |
| S6 R2 clock +300 ms | A3 | 12/46 | 0.10 / ∞ | 0 | 0 | **23/46** | 9 |
| **S7 20% of R2 datagrams lost** | A4 | **9/46** | 0.01 / ∞ | **9** | **0** | 37/46 | 0 |
| S8 30% of R1 datagrams duplicated | A4 | 0/46 | 0.01 / 1.04 | 0 | 0 | 46/46 | 0 |
| **S9 requests seen by R1 and R3** | A1 | 0/46 | 1.01 / 1.07 | 0 | 0 | **0/46** | **101** |
| S9b = S9 + roles (only R1 counts requests) | A1 | 0/46 | 1.01 / 1.07 | 0 | 0 | 46/46 | 0 |

Additional measured facts:

- **Arrival alignment in the proposal:**
  - S4 (sub-window intervals): 20/46 exact counts.
  - **S6 (clock skew): 12/46 one-sided.** The skewed router's report for a given time span arrives one window earlier than its peer's.
  - S5: 23/46, the same as sender alignment.
- **Flood source 10.0.0.1:** fwd counts exact and rev = 0 in every complete window of every scenario (proposal).
- **Receiver:** S7 has 9 missing sequence numbers, which are exactly the 9 withheld windows. S8 has 13 duplicates detected and discarded.

**Live Click confirmation** (`tests/click/phase4_two_routers.click`, two routers on a genuinely asymmetric path, 8 s, loopback, `THRESH 50`):

- The proposal's totals equal Click's `Counter` totals exactly: (16 821, 241).
- Every inner window has both directions for the client at /8. The request/reply ratio is within 15% of 100/30 in all 6 inner windows.
- The paper aggregator, on the same packets, had a one-sided key covering the client in **7/7** inner windows. Example window: `192.0.0.0/8 → [99, 28]` (balanced), but `192.168.0.0/16, 192.168.1.0/24, 192.168.1.1/32 → [99, 0]`.

## 6. Findings

| ID | Finding | Evidence |
|---|---|---|
| **G1** | **Summing per-prefix keys fails when routers report different granularities (A5).** One router's traffic hot enough to expand to /32 while the other stays at /8 makes the paper aggregator one-sided at /16, /24 and /32 **in every window**, both simulated (46/46) and live (7/7). The /8 key stays balanced. This is a direct consequence of MULTOPS's per-router, rate-dependent expansion (Phase 2, F3), so under asymmetric routing, with unequal rates per direction, it is the normal case, not an edge case. | S2; live test |
| **G2** | **Summing rates over time is wrong (A2).** EWMA rates are levels. A router reporting twice per analysis period is counted twice, roughly doubling that side's rate (median ratio error 0.99). Counts do not have this problem. | S4 |
| **G3** | **Loss creates one-sided windows (A4).** Every lost report of the return-path router produced a one-sided window for the paper aggregator (9 lost → 9 windows). The proposal detected the gap and withheld those windows (9 withheld, 0 one-sided). Withholding is a *policy*: it avoids the false precondition, but it also leaves the window undecided, so an attack in that window would go unexamined (Phase 5). | S7 |
| **G4** | **Duplicates inflate the paper aggregator (A4).** Ratio error up to 1.04 in windows with duplicates. V1 sequence numbers remove them completely. | S8 |
| **G5** | **Misalignment is not fixed by the proposal (A3).** With a 0.5 s phase offset or 300 ms clock skew, only 23/46 windows have exact counts (max error 15 and 9 packets). The proposal stays two-sided here (0 one-sided) only because both halves are counted with the same weight. Arrival alignment under skew *does* produce one-sided windows (12/46). **Exact reconstruction requires aligned interval boundaries**, which the current protocol does not provide. | S5, S6 |
| **G6** | **Double observation is invisible to any aggregator (A1).** If a packet crosses two monitors, both count it. The fused request count was +100% (max error 101), with no signal in the telemetry that anything is wrong. The role configuration fixes it only when the operator knows which monitor is the designated observation point for which traffic. | S9, S9b |
| **G7** | **Exactness has a price: resolution.** With granularity mismatch, the finest exact node for the client was /8 in every window (S2, live). In the simulation that /8 holds only the client; **in a real network a /8 aggregates many hosts**, so a per-/8 decision cannot single out a host [INFERENCE]. Even in the matched baseline (S3), 9/46 windows fell back to /8 at session starts, because expansion transients put pre-expansion traffic in a /8 residual. | levels column; S3 |
| **G8** | **When A1–A5 hold, the proposal reconstructs global counts exactly.** Zero count error in 46/46 windows for S1–S4 and S8, and exact live totals. This is a statement about counting, under the stated assumptions. It is **not** a statement about detection accuracy. | S1–S4, S8; live |

## 7. Answer to the Phase 4 question

**Does summing router counters reconstruct the global state?**

- **The paper's version** sums *rates* per *prefix key* per *arrival period*. It reconstructs the global state only under A1–A5, and its own setting violates A5. With asymmetric routing and different rates per direction, MULTOPS expands the two routers differently, and the fused state is one-sided at every prefix finer than the common level (G1). It additionally breaks under A2 (G2), A4 (G3, G4) and A3 (G5).
- **The proposed version** sums *counts*, with de-duplication, a completeness check and a granularity rule. It reconstructs counts exactly when A1 and A3 hold. It turns A4 violations into explicitly withheld windows rather than wrong ones. It cannot fix A1 (needs topology knowledge) or A3 (needs aligned intervals). It pays for exactness with coarser prefixes (G7).

**This is a proposal evaluated in simulation and on loopback.** It is not an established result, and its effect on detection is untested until Phase 5.

## 8. Proposed further corrections (not implemented; for Phase 9)

| Problem | Possible correction | Trade-off |
|---|---|---|
| G5 alignment | Routers export on **globally aligned boundaries** (e.g. at multiples of INTERVAL in synchronized wall-clock time, NTP/PTP) | Needs clock synchronization; residual skew still blurs edges |
| G7 resolution | **Coordinated expansion**: the aggregator tells all routers to expand a prefix, so granularity matches | Needs a control channel (like the drop-command channel), with the same security concerns |
| G6 double observation | Monitor only at the network edge; or tag packets as already counted | Deployment constraint; a tag changes packets |
| G3 withheld windows | Carry the last complete state forward, or decide on the complete router subset with an explicit "partial" flag | Either risks wrong decisions; evaluate in Phase 5 |

## 9. Tests [VERIFIED]

| Suite | Result |
|---|---|
| `tests/python/test_aggregator.py`: paper example, reset per period, rates summed over time, no de-duplication, exact asymmetric fusion, granularity fallback, missing router, sub-window intervals, sender vs. arrival, late intervals, roles, uncounted, absolute Unix-time windows | 15/15 |
| `tests/python/test_phase4_sim.py`: properties of §5 on 15 s runs, plus **committed results reproduce exactly** | 9/9 |
| `tests/click/run_phase4_click.py`: live two-router test | 6/6 checks |
| All Phase 2–3 suites (C++ release and ASan+UBSan, valgrind, Python, Click) | pass; 50 Python tests, 0 skipped |

**Bugs found and fixed during this phase:**

1. Arrival-aligned results were first scored against the wrong truth window (an evaluation bug; fixed with the explicit one-window lag in §4).
2. S4–S9 were first confounded with the S2 granularity effect (redesigned to change one factor at a time).
3. `WindowedAggregator` tried to create about 1.8 × 10⁹ empty windows when fed real Unix timestamps. The process was killed for memory in the first live run. It now starts at the first window with data, and a unit test covers it.

## 10. Limitations

- The simulation models telemetry, not a network: constant delays, no data-path loss, no routing changes, evenly spaced packets, one client and one attacker.
- Ground truth assumes each packet should count once, toward its source (requests) or destination (replies). That is the paper's intended global state, (R_in, R_out) per source.
- Scores cover 46 windows per scenario with a single seed. Loss and duplication results depend on that seed, though they are deterministic and reproducible.
- The live test used one host clock, so it cannot exhibit skew.
- Only `THRESH`, interval, phase, skew, loss, duplication and double observation were varied. Memory limits, spoofed or many-source traffic and higher rates are left for Phases 5 and 8.

## 11. Questions for Phase 5 [OPEN]

1. **Decision level.** Decide at the finest exact node (exact but possibly coarse, G7), or also evaluate the paper's per-key decision for comparison? My recommendation is both, reported side by side.
2. **Incomplete windows.** Skip them (no false positive from loss, but attacks go unexamined), or decide on partial data with a flag?
3. **Thresholds.** The paper gives no values for τ_ratio and τ_rate. Should Phase 5 sweep them and report sensitivity, rather than picking one?
4. **Observation unit for detection metrics** (Phase 8 prerequisite): (prefix, window) pairs?
