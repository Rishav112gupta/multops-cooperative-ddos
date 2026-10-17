# Phase 2 — MULTOPS / IPRateMonitor: Re-implementation and Verification

**Status:** complete, awaiting approval before Phase 3.
**Date:** 2026-10-17

Labels: **[VERIFIED]** checked by test or source reading in this phase · **[UPSTREAM]** behaviour of Click's code, verified by reading it · **[ASSUMPTION]** our engineering choice · **[INFERENCE]** reasoning, not tested · **[OPEN]** a decision needed before Phase 3.

> **Scope warning.** The authors' original modified `IPRateMonitor` is unavailable. This phase builds a **new** implementation. Its reference is the **upstream Click `IPRateMonitor`**, the element the paper says it modified (§4.2, §8), together with the paper's text. Nothing here reproduces or confirms any result in the paper. No detection, telemetry or performance claim is tested in this phase.

---

## 1. Objective

Provide a correct, testable MULTOPS rate monitor that behaves like the element the paper extended, adds the paper's export hooks (`INTERVAL`, `AGGREGATOR`, `run_timer`, `collect_stats_recursive`), and documents every way it differs.

## 2. Reference sources

| Source | Version | Use |
|---|---|---|
| AINA 2026 paper | local PDF | Requirements (`docs/PAPER_SPECIFICATION.md` §1) |
| Click `elements/ip/ipratemon.{hh,cc}` | github.com/kohler/click @ `9197a594b1c3` (2022-07-04) | Reference algorithm (read in full) |
| Click `include/click/ewma.hh` | same commit | EWMA arithmetic, used directly in a differential test |
| Gil & Poletto, USENIX Security 2001 | not re-read in this session | Background only. Statements about it below are labelled. |

## 3. How upstream IPRateMonitor works [UPSTREAM]

| Aspect | Behaviour | Source |
|---|---|---|
| Tree | 4 levels × 256 slots. Level *L* is keyed by address byte *L*, so a counter is a /8, /16, /24 or /32. | `ipratemon.hh` `Stats`, `update()` |
| Direction | Input 0 → keyed by **source**, "forward". Input 1 → keyed by **destination**, "reverse". For an address X: fwd = traffic *from* X, rev = traffic *to* X. | `ipratemon.hh:329,331` |
| Statistic | **EWMA rates, not counts.** `RateEWMAX<FixedEWMAXParameters<5,10>>`: α = 1/32 per epoch; epoch = `click_jiffies() >> 3` = 8 ms at user level (125 epochs/s); time constant ≈ 32 epochs ≈ 256 ms. | `ipratemon.hh:74,84`; `ewma.hh` |
| Update path | Every counter on the path from the root to the deepest existing level is updated, so a parent's rate includes its whole subtree. | `update()` loop |
| Expansion | If the deepest counter's fwd **or** rev rate (per second) ≥ THRESH, open **one** level below it. The new child copies the parent's EWMA. | `ipratemon.hh:286-294` |
| Folding | About once per second, walk the age list in a random direction and delete subtrees whose parent's fwd and rev are both < THRESH. Without a memory limit, stop after freeing about 10%. | `ipratemon.cc:182-193` |
| Memory limit | `MEMORY` in KB (minimum 100). New counters and tables are refused beyond it. | `make_counter`, `update` |
| Sampling | `RATIO`: a packet updates the EWMAs with probability ≈ RATIO. THRESH is pre-scaled by RATIO; reported rates are not rescaled. | `ipratemon.cc:71,106` |

**Comparison with the original MULTOPS design [INFERENCE, from memory of Gil & Poletto 2001; to be checked against that paper].** The 4-level, 256-ary layout, the per-record to/from rates, expansion above a threshold and contraction below it all match the original description. The original paper discusses attacker-oriented and victim-oriented trees. Click's single tree keyed by src on input 0 and dst on input 1 records both directions per address. Its exact correspondence to either orientation depends on how the Click configuration wires the inputs.

## 4. What the paper specifies vs. upstream

| Paper item | Upstream reality | Consequence |
|---|---|---|
| Alg. 1: `Lookup(T, P.SrcIP)` for **both** directions; `R_in++` / `R_out++` | Forward is keyed by src, reverse by **dst**. EWMA rates, not `++` counts. | Under Alg. 1 as written, a reply packet is attributed to the *responder's* address, not to the requester. That conflicts with the paper's own flow-pair definition (§3). We follow upstream. **[OPEN]** |
| `to_rate`, `from_rate` | Upstream says forward/reverse | Mapping not given. §7.3 says the attacker 10.0.0.1 had "high to_rate, zero from_rate", so **to_rate = forward (traffic sent by the prefix)** and **from_rate = reverse**. **[INFERENCE]** |
| "rate statistics for every node with active traffic" | — | "Active" and "which levels" are undefined. Both modes are implemented (`EXPORT ALL / LEAVES`). **[OPEN]** |
| `AGGREGATOR`, `INTERVAL` | — | Implemented as keywords. The timer runs the collection; the UDP send is **Phase 3**. |

## 5. Implementation map

| File | Role |
|---|---|
| `multops/include/multops/clock.hpp` | Epoch source interface. `ManualClock` for tests, `SteadyClock` for wall time. |
| `multops/include/multops/rate_ewma.hpp` | `RateEWMA2`: line-by-line port of `RateEWMAX` + `DirectEWMAX` |
| `multops/include/multops/multops_tree.hpp`, `multops/src/multops_tree.cpp` | `MultopsTree`: update, expansion, fold, forced_fold, memory limit, reset, lookup, look, `collect_stats` (the paper's `collect_stats_recursive`), `check_invariants` |
| `click/elements/coopipratemonitor.{hh,cc}` | Click element `CoopIPRateMonitor`: upstream arguments + `INTERVAL`, `AGGREGATOR`, `EXPORT`, `FOLD_UNITS`, `SEED`; `run_timer`; handlers |
| `click/elements/multopscore.cc` | Compiles the core into Click (`ELEMENT_PROVIDES(MultopsCore)`) |
| `click/install_into_click.sh` | Installs into a Click tree and rebuilds |
| `tools/multops_replay.cpp` | Deterministic offline trace replay (debugging, future experiments) |
| `tests/cpp/*`, `tests/click/*`, `tests/data/*`, `scripts/run_all_tests.sh` | Tests (see §8) |

The core library has no Click dependency, so every behaviour can be unit tested with a controlled clock. The element is a thin wrapper, which keeps Phase 3 (the sender) and the later phases independent of the data structure.

## 6. Deviations from upstream (all intentional, all tested)

| ID | Upstream | Ours | Why | Effect when traffic is below the limits |
|---|---|---|---|---|
| **D1** | `static unsigned prev_fold_time` inside an inline member, **shared by every IPRateMonitor instance** (`ipratemon.hh:236`) | Per-instance `prev_fold_epoch_` | With two monitors in one Click process, as a two-router asymmetric simulation would need, a busy instance keeps resetting the shared timestamp, so the other instance's periodic fold never runs. | None for a single instance |
| **D2** | `click_random()` for sampling and fold direction | Seeded `mt19937_64` (`SEED`) | Reproducible runs | Statistically equivalent |
| **D3** | Rate conversion `(scaled * freq) >> 10` in 32-bit `int` (`ipratemon.hh:268`) | 64-bit | Overflows above ~2.1 M units/s, i.e. BYTES mode above ~2.1 MB/s ≈ 17 Mbit/s, which corrupts both the expansion decision and the annotations | Identical |
| **D4** | `reset` handler frees level-0 counters without subtracting their size from `_alloced_mem` (`ipratemon.cc:343`) | Accounted | Repeated resets otherwise inflate memory use and eventually block all counting under `MEMORY` | Identical counters |
| **D5** | `forced_fold` step `perc = THRESH/5` may be 0 (`ipratemon.cc:153`), and there is no exit if only the root remains | Step ≥ 1; stop at root-only | Avoids an infinite loop when THRESH < 5 or memory cannot be freed | Identical when upstream terminates |
| **D6** | `_thresh = (_thresh * _ratio) >> 16` with `int × unsigned` → 32-bit wrap (`ipratemon.cc:71`) | Exact 64-bit | Upstream silently changes **any THRESH ≥ 65 536**, e.g. 100 000 → 34 464 (tested) | Identical for THRESH < 65 536 |
| **D7** | — | Exact per-window `fwd_count` / `rev_count` per counter, counted for every packet (not subject to RATIO) and reset by `collect_stats(…, true)` | The paper's Alg. 1 uses counts and its prose uses rates; exporting both lets Phase 3/4 choose with evidence | Additional data only |
| **D8** | `print()` checks activity *before* ageing the EWMA | Ages first, then checks | Avoids listing counters that are already idle | Reporting only |
| **D9** | `anno_level` handler, `set_anno_level`, `llrpc` | Omitted (the `anno_this < now` check is therefore absent) | Not used by the paper | None unless those features are used |
| **D10** | `sizeof(Counter)` = 40 B, `sizeof(Stats)` = 2080 B (measured against the Click headers) | 48 B and 2072 B | Extra window counters, no back-pointer | The same `MEMORY` holds slightly fewer counters |

`FOLD_UNITS UPSTREAM` (the default) keeps upstream's fold comparison exactly, including its unit mismatch (F7). `PERSEC` is an opt-in alternative for sensitivity studies.

## 7. Findings (verified behaviour that matters for the research)

| ID | Finding | Evidence | Why it matters |
|---|---|---|---|
| **F1** | The structure holds **EWMA rates**, not counts. A steady 10 000 pps reads as **9 998** (the fixed point sits slightly below k·1024). A step change reaches about 64% after 32 epochs (256 ms). | `ewma_converges_to_constant_rate`, `ewma_time_constant_is_32_epochs` | Detection latency has a floor of a few hundred ms from the estimator alone. Short bursts are smoothed. |
| **F2** | fwd = from-address (input 0, src); rev = to-address (input 1, dst) | `tree_directions_are_tracked_separately`, Click run | Defines what `to_rate` and `from_rate` mean in the telemetry. The paper's Alg. 1 differs (§4). |
| **F3** | **Cascade expansion**: one level per packet, but because children inherit the parent's EWMA, a prefix crossing THRESH at /8 reaches /32 in **3 more packets** | `tree_expands_one_level_per_update_and_cascades_to_host` | Trees deepen almost instantly for any hot /8. |
| **F4** | **Inherited-rate inflation**: 200 hosts × 1 pps in one /24 (200 pps total, THRESH 100). The host whose packet triggered the cascade was reported at **105 pps** at t = 0.19 s, against a true 1 pps. | `tree_inherited_rate_inflates_low_rate_host_after_cascade`; probe output in §8 | An exporter sending /32 records can transmit a large one-sided rate for a benign low-rate host. This is a possible false-positive source for the aggregator, inherited from upstream. |
| **F5** | Exact counts at deeper levels start only when that level is created, so for the same window parent ≠ Σ children | Click run: /8 = 50 100, /16 = 49 979, /32 = 49 977 | Count-based aggregation must use one level consistently. |
| **F6** | Parent counters include their subtree, so `EXPORT ALL` emits **nested** prefixes (10/8, 10.0/16, 10.0.0/24, 10.0.0.1/32 all carrying the same flood) | `tree_collect_all_levels_vs_leaves_only`, Click snapshot | Summing records across prefix lengths multiplies the traffic. The aggregator key must include the prefix length (Phase 4). |
| **F7** | Upstream fold compares a per-epoch ×1024 value with a per-second THRESH. At 125 epochs/s a subtree is kept until its rate drops below ≈ 0.12 × THRESH. With `MEMORY` set but not reached, **at most one subtree is folded per second**. | `tree_fold_units_upstream_vs_per_second`, `tree_fold_prunes_idle_subtrees` | Stale /32 subtrees linger. Combined with F4, this affects how long an inflated record persists. |
| **F8** | When `MEMORY` is exhausted, **new /8 counters cannot be created and their packets are not counted at all** | `tree_memmax_blocks_new_counters_at_root`, `tree_memmax_limits_expansion` | **[INFERENCE]** A spoofed-source flood that fills memory could blind the monitor to other prefixes. Relevant to Phases 5 and 9. |
| **F9** | Per-packet cost: at most 4 counter updates plus at most one allocation of 2 072 B + 48 B. Fold is O(tables) once per second. Collect is O(counters). Memory per fully expanded host path ≈ 3 tables + 4 counters ≈ 6.4 KB. | Code, `tree_memory_accounting_matches_structure` | Analytical only. Timing is measured in Phase 8. |
| **F10** | With RATIO < 1, reported rates are ≈ RATIO × true rate (4000 pps at RATIO 0.5 reads ≈ 2000). Exact counts are unaffected. | `tree_sampling_ratio_scales_threshold_and_keeps_exact_counts` | The aggregator must rescale, or RATIO must be 1. |
| **F11** | The 32-bit EWMA storage limits per-epoch samples to about 4.19 M units, i.e. ≈ 524 M units/s (BYTES mode ≈ 4.2 Gbit/s). Kept for fidelity. | Arithmetic from `ewma.hh` | A limit to state in experiments. |
| **F12** | Upstream THRESH ≥ 65 536 wraps (D6) and the fold timer is shared across instances (D1) | Tests, source lines | Anyone re-running the authors' setup on upstream Click with such values would see different behaviour. |

## 8. Test results [VERIFIED]

Command: `scripts/run_all_tests.sh <click-src>`. Logs are written to `build/test-logs/` and are not committed.

| Suite | Result |
|---|---|
| `test_rate_ewma` | 11 tests, 0 failures |
| `test_multops_tree` | 31 tests, 0 failures |
| `diff_upstream_ewma`: our EWMA vs Click `ewma.hh`, 200 random trials incl. epoch wrap-around and ≥100-epoch gaps | 500 148 comparisons, **0 mismatches** |
| `replay_sample_trace` | pass (`invariants=ok`) |
| ASan + UBSan build, all of the above | pass |
| valgrind memcheck on both unit suites | 0 errors, 0 leaks |
| Compiler warnings (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion`) | 0 |
| Click build of `CoopIPRateMonitor` with Click's own flags | 0 warnings |
| `tests/click/phase2_equivalence.click`: upstream `IPRateMonitor` vs `CoopIPRateMonitor` on identical packets, 5 s, 10 000 + 50 pps forward, 200 pps reverse | 11/11 checks pass. Same 9 active prefixes. Worst relative rate difference 0.0000% in 4 of 5 repeated runs and 0.0024% in 1 (an 8 ms epoch ticked between the two handler reads). Exact counts equal Click `Counter` totals (e.g. 50 090 = 50 090). Export timer fired 5 times in 5 s. |

Probe for F4 (scratch program, inputs as in the test): `true per-host rate 1 pps, aggregate 200 pps; peak reported /32 rate = 105 pps for 10.0.0.164 at t=0.192 s`.

**Problems found and fixed during this phase:**

1. A test expectation assumed 10 000 pps reads as exactly 10 000. The truth is 9 998, as F1 explains. The test was corrected, not the code.
2. A test assumed gradual expansion; the real behaviour is the cascade in F3. The test was rewritten to assert the real behaviour.
3. UBSan found a signed overflow in our THRESH × RATIO computation for huge THRESH. Fixing it led to the discovery of upstream bug D6.
4. Our `look` header printed jiffies. Upstream actually prints epochs (its documentation says jiffies), so ours now matches upstream.

## 9. What is NOT verified

- Anything about detection accuracy, false positives, telemetry, aggregation or enforcement.
- Throughput and latency of the element (Phase 8).
- A build on WSL2 or with older compilers. The core targets C++14 to make that likely, but it is untested.
- A Click kernel-module build.
- Behaviour against the authors' original modified element, which is unavailable.

## 10. Decisions needed before Phase 3 [OPEN]

1. **Rates or counts in `PrefixStatsRecord`?** The paper says rates. Exact window counts (D7) are additive across routers within a window, while EWMA rates are not exactly additive across unsynchronised routers. My recommendation is to carry both, which needs a record larger than the paper's 16 bytes; the size change would be documented. The alternative is to keep the paper's 16-byte record with rates only.
2. **Export mode:** `LEAVES` avoids the nested double-counting in F6. `ALL` matches "every node with active traffic".
3. **to_rate / from_rate mapping:** adopt to_rate = forward and from_rate = reverse, per the inference from §7.3?
4. **Telemetry header additions** (router ID, sequence number, interval ID) to support the duplicate, loss and window analyses in Phases 3–4. This would be a documented extension beyond the paper's 6-byte header.
