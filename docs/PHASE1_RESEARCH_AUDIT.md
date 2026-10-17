# Phase 1 — Repository and Research Audit

**Project:** Decoupled State Aggregation for Asymmetric DDoS Detection using MULTOPS
**Paper audited:** `AINA_2026.pdf` (Smriti, Dham, HariBabu K — BITS Pilani), 12 pages, read in full
**Audit date:** 2026-10-17
**Scope:** Read-only. No source code was created, modified or deleted.

Labels used in this document:

- **[VERIFIED]**: checked directly against the paper text or the repository contents.
- **[PAPER CLAIM]**: stated by the paper but not reproduced by us.
- **[ASSUMPTION]**: our working assumption, to be confirmed.
- **[HYPOTHESIS]**: a suspected problem that needs code or experiments to confirm.

---

## 1. Headline finding

**The repository contains no implementation of the paper. [VERIFIED]**

| Location inspected | Contents |
|---|---|
| `Rishav112gupta/interpretable_rythm_generation`, branch `main` / `claude/great-curie-irkdlg` (commit `b8d1b5e`, "Initial commit") | One file: `README.md`, whose entire content is `# interpretable_rythm_generation` |
| Remote branch `claude/hindustani-tala-grammar-0m49pm` | Hindustani tala / rhythm-grammar research (datasets, grammar JSON). Unrelated to networking. |
| Remote branch `claude/intelligent-fermat-uqwnt0` | `instagram-automation/` web application. Unrelated. |
| Keyword search (`multops`, `IPRateMonitor`, `PolicyEnforcer`, `aggregator`, `.click`) across all branches | No relevant hits. The only `click` matches are React `onClick` handlers. |
| Other repositories reachable from this session (`Rishav112gupta/INSTAGRAM_AUTOMATION`, `ArnavGarg2006/AgriTech_Information_System_Sikkim`) | Not inspected beyond their names. Neither name suggests MULTOPS code. |

The repository name ("interpretable rhythm generation") also doesn't match the research topic. The MULTOPS code most likely lives somewhere else, for example on an author's machine, in a separate GitHub repo, or in a Click source tree on WSL2.

**Consequence:** every code-related row in the audit table below is *Missing*. The rest of this report audits the paper on its own terms: its internal consistency, its algorithms, and which claims can be tested once the code is available.

---

## 2. Research summary (plain English)

1. **MULTOPS** (Gil & Poletto, USENIX Security 2001) is a tree of packet counters keyed by IP prefix (/8 → /16 → /24 → /32). For each prefix it tracks the rate of packets going *to* it and coming *from* it. Normal traffic is roughly proportional (requests produce responses). A flood produces a heavy one-way stream, so a large to/from ratio suggests an attack.
2. **The asymmetry problem.** On the Internet, a request and its reply often take different paths. A router that sees only the request direction measures `R_out ≈ 0` and wrongly calls legitimate traffic a flood (a false positive).
3. **Proposed fix.** Each router keeps its local MULTOPS tree but periodically exports per-prefix `to_rate`/`from_rate` over a small UDP telemetry protocol. A central Python **aggregator** sums the values from all routers per prefix, recomputes the ratio on this "global" view, and sends a UDP **drop command** to a Click `PolicyEnforcer` element when a prefix looks malicious.
4. **Reported result [PAPER CLAIM].** In a WSL2 simulation with one 10 000 pps UDP flood and one 50 pps legitimate asymmetric session, the cooperative system blocked the flood (100% detection) and did not block the legitimate session (0% false positives). Telemetry overhead is described as "negligible".

## 3. Architecture as described in the paper

```
 Click router(s)                                     Python aggregator (aggregator.py)
 ┌───────────────────────────────┐   UDP :49555    ┌─────────────────────────────────┐
 │ traffic sources (synthetic)   │  stats packets  │ recv + struct.unpack            │
 │   → IPRateMonitor (modified)  │ ──────────────► │ dict[prefix] += to/from rates   │
 │      run_timer every INTERVAL │                 │ threading.Timer:                │
 │      collect_stats_recursive  │                 │   analyze_and_reset_stats       │
 │      send_stats_packet        │   UDP :50001    │   ratio > τ → SendBlockCommand  │
 │   → PolicyEnforcer  ◄──────────────────────────  │                                 │
 │      drop if src ∈ blocklist  │  drop commands  └─────────────────────────────────┘
 │   → Counter (ctr, ctr_good)   │
 │   ControlSocket :7777 (telnet)│
 └───────────────────────────────┘
```

---

## 4. Component audit table

| Research component | Paper description | Code status | Evidence | Issues |
|---|---|---|---|---|
| **IPRateMonitor (modified)** | Click C++ element; 4-level, 256-ary MULTOPS tree; new `AGGREGATOR` and `INTERVAL` parameters; `run_timer`, `collect_stats_recursive`, `send_stats_packet` (§4.2, p.5) | **Missing** | No C++ files in any branch | Can't check rate vs count semantics, tree expansion or pruning, reset behavior, or which direction counts as "ingress" (see §5, P1/P7) |
| **UDP telemetry** | `StatsPacketHeader` 6 B (32-bit auth placeholder + 16-bit record count); `PrefixStatsRecord` 16 B (prefix, length, `to_rate`, `from_rate`); `htonl`/`htons`; port 49555 (§4.2, §5.1) | **Missing** | No sender or receiver code | Field widths and types not specified; a natural C++ struct of `uint32+uint16` is 8 B, not 6 B, unless packed (P2); no sequence number, router ID or timestamp; auth field is a placeholder |
| **Aggregator** | `aggregator.py`; dict keyed by prefix; sums rates; `threading.Timer` → `analyze_and_reset_stats`; Algorithm 2 (§4.3) | **Missing** | No Python files | Algorithm 2's `τ_rate` guard has no effect as written (P3); summing is only correct for disjoint observations (P4); thresholds `τ_ratio`/`τ_rate` have no numeric values |
| **PolicyEnforcer** | Click element listening on UDP 50001; Algorithm 3 adds DROP routes for a source prefix (§4.4) | **Missing** | No C++ or Click files | No command format given; no expiry or removal; no authentication, so a forged UDP packet could block any prefix (P8) |
| **Drop-policy protocol** | "Explicit packing and alignment", Python sender → C++ receiver (§4.4) | **Missing** | — | Wire format not given in the paper at all |
| **Click scripts** | `test_attack.click` (flood only), `test-full.click` (flood + legitimate) (§5.2) | **Missing** | — | Topology unclear: the testbed has one router (§5.1), yet the paper claims reconstruction across routers (P5) |
| **Experiments / logs** | 3 scenarios; ControlSocket `telnet localhost 7777`; log excerpts p.10–11; Table 2 | **Missing** (no logs, configs, scripts or raw data) | Only the excerpts printed in the PDF | Table 2 contradicts §7.1 (P6); each class is n = 1 flow; no latency or overhead numbers (P9) |
| **Build instructions / dependencies** | Click Modular Router on WSL2; Python | **Missing** | README is one line | Click version, build flags (`--enable-user-multithread`?, element registration) unknown |
| **Tests** | None described | **Missing** | — | — |
| **Documentation** | Paper only | **Partial** (paper only) | This file is the first project doc | — |

**Classification summary**

| Component | Status |
|---|---|
| IPRateMonitor extension | Missing |
| UDP telemetry protocol | Missing (the paper specification is also incomplete) |
| Aggregator | Missing |
| PolicyEnforcer + drop protocol | Missing |
| Experimental testbed (Click scripts) | Missing |
| Experimental results | Missing. The paper's reported numbers are **inconsistent with the paper** in places (see P5, P6). |

No component is in the "Implemented and verified" or "Implemented but unverified" category.

---

## 5. Problems found in the paper itself (code-independent)

These findings come only from reading the paper. Each one is something Phases 2–8 must confirm or refute against the real code.

### P1 — Counts vs. rates [HYPOTHESIS]
Algorithm 1 increments counters (`Node.R_in++`), but the text and protocol talk about `to_rate`/`from_rate`. Original MULTOPS (and, as far as we know, Click's stock `IPRateMonitor`) keeps **exponentially-decayed rates**, not raw counts. *[ASSUMPTION: to be checked against the Click source in Phase 2.]* If raw counts are exported and never reset, ratios drift over time. If decayed rates are exported, summing them across routers with different update times is approximate.

### P2 — 6-byte header and C++ struct padding [HYPOTHESIS]
`struct { uint32_t auth; uint16_t n; }` has `sizeof == 8` on mainstream ABIs unless declared `__attribute__((packed))` or serialized field by field. The paper says C++ structs were used "so that there are no padding issues", which is backwards: structs are where padding comes from. For the 16-byte record, `uint32 prefix + uint8 len + 3 pad + uint32 to + uint32 from = 16` fits, but only if both rates are 32-bit integers. Floats or doubles, or a different layout, would change it. The Python `struct` format must use `!` (network order, no native alignment) with explicit `x` pad bytes. Phase 3 will check this.

### P3 — The `τ_rate` guard in Algorithm 2 never takes effect [VERIFIED from algorithm text]
Algorithm 2, lines 5–6:
```
Ratio ← (R_out > 0) ? R_in / R_out : ∞
if Ratio > τ_ratio  or  (R_out == 0 ∧ R_in > τ_rate) then block
```
When `R_out == 0`, `Ratio = ∞ > τ_ratio`, so the first clause is already true and the `τ_rate` minimum-volume condition is never needed. As written, **any prefix with even one packet in and zero packets out in a window gets blocked**, including DNS queries over asymmetric paths, one-way telemetry, multicast and so on. Algorithm 1 (line 10) has the same issue and also lacks the `τ_rate` clause entirely. The intended rule is probably `(R_out > 0 ∧ Ratio > τ_ratio) ∨ (R_out == 0 ∧ R_in > τ_rate)`, plus a minimum-volume floor in both branches. This is a proposal, not an established fix.

### P4 — Summing per-router values is only correct for disjoint observations [HYPOTHESIS]
`G.R_in += Msg.R_in` reconstructs the global rate only if **each packet is counted by exactly one monitor**. If a packet crosses two monitored routers (common in a real path), it is counted twice. Summing also assumes the routers' reporting windows line up, but there's no timestamp or sequence number. UDP loss of one report silently turns a balanced flow into a one-sided one: losing Router 2's report in the paper's own example gives `to=1000, from=10`, which is ratio 100 and gets blocked. Duplicate or delayed reports inflate one side. Records from different prefix lengths (a /24 and a /32) must not be merged into one dict key unless the length is part of the key. Phase 4 will analyze this.

### P5 — One router can't produce the claimed asymmetric reconstruction [HYPOTHESIS / needs scripts]
§5.1 says the testbed is one Click script plus the aggregator on one host. Table 1 says Flow B's return traffic "bypasses the ingress monitor". If the only monitor doesn't see the return path, the aggregator has no source for `R_out` and cannot reconstruct balance. Yet §7.3 reports "balanced to_rate and from_rate" for 192.168.1.1. Possible explanations: `test-full.click` contains two `IPRateMonitor` instances acting as two routers, or the return path is in fact observed. **Multi-router aggregation, the paper's core contribution, isn't shown to have been tested with more than one telemetry source.** The `.click` scripts are needed to settle this.

### P6 — Table 2 contradicts the Scenario 1 description [VERIFIED from paper text]
- §7.1 says that without the aggregator the attack "was not being blocked … a detection failure", but Table 2 reports Baseline **Detection Rate = 100%** for the flood.
- Baseline **FPR = 100%** for benign traffic, but Scenario 1 used `test_attack.click`, which according to §5.2 contains **only attack traffic**. No benign flow was present in the baseline run, so its FPR wasn't measured.
- In the standalone baseline nothing ever acts on detections (no aggregator, so the PolicyEnforcer receives nothing). "Detected" and "flagged" aren't observable there without separate local-detection logging.

### P7 — Direction semantics are undefined [HYPOTHESIS]
§3 defines `R_in(S,D)` and `R_out(D,S)` per flow pair. MULTOPS keys on a single address/prefix with "to" and "from" counters. Algorithm 1 uses `P.SrcIP` and `P.isIngress`, a third convention. The aggregator also keys on `Msg.Src` (Alg. 1) versus prefix `p` (Alg. 2). Whether the tree is attacker-oriented (keyed by source) or victim-oriented (keyed by destination) determines what gets blocked. A spoofed-source flood would have its traffic spread across many random source prefixes, each low-volume. Phase 2 and Phase 5 will cover this.

### P8 — Drop-command channel is unauthenticated [HYPOTHESIS, high severity if confirmed]
The telemetry auth field is a "32-bit placeholder" (§4.2). The drop protocol has no authentication described, and Algorithm 3 has no expiry or removal. Anyone who can send a UDP packet to port 50001 could block arbitrary prefixes, which turns the mitigation into a denial-of-service tool. Forged telemetry to port 49555 could also cause legitimate prefixes to be flagged. This should be tested only in an isolated lab (Phase 6).

### P9 — Quantitative claims lack data
- **Sample size:** one malicious flow and one benign flow, in one run each. "100%" and "0%" are 1/1 and 0/1. No repetitions or variance are reported.
- **Observation unit:** undefined (flow? prefix? analysis window? packet?).
- **Thresholds** `τ_crit`, `τ_ratio`, `τ_rate`, `Δt` and the window length are never given numerically.
- **Overhead:** "negligible" with no measured bytes/s, CPU or memory. §1.4 promises a "detection delay" comparison, but none appears in §7.
- **Detection latency:** the logs show the counter stopping at about 20 089–20 112 packets. At the claimed 10 000 pps this implies roughly 2 s to mitigation. *[Our inference, not a paper claim.]*
- Paper references [8] and [13] have date and volume details we have not checked. Out of scope here.

### P10 — Minor inconsistencies
- Scenario 2 final count 20112 vs Scenario 3 attack count 20089. Not a contradiction (separate runs), but neither is explained.
- The log boxes are titled "Aggregator Log Output" but show ControlSocket `read:` values of Click counters.
- Fig. 1 targets: attack → 18.0.0.1, legitimate → 192.168.1.2. Table 1 agrees. OK.
- §4.1 states that MULTOPS is "ineffective against DDoS attacks with proportional traffic flows". The cooperative design inherits this limitation, and the paper doesn't evaluate it.

---

## 6. Claims register: what is claimed vs. what is reproducible

| # | Paper claim | Where | Reproducible now? |
|---|---|---|---|
| C1 | Header 6 B, record 16 B | §4.2, §7.4 | No: no code |
| C2 | Aggregator removes false positives for asymmetric flows | Abstract, §7.3 | No: no code, and see P5 |
| C3 | 100% DR on high-rate UDP flood | Abstract, Table 2 | No: n = 1, no code |
| C4 | 0% FPR for cooperative framework | Table 2 | No: n = 1, no code |
| C5 | Baseline has 100% FPR | Table 2 | No, and inconsistent with §5.2 (P6) |
| C6 | Telemetry overhead negligible | Abstract, §7.4 | No: no measurements given |
| C7 | O(1) average aggregator update | §7.4 | True for a Python dict insert/update in general. Per-window cost is O(active prefixes). |

---

## 7. What is needed to proceed

The following must be supplied before Phase 2 (MULTOPS verification) can be anything other than a literature exercise:

1. Modified `ipratemonitor.cc` / `.hh` (and the unmodified Click version it was based on).
2. `policyenforcer.cc` / `.hh`.
3. `aggregator.py`.
4. `test_attack.click`, `test-full.click`.
5. Any logs, screenshots or notes from the runs reported in §7.
6. The Click version or commit, and build steps used on WSL2.
7. The numeric values of `τ_ratio`, `τ_rate` and `INTERVAL`.

Ways to provide them: push them to this repo (ideally a dedicated `multops/` directory or a new repository), attach the GitHub repo to this session, or upload a zip.

If the code can't be recovered, the alternative is a **clean-room re-implementation from the paper's specification**. That would be a *new* implementation, and results from it could not count as reproducing the paper's results. That decision belongs to the research owner.
