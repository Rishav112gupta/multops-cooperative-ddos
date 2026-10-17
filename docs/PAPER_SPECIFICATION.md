# Technical Specification Extracted from AINA_2026.pdf

This is the reference that the new implementation in this repository is built against. It lists **only** what the paper says, with page and section, and marks each item as:

- **SPEC**: stated concretely enough to implement directly.
- **UNDER**: mentioned, but key details (types, units, values) are missing.
- **NONE**: not specified at all. Any choice we make is an engineering assumption and is recorded in the phase report that introduces it.

The paper PDF is kept locally under `paper/` and is git-ignored. It is not redistributed.

---

## 1. MULTOPS / IPRateMonitor (§2.3, §4.1, §4.2, Alg. 1)

| Item | Paper text (paraphrased) | Status |
|---|---|---|
| Data structure | MULTOPS, a "tree-based data structure … to monitor packet rate statistics across multiple levels of aggregation (IP prefixes)" (§4.1) | SPEC |
| Shape | "4-level, 256-ary tree structure" (§4.2) | SPEC |
| Base element | The authors *modified* Click's existing `IPRateMonitor` element (§4.2, §8) | SPEC |
| Expansion and pruning | "dynamically prunes and expands the tree based on traffic volume … within a fixed memory budget" (§2.3) | UNDER (no thresholds or memory values) |
| Per-packet update | Alg. 1 l.2–3: `Node ← Lookup(T_local, P.SrcIP)`; `if P.isIngress then Node.R_in++ else Node.R_out++` | UNDER (keyed on SrcIP for *both* directions, which differs from upstream; "ingress" undefined) |
| Rate vs. count | The algorithm uses `++` counters, while the prose and the protocol use `to_rate` / `from_rate` | UNDER (contradictory) |
| New parameters | `AGGREGATOR` and `INTERVAL`, configured from the Click script (§4.2) | UNDER (syntax and units not given) |
| Periodic export | Click `Timer` → `run_timer` → collect + send → reschedule (§4.2) | SPEC |
| Traversal | `collect_stats_recursive` traverses the tree and extracts "rate statistics for every node with active traffic" (§4.2) | UNDER ("active" undefined; whether every level or only leaves is exported is unstated) |
| Send | `send_stats_packet`: `htonl`/`htons`, `sendto()` (§4.2) | SPEC (for Phase 3) |
| Configuration values | TYPE, RATIO, THRESH, MEMORY used in experiments | NONE |

## 2. UDP telemetry protocol (§4.2, §5.1, §7.4)

| Item | Paper text | Status |
|---|---|---|
| Transport | UDP, "fire-and-forget" | SPEC |
| Destination port | 49555 on the aggregator | SPEC |
| Header | `StatsPacketHeader`, 6 bytes: 32-bit authentication placeholder + 16-bit record count | SPEC (sizes), UNDER (packing) |
| Record | `PrefixStatsRecord`, 16 bytes: IP prefix, prefix length, `to_rate`, `from_rate`; "padding was explicitly considered" | UNDER (field widths, types, pad position and units not given) |
| Byte order | Network order via `htonl`/`htons` | SPEC |
| Records per packet, MTU handling, multi-packet export | — | NONE |
| Router ID, sequence number, timestamp, interval ID | — | NONE (absent) |
| Authentication | Placeholder only | SPEC (as a placeholder, i.e. *not* implemented) |

## 3. Python aggregator (§4.3, Alg. 2, §5.1)

| Item | Paper text | Status |
|---|---|---|
| Implementation | Standalone Python, `aggregator.py`, UDP socket, `struct` parsing | SPEC |
| State | Python dict keyed by IP prefix; adds incoming `to_rate` and `from_rate` | SPEC |
| Worked example | R1 sends (B, 1000, 10), R2 sends (B, 10, 1000), and the fused result is (1010, 1010) | SPEC |
| Analysis loop | `threading.Timer` → `analyze_and_reset_stats`; the dict is reset after each analysis | SPEC |
| Analysis period | — | NONE |
| Is prefix length part of the key? | — | NONE |
| Output | Sends drop commands to UDP port 50001 | SPEC |

## 4. Cooperative detection algorithm (Alg. 1 l.7–12, Alg. 2)

```
Ratio ← (R_out > 0) ? R_in / R_out : ∞
Alg.1: if Ratio > τ_crit                                  then block Msg.Src
Alg.2: if Ratio > τ_ratio  or  (R_out == 0 ∧ R_in > τ_rate) then block p
```

| Item | Status |
|---|---|
| Ratio formula | SPEC |
| Values of τ_crit, τ_ratio, τ_rate | NONE |
| Zero-traffic handling | SPEC, but as written the `τ_rate` clause is subsumed by `Ratio = ∞` (see Phase 1, P3) |
| Alg. 1 accumulates without reset; Alg. 2 resets each window | SPEC (inconsistent between the two algorithms) |

## 5. PolicyEnforcer (§4.4, Alg. 3)

| Item | Paper text | Status |
|---|---|---|
| Form | A new Click element listening on UDP port 50001 | SPEC |
| Command format | "explicit packing and alignment" | NONE (no layout given) |
| Logic | On a command, if the prefix is not present, add `(prefix, len, DROP)`. On each packet, longest-prefix lookup of `pkt.src`; drop on match, otherwise forward. | SPEC |
| Expiry, removal, authentication, acknowledgement | — | NONE |

## 6. Click router configurations (§5.1, §5.2, Fig. 1)

| Item | Paper text | Status |
|---|---|---|
| Platform | Click Modular Router on WSL2, same host as the aggregator | SPEC |
| Scripts | `test_attack.click` (one-way flood only) and `test-full.click` (flood plus legitimate two-way session) | UNDER (contents not given) |
| Counters | `ctr` (attack) and `ctr_good` (legitimate), read via `ControlSocket` on TCP 7777 | SPEC |
| Traffic generation | Runtime synthetic generation inside Click; PCAP replay rejected | SPEC |
| Number of monitors | Not stated. Fig. 1 shows one router pipeline. | NONE |

## 7. Experimental scenarios (§5.3, §6.1 Table 1, §7)

| Parameter | Flow A (malicious) | Flow B (legitimate) |
|---|---|---|
| Source → target | 10.0.0.1 → 18.0.0.1 | 192.168.1.1 → 192.168.1.2 |
| Rate | 10 000 pps | 50 pps |
| Pattern | Unidirectional UDP flood, R_out = 0 | Asymmetric session; the return path bypasses the ingress monitor |

| Scenario | Script | Aggregator | Paper hypothesis |
|---|---|---|---|
| 1. Baseline | `test_attack.click` | off | `ctr` increases indefinitely |
| 2. Simple cooperative | `test_attack.click` | on | Flood detected, drop sent, `ctr` stops |
| 3. Advanced cooperative | `test-full.click` | on | `ctr` stops, `ctr_good` keeps increasing |

Durations, repetitions, packet sizes, analysis interval and thresholds are **NONE**.
