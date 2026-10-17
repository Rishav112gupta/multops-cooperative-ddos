# Phase 3 — UDP Telemetry Protocol: Implementation and Validation

**Status:** complete, awaiting approval before Phase 4.
**Date:** 2026-10-17

Labels: **[PAPER]** paper-faithful behaviour · **[EXTENSION]** our research extension · **[VERIFIED]** shown by a test in this phase · **[ASSUMPTION]** engineering choice · **[INFERENCE]** reasoning, not tested.

> **Scope.** This phase covers how router statistics are serialized, sent, received and validated. It performs **no aggregation and no detection**; those are Phases 4–5. All tests ran on the loopback interface (127.0.0.1) inside this container. Nothing here reproduces a result from the paper.
>
> **UDP gives no delivery guarantee.** Datagrams can be lost, duplicated or reordered. The V1 format lets a receiver *detect* these events. It does not prevent them and does not retransmit.

---

## 1. Decisions implemented (from the Phase 2 review)

| # | Decision | Implementation |
|---|---|---|
| 1 | Export both EWMA rates and exact per-interval counts; versioned protocol | V1 format: 72-byte header, 32-byte records (§3). The paper format is kept separately as `FORMAT PAPER` (§2). |
| 2 | Prefer non-overlapping leaf statistics, but verify coverage first; keep hierarchical option | Coverage was measured. Pure leaves **lose** traffic (§5), so a new `PARTITION` mode was added: leaves plus residual records, exact and non-overlapping. `LEAVES` and `ALL` remain available. |
| 3 | Verify `to_rate`/`from_rate` with controlled bidirectional tests | Confirmed in Click with real packets and swapped-wiring control (§4). Applied identically in C++ and Python. |
| 4 | Router ID, sequence number, interval ID, protocol version; validate malformed, duplicate and out-of-order input | All in V1 (§3), plus boot ID (restart detection) and fragmentation. Receiver behaviour is described in §6. |

## 2. Paper format (`FORMAT PAPER`) [PAPER]

The paper (§4.2) gives sizes and field names only. Field order, integer widths and the position of the padding are **our assumptions**, chosen as the simplest layout that matches the stated sizes.

**StatsPacketHeader — 6 bytes**

| Offset | Size | Type | Field | Source |
|---|---|---|---|---|
| 0 | 4 | uint32 BE | auth placeholder | paper ("32-bit placeholder") |
| 4 | 2 | uint16 BE | record count | paper ("16-bit field") |

**PrefixStatsRecord — 16 bytes**

| Offset | Size | Type | Field | Source |
|---|---|---|---|---|
| 0 | 4 | uint32 BE | IPv4 prefix | paper (field named); width [ASSUMPTION] |
| 4 | 1 | uint8 | prefix length | paper (named); width [ASSUMPTION] |
| 5 | 3 | — | padding, must be 0 | paper ("padding was explicitly considered"); position [ASSUMPTION] |
| 8 | 4 | uint32 BE | to_rate (units/s) | paper (named); width and unit [ASSUMPTION] |
| 12 | 4 | uint32 BE | from_rate (units/s) | paper (named) |

What this format **cannot** do: it has no magic or version, so any 6+16·n bytes decode, including random junk ([VERIFIED], `paper_rejects_malformed_datagrams`). It has no router identity, so two routers cannot be told apart except by source address. With no sequence number, duplicates and losses are undetectable ([VERIFIED], `test_paper_format_cannot_detect_duplicates`). It has no interval boundary, which matters when an export spans several datagrams, and no exact counts.

## 3. V1 format (`FORMAT V1`, default) [EXTENSION]

All integers are big-endian. Both encoders write field by field; neither copies a C++ struct, so compiler padding cannot reach the wire (Phase 1, P2).

**Header — 72 bytes**

| Offset | Size | Type | Field | Meaning / validation |
|---|---|---|---|---|
| 0 | 2 | uint16 | magic | `0x4D54` ("MT"), else `bad_magic` |
| 2 | 1 | uint8 | version | 1, else `bad_version` |
| 3 | 1 | uint8 | header_len | 72, else `bad_header_length` (allows future growth) |
| 4 | 1 | uint8 | record_len | 32, else `bad_record_length` |
| 5 | 1 | uint8 | export_mode | 0 LEAVES, 1 PARTITION, 2 ALL, else `bad_export_mode` |
| 6 | 1 | uint8 | count_unit | 0 PACKETS, 1 BYTES, else `bad_count_unit` |
| 7 | 1 | — | reserved | 0, else `reserved_not_zero` |
| 8 | 4 | uint32 | router_id | configured `ROUTER_ID` (a claim, not authenticated) |
| 12 | 4 | uint32 | boot_id | random per element start (or `BOOT_ID`); a new value means the router restarted |
| 16 | 8 | uint64 | sequence | per (router, boot); +1 per datagram, starts at 0 |
| 24 | 4 | uint32 | interval_id | per (router, boot); +1 per export, starts at 0 |
| 28 | 2 | uint16 | fragment_index | 0-based |
| 30 | 2 | uint16 | fragment_count | ≥ 1 and > index, else `bad_fragment` |
| 32 | 8 | uint64 | timestamp_us | sender wall clock at collection. **Not synchronized across routers.** |
| 40 | 4 | uint32 | interval_ms | measured length of the reported window |
| 44 | 2 | uint16 | record_count | datagram length must equal 72 + 32·count, else `length_mismatch` |
| 46 | 2 | — | reserved | 0 |
| 48 | 4 | uint32 | auth_placeholder | the paper's placeholder. **Not authentication.** |
| 52 | 4 | — | reserved | 0 |
| 56 | 8 | uint64 | uncounted_fwd | units refused by the memory limit in this interval (all fragments repeat it) |
| 64 | 8 | uint64 | uncounted_rev | likewise |

**Record — 32 bytes**

| Offset | Size | Type | Field | Meaning / validation |
|---|---|---|---|---|
| 0 | 4 | uint32 | prefix | IPv4; host bits must be 0, else `host_bits_set` |
| 4 | 1 | uint8 | prefix_len | ≤ 32, else `bad_prefix_length` |
| 5 | 1 | uint8 | flags | bit0 LEAF, bit1 RESIDUAL; rules below, else `bad_flags` |
| 6 | 2 | — | reserved | 0 |
| 8 | 4 | uint32 | fwd_rate | EWMA units/s *from* the prefix (paper **to_rate**), saturating |
| 12 | 4 | uint32 | rev_rate | EWMA units/s *to* the prefix (paper **from_rate**), saturating |
| 16 | 8 | uint64 | fwd_count | exact units in this interval |
| 24 | 8 | uint64 | rev_count | exact units in this interval |

**Flag rules per mode:** LEAVES records must have LEAF set. PARTITION records must have exactly one of LEAF or RESIDUAL, and RESIDUAL cannot be on a /32. ALL records may have LEAF or no flag, but never RESIDUAL.

**Datagram size:** `MAX_PAYLOAD` defaults to 1472 bytes, the largest UDP payload with no IP fragmentation on a 1500-byte MTU. That allows 43 V1 records or 91 paper records per datagram. Larger exports are split into fragments that share an `interval_id`. An interval with no records is still sent as one empty datagram (72 bytes), so a receiver can distinguish "router alive, no traffic" from "report lost" [ASSUMPTION]. Both formats do this.

**Size comparison:** paper = 6 + 16n bytes per datagram; V1 = 72 + 32n. For n = 43, V1 sends 1448 bytes against the paper's 694. V1 roughly doubles telemetry volume in exchange for the fields above. Measured volumes from one run are in §7.

## 4. Direction mapping (`to_rate` / `from_rate`) [VERIFIED]

**Test:** `tests/click/phase3_telemetry.click`, real packets in Click. Host H = 192.168.1.1 sends 100 pps to server 10.9.9.9 on the request path, and the server replies at 30 pps on the reply path. A separate 10.0.0.1 flood and a reply-path-only flow C (172.16.0.1 → .9) give distinguishable rates. Router 1 has the request path on input 0. Router 4 is the control, with the **same packets wired the other way round**.

| Prefix | Router 1 (fwd, rev) | Ground truth (Click `Counter`) | Router 4, swapped (fwd, rev) |
|---|---|---|---|
| 192/8 (host H) | (601, 181) | H = 601 requests, R = 181 replies | (0, 0) |
| 10/8 (flood source + server) | (6020, 0) | A = 6020 | (181, 601) |
| 18/8 (flood target) | (0, 0) | — | (0, 6020) |
| 172/8 (flow C) | (0, 1201) | C = 1201 | (1201, 0) |

**Confirmed mapping:**

- **fwd(P)** = traffic whose *source* is in P, observed on input 0.
- **rev(P)** = traffic whose *destination* is in P, observed on input 1.

The server 10.9.9.9 never appears on router 1, because no packet keyed it.

**What this means in practice:**

- **With requests wired to input 0**, fwd = "sent by P" and rev = "received by P". H's record has fwd ≈ 100 pps and rev ≈ 30 pps (100 and 28 measured).
- **This matches the paper's description** of 10.0.0.1 as "high to_rate, zero from_rate" (§7.3), so **to_rate ≡ fwd** and **from_rate ≡ rev**. The paper-format exporter in the same run sent 192.168.1.1 with to_rate = 100 and from_rate = 28. This is now consistent in C++ (`to_paper_record`) and Python (`RecordV1.to_rate` / `from_rate`).
- **The meaning depends on wiring, not on the protocol.** Swapping the inputs attributes the same packets to the other endpoints (router 4). Experiment configurations must document which traffic direction enters input 0.

## 5. Coverage: is leaf-level export complete? [VERIFIED]

Ground truth comes from Click `Counter` elements in the same process, summed over every interval including the final flush. Results from the reference run:

| Mode | Σ fwd_count | Σ rev_count | vs truth (6621 / 1382) |
|---|---|---|---|
| **PARTITION** | 6621 | 1382 | **exact** |
| LEAVES | 6566 | 1357 | **−55 / −25: incomplete** |
| ALL | 26 325 | 5456 | ×3.98: overlapping |

Across 5 repeated runs, the LEAVES shortfall in fwd was 43–55 packets. PARTITION was exact in every run.

**Why leaves alone are not enough.** A child counter only exists once its level has been expanded (Phase 2, F5). Traffic counted at the parent before then, or refused below it by the memory limit, is in no leaf.

**How `PARTITION` fixes it.** For every expanded counter it emits one **RESIDUAL** record:

- *count* = parent count − Σ child counts. This is never negative, because every packet that updates a child updated its parent in the same window.
- *rate* = max(0, parent rate − Σ child rates). This is approximate: children inherit EWMA state (Phase 2, F4), so the clamp at 0 can trigger.

Together the records cover every counted unit exactly once. Units refused at the root are reported in `uncounted_fwd`/`uncounted_rev`, which completes the account: **Σ counts + uncounted = units offered**. This is verified per window in `partition_counts_equal_offered_units_every_window`, over 12 windows × 2 memory limits, including a run where the root refused counters. It is also verified end to end in C++ → UDP → Python and in Click.

**Remaining limitation: granularity.** A residual record sits at a coarser prefix than the traffic it describes. In the run above, 192.168.0.0/16 alone holds (583, 174) of H's (601, 181); the rest is in the 192.0.0.0/8 residual. Partition counts are exact for the whole tree and for any prefix that contains its residuals. They cannot be split exactly below a residual. Phase 4 must handle this when routers expand differently.

## 6. Receiver behaviour (`aggregator/telemetry_receiver.py`) [VERIFIED]

| Event | Classification | Effect |
|---|---|---|
| Validation failure | `malformed`, counted by error code | Dropped. No stream state is created. |
| New sequence above all earlier ones | `accepted` | Processed |
| New sequence below one already seen | `reordered` | Processed |
| Sequence already seen (window 4096) | `duplicate` | Dropped, never double-counted |
| Sequence ≤ highest − 4096 | `stale` | Dropped (new and duplicate cannot be told apart) |
| New boot_id for a known router_id | new stream + `restart` | Sequence restarts are not misread as duplicates |
| Source address changes within a stream | `source_changes` counter | Recorded only (no authentication) |
| Fragments | Reassembled by (router, boot, interval), in any order | Delivered only when complete |
| Missing fragment | `expire_pending(timeout)` → `intervals_incomplete` | **The partial interval is never delivered** |
| Fragments disagree (timestamp, count, mode) or a new sequence arrives for a finished interval | `intervals_inconsistent` | Not delivered |

`missing_estimate` is the number of sequence numbers between the lowest and highest seen that never arrived. It is an **estimate**: late datagrams may still arrive, and losses after the last received datagram are invisible. By default the receiver refuses to bind to a non-loopback address.

## 7. Test results [VERIFIED]

Command: `scripts/run_all_tests.sh <click-src>` from a clean build. Logs go to `build/test-logs/` and are not committed.

| Suite | Content | Result |
|---|---|---|
| `test_rate_ewma` | Phase 2 | 11/11 |
| `test_multops_tree` | Phase 2, plus 5 coverage tests | 36/36 |
| `test_telemetry` | hand-written golden bytes (V1 and paper), extreme values, saturation, every decode error, flag rules, fragmentation and sequencing, send-failure accounting, tree → exporter → decoder count preservation, 50 000-mutation decoder fuzz, loopback `UdpSender` | 17/17 |
| `diff_upstream_ewma` | Phase 2 | 500 148 comparisons, 0 mismatches |
| `telemetry_vectors_up_to_date` | committed vectors == current C++ output | pass |
| Python (26 tests) | codec vs hand-written bytes; **31 cross-language vectors**: 6 valid V1 decoded to identical fields and re-encoded to identical bytes, 21 malformed V1 rejected with the same error code as C++, 1 valid + 3 malformed paper vectors; 2000 random round trips; 20 000 random mutations raise only `DecodeError`; 14 receiver state-machine tests; 3 C++→UDP→Python integration tests (below) | 26/26, 0 skipped |
| ASan + UBSan | all of the above | pass |
| valgrind | 3 C++ unit suites | 0 errors, 0 leaks |
| Warnings | `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`; Click build of the element | 0 |
| Phase 2 Click equivalence | rerun after the element changes | 11/11, unchanged |
| **Phase 3 Click integration** | 5 monitors, 6 s, loopback | **23/23 checks** in each of 5 runs |

**Integration-test details:**

- *Replay → UDP → Python (PARTITION):* received records equal the tool's CSV interval by interval. Σ counts = 6150 fwd and 600 rev, equal to the trace. Interval IDs are contiguous.
- *Fault-injection relay:* seeded drops (~10%), duplicates (~8%) and adjacent swaps. The receiver's accepted, reordered and duplicate counts equal an independent oracle computed from the delivered order. `missing_estimate` equals the dropped sequence numbers inside the observed range. Every interval that lost a fragment was reported incomplete, and none was delivered partially.
- *Click run:* 52 V1 datagrams, all valid. Received equals sent for each router (13 each). There were no gaps, no local send failures, and all intervals were complete.

**Telemetry volume in the reference Click run** (informational: one 6 s run, 0.5 s interval, 3 small flows; not a general overhead claim, which is Phase 8):

| Exporter | Datagrams | Bytes | ≈ B/s |
|---|---|---|---|
| V1 PARTITION | 13 | 2472 | 412 |
| V1 LEAVES | 13 | 2184 | 364 |
| V1 ALL | 13 | 5608 | 935 |
| PAPER (LEAVES) | 13 | 702 | 117 |

**EWMA reading jitter (measured while investigating a 30 pps flow that read as 28):** my first hypothesis was a downward bias. The measurement **rejected** it. The mean reading at 30 pps is 30.00, but the instantaneous reading moves with the phase of packet arrivals relative to the export:

| True pps | Mean reading | Min–max reading |
|---|---|---|
| 5 | 5.26 (+5.3%) | 3.66–7.45 |
| 10 | 10.16 | 8.42–12.21 |
| 30 | 30.00 | 28.08–31.86 |
| 100 | 99.66 | 98.02–101.20 |
| 1000 | 998.17 | constant |

(Evenly spaced packets, 100 s after warm-up; scratch program, core library.) Ratios computed from single readings of low-rate flows inherit this jitter. Exact counts don't.

## 8. Paper-faithful vs. extension summary

| Aspect | Paper | This repository |
|---|---|---|
| Transport, port | UDP, fire-and-forget, 49555 | Same (`AGGREGATOR ADDR:PORT`, default port 49555) |
| `send_stats_packet` with `htonl`/`htons`/`sendto` | yes | Big-endian field-by-field encoding, `sendto` on a non-blocking socket |
| Header / record | 6 B / 16 B | `FORMAT PAPER` (layout assumptions in §2) **or** V1 72 B / 32 B [EXTENSION] |
| Values exported | to_rate, from_rate | V1: rates **and** exact counts [EXTENSION] |
| What is exported | "every node with active traffic" | `ALL` (paper reading, overlapping), `LEAVES`, `PARTITION` [EXTENSION] |
| Router ID, sequence, interval, boot, version, fragmentation, coverage counters | absent | V1 [EXTENSION] |
| Authentication | 32-bit placeholder | Still a placeholder. **No security in any format.** |
| Element default | — | `FORMAT V1`, `EXPORT ALL` (unchanged from Phase 2 for compatibility); test configs use `PARTITION` |

## 9. Limitations (honest list)

1. **No delivery guarantee.** Loss is detected and estimated, never repaired. A lost fragment loses its whole interval at the receiver.
2. **No authentication or integrity beyond the UDP checksum.** Anyone who can reach the port can forge any router ID, sequence or record. A forged high sequence number can even make genuine datagrams look stale. This is in scope for Phase 6/9 and must not be called "secure".
3. **Clocks are not synchronized.** `timestamp_us` is the sender's clock, and routers' intervals are not aligned with each other. Phase 4 must decide how to combine them.
4. **Residual granularity** (§5): exact totals, but not exact below a residual's prefix.
5. **Rates are approximate.** Residual rates are clamped, rates saturate at 2³²−1, low-rate readings jitter (§7), and inherited-rate inflation remains (Phase 2, F4). Counts are the exact quantity.
6. **The paper format's field order and widths are assumed.** The authors' real layout may differ.
7. **Tested only on loopback** in one container (Ubuntu 24.04, g++ 13, Python 3.13, Click `9197a59`). Not tested on WSL2, across real hosts, under real network loss, or at high export rates (Phase 8).
8. Send failures count only datagrams the *local* socket refused (for example a full buffer). They say nothing about delivery.

## 10. Files

`multops/include/multops/telemetry.hpp`, `multops/src/telemetry.cpp` (codec + exporter) · `multops/include/multops/udp_sender.hpp`, `multops/src/udp_sender.cpp` · `multops/*/multops_tree.*` (PARTITION mode, uncounted counters) · `click/elements/coopipratemonitor.*` (keywords `FORMAT`, `ROUTER_ID`, `BOOT_ID`, `MAX_PAYLOAD`, `EXPORT PARTITION`; handlers `tx_*`, `next_*`) · `aggregator/telemetry_protocol.py`, `aggregator/telemetry_receiver.py` · `tools/telemetry_vectors.cpp`, `tools/multops_replay.cpp` (`--send`) · `tests/cpp/test_telemetry.cpp` · `tests/python/*` · `tests/click/phase3_telemetry.click`, `tests/click/run_phase3_click.py` · `tests/data/telemetry_vectors.jsonl` (generated, not hand-written).

## 11. Questions for Phase 4 [OPEN]

1. **Time alignment.** Routers export on independent timers. Should we align by the receiver's arrival time (simple, adds network jitter), by the sender timestamp (needs clock sync), or by explicitly synchronized interval boundaries (a design change)?
2. **Mixed granularity across routers.** Router A may report 10.0.0.1/32 while router B reports only a 10.0.0.0/8 residual. Should the aggregator compare at a common coarser prefix, or attribute the residual proportionally? The first is exact; the second is an estimate.
3. **Counts or rates for the decision.** Counts are exact and additive. Rates are smoothed and jitter at low rates (§7). My recommendation is to make the aggregation decision on counts per aligned window, and keep rates for comparison with the paper's method.
4. **Missing reports.** If a router's interval is lost or incomplete, should that window be skipped for prefixes that router covers, or decided on partial data? Partial data reproduces the exact asymmetric false positive this research is about.
