# multops-cooperative-ddos

Reproduction and validation of the paper **"Decoupled State Aggregation for Asymmetric DDoS Detection using MULTOPS"** (Smriti, Dham, HariBabu K — BITS Pilani, AINA 2026).

The paper proposes a cooperative extension of MULTOPS. Click Modular Router instances export per-prefix `to_rate` / `from_rate` statistics over a lightweight UDP telemetry protocol. A central Python aggregator fuses them into a global view so that legitimate asymmetric traffic is not misclassified as a flood. Drop commands are then sent back to a Click `PolicyEnforcer` element.

## Status

| Phase | Topic | Status |
|---|---|---|
| 1 | Repository & research audit | Done: [`docs/PHASE1_RESEARCH_AUDIT.md`](docs/PHASE1_RESEARCH_AUDIT.md) |
| 2 | MULTOPS / IPRateMonitor re-implementation and verification | Done (approved): [`docs/PHASE2_MULTOPS_VERIFICATION.md`](docs/PHASE2_MULTOPS_VERIFICATION.md) |
| 3 | UDP telemetry protocol (paper format + versioned V1 extension) | Done (approved): [`docs/PHASE3_TELEMETRY_VALIDATION.md`](docs/PHASE3_TELEMETRY_VALIDATION.md) |
| 4 | Global state aggregation (paper Algorithm 2 vs. proposal) | Done (approved): [`docs/PHASE4_AGGREGATION_ANALYSIS.md`](docs/PHASE4_AGGREGATION_ANALYSIS.md) |
| 5 | Detection engine and validation (no mitigation) | Done, awaiting review: [`docs/PHASE5_DETECTION_VALIDATION.md`](docs/PHASE5_DETECTION_VALIDATION.md) |
| 6–10 | Enforcement, experiments, evaluation | Not started |

The authors' original source code is unavailable. This repository contains a **new implementation** written from the paper and from upstream Click's `IPRateMonitor`, the element the paper says it extended. It is not the authors' code, and results obtained with it are not a reproduction of the paper's results. The paper's reported results (100% detection, 0% false positives) remain unverified claims.

Specification extracted from the paper: [`docs/PAPER_SPECIFICATION.md`](docs/PAPER_SPECIFICATION.md).
Build, test and debugging instructions: [`docs/BUILD_AND_DEBUG.md`](docs/BUILD_AND_DEBUG.md).

## Quick start

```bash
cmake -S . -B build && cmake --build build -j && (cd build && ctest --output-on-failure)
scripts/run_all_tests.sh /path/to/configured/click   # + sanitizers, valgrind, Click element tests
```

## Layout

```
multops/             Click-independent MULTOPS core library (C++14)
click/elements/      Click elements (CoopIPRateMonitor; PolicyEnforcer in Phase 6)
click/configs/       Click scripts for experiments (later phases)
aggregator/          Python telemetry codec + receiver (Phase 3); aggregators (Phase 4); detection (Phase 5)
experiments/         Deterministic simulations and their generated results
tools/               Offline utilities (multops_replay, telemetry_vectors)
tests/cpp/           C++ unit and differential tests
tests/python/        Python unit and integration tests (stdlib unittest)
tests/click/         Click-level tests
tests/data/          Sample trace, generated golden vectors
scripts/             Test runners
experiments/logs/    Raw logs from experiment runs (never edited by hand)
experiments/results/ Derived metrics and plots
docs/                Phase-by-phase research reports
paper/               Paper notes (the PDF is kept local and git-ignored)
```

## Rules for this project

- Do not fabricate results. Every number must trace back to a log in `experiments/logs/`.
- Separate paper claims, verified findings, assumptions and proposals.
- Run traffic generation and mitigation only in an isolated, authorized local testbed.
