# multops-cooperative-ddos

Reproduction and validation of the paper **"Decoupled State Aggregation for Asymmetric DDoS Detection using MULTOPS"** (Smriti, Dham, HariBabu K — BITS Pilani, AINA 2026).

The paper proposes a cooperative extension of MULTOPS. Click Modular Router instances export per-prefix `to_rate` / `from_rate` statistics over a lightweight UDP telemetry protocol. A central Python aggregator fuses them into a global view so that legitimate asymmetric traffic is not misclassified as a flood. Drop commands are then sent back to a Click `PolicyEnforcer` element.

## Status

| Phase | Topic | Status |
|---|---|---|
| 1 | Repository & research audit | Done: [`docs/PHASE1_RESEARCH_AUDIT.md`](docs/PHASE1_RESEARCH_AUDIT.md) |
| 2 | MULTOPS / IPRateMonitor re-implementation and verification | Done, awaiting review: [`docs/PHASE2_MULTOPS_VERIFICATION.md`](docs/PHASE2_MULTOPS_VERIFICATION.md) |
| 3–10 | Telemetry, aggregation, detection, enforcement, experiments, evaluation | Not started |

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
aggregator/          Python aggregator (Phase 4)
tools/               Offline utilities (multops_replay)
tests/cpp/           C++ unit and differential tests
tests/click/         Click-level tests
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
