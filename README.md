# multops-cooperative-ddos

Reproduction and validation of the paper **"Decoupled State Aggregation for Asymmetric DDoS Detection using MULTOPS"** (Smriti, Dham, HariBabu K — BITS Pilani, AINA 2026).

The paper proposes a cooperative extension of MULTOPS. Click Modular Router instances export per-prefix `to_rate` / `from_rate` statistics over a lightweight UDP telemetry protocol. A central Python aggregator fuses them into a global view so that legitimate asymmetric traffic is not misclassified as a flood. Drop commands are then sent back to a Click `PolicyEnforcer` element.

## Status

| Phase | Topic | Status |
|---|---|---|
| 1 | Repository & research audit | Done: [`docs/PHASE1_RESEARCH_AUDIT.md`](docs/PHASE1_RESEARCH_AUDIT.md) |
| 2 | MULTOPS implementation verification | Blocked: original source code not yet in repo |
| 3–10 | Telemetry, aggregation, detection, enforcement, experiments, evaluation | Not started |

**No implementation code is present yet.** The paper's reported results (100% detection, 0% false positives) are unverified claims until the experiments in this repository reproduce them.

## Layout

```
click/elements/      C++ Click elements (modified IPRateMonitor, PolicyEnforcer)
click/configs/       Click scripts (test_attack.click, test-full.click, ...)
aggregator/          Python aggregator (aggregator.py)
tests/               Automated unit / protocol tests
experiments/logs/    Raw logs from experiment runs (never edited by hand)
experiments/results/ Derived metrics and plots
docs/                Phase-by-phase research reports
paper/               Paper PDF and notes
```

## Rules for this project

- Do not fabricate results. Every number must trace back to a log in `experiments/logs/`.
- Separate paper claims, verified findings, assumptions and proposals.
- Run traffic generation and mitigation only in an isolated, authorized local testbed.
