# Build, Test and Debug Guide

Verified on: Ubuntu 24.04 (container), g++ 13.3, CMake 3.28, Python 3, valgrind,
Click upstream commit `9197a594b1c3` (2022-07-04, github.com/kohler/click).
**Not yet verified on WSL2**, although nothing here is WSL-specific.

## 1. Core library and unit tests (no Click needed)

```bash
sudo apt install build-essential cmake python3 valgrind   # once
cmake -S . -B build
cmake --build build -j
(cd build && ctest --output-on-failure)
```

Binaries in `build/`:

| Binary | Purpose |
|---|---|
| `test_rate_ewma` | EWMA unit tests (11) |
| `test_multops_tree` | MULTOPS tree unit tests (36) |
| `test_telemetry` | Telemetry codec, exporter, UDP sender (17) |
| `multops_replay` | Offline trace replay tool, optional UDP export (see §4) |
| `telemetry_vectors` | Emits cross-language golden vectors |

CTest also runs the Python tests (`python3 -m unittest discover -s tests/python -t .`, stdlib only) with `MULTOPS_BUILD_DIR` set, so the integration tests can launch the C++ tools.

Run a subset of tests by name: `./build/test_multops_tree fold`

## 2. With Click (element + differential tests)

```bash
git clone https://github.com/kohler/click.git ~/click
cd ~/click
./configure --disable-linuxmodule --enable-userlevel --enable-local --disable-dpdk
make -j"$(nproc)"                       # ~5-10 min

cd /path/to/multops-cooperative-ddos
scripts/run_all_tests.sh ~/click        # everything below in one go
```

`scripts/run_all_tests.sh <click>` does the following:

1. Builds the release configuration and runs the unit tests. It also runs `diff_upstream_ewma`, which compares our EWMA with Click's `include/click/ewma.hh` bit for bit, and the replay smoke test.
2. Builds with ASan + UBSan and reruns all of it.
3. Runs valgrind memcheck on the unit tests.
4. Installs the element into Click (`click/install_into_click.sh`), rebuilds `userlevel/click`, and runs `tests/click/phase2_equivalence.click`. That script checks the new element against upstream `IPRateMonitor` on identical packets.
5. Runs `tests/click/run_phase3_click.py`. It exports telemetry from 5 monitors over loopback to a Python receiver and checks validity, sequencing, coverage per export mode and the direction mapping.

Logs go to `build/test-logs/`.

### Installing the element only

```bash
click/install_into_click.sh ~/click          # copies files, rebuilds userlevel/click
~/click/userlevel/click my-config.click
```

The script copies:

- `click/elements/{coopipratemonitor.hh,coopipratemonitor.cc,multopscore.cc}` → `<click>/elements/local/`
- `multops/src/{multops_tree,telemetry,udp_sender}.cpp` → `<click>/elements/local/*_impl.inc`
- `multops/include/multops/*.hpp` → `<click>/include/multops/`

Re-run it after every change to `multops/` or `click/elements/`.

## 3. Using the element

```
mon :: CoopIPRateMonitor(PACKETS, 1, 1000, 600, INTERVAL 1, EXPORT PARTITION,
                         AGGREGATOR 127.0.0.1:49555, ROUTER_ID 1);
outbound -> [0]mon[0] -> ...;   // accounted to SOURCE address (forward)
inbound  -> [1]mon[1] -> ...;   // accounted to DESTINATION address (reverse)
```

Handlers can be read through a `ControlSocket(TCP, 7777)` (`telnet localhost 7777`, then `READ mon.look`) or with `DriverManager(print mon.snapshot)`:

| Handler | Shows |
|---|---|
| `look` | upstream-format rate table |
| `snapshot` | last export (CSV) |
| `lookup ADDR` | per-level path for one address |
| `stats` | tables, counters, memory, fold runs, invariant check |
| `tx_datagrams`, `tx_bytes`, `tx_failures`, `next_sequence`, `next_interval_id` | telemetry sender counters |
| `reset`, `export`, `memmax` | write handlers |

Receive telemetry (loopback only unless `--allow-non-loopback`):

```bash
python3 -m aggregator.telemetry_receiver --listen 127.0.0.1:49555 --duration 10 --out rx.jsonl
```

## 4. Offline replay tool

```bash
./build/multops_replay --thresh 100 --interval-ms 1000 tests/data/sample_trace.csv
./build/multops_replay --thresh 100 --mode partition --send 127.0.0.1:49555 --router-id 1 tests/data/sample_trace.csv
```

The input is CSV lines of `time_ms,F|R,addr[,value]`. The output has one CSV block per interval, and a summary goes to stderr. It is deterministic, which makes it the quickest way to debug tree behaviour without Click.

## 5. Phase 4 aggregation analysis

```bash
python3 -m experiments.phase4.run_phase4 --build build --out experiments/results/phase4
```

The run is deterministic (seeded, simulated clocks) and takes a few seconds. It writes `phase4_results.json` and `phase4_results.md`. A test checks that the committed JSON reproduces exactly.

## 6. Debugging tips

| Problem | What to do |
|---|---|
| Crash or memory error | `cmake -S . -B build-asan -DMULTOPS_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug` and rerun. ASan reports the exact line. |
| Leak suspicion | `valgrind --leak-check=full ./build/test_multops_tree` |
| Step through a test | `gdb --args ./build/test_multops_tree tree_fold` (the argument filters tests) |
| Tree looks inconsistent | `MultopsTree::check_invariants()` returns a description of any broken age-list link, parent link or memory-accounting mismatch. The Click `stats` handler reports it as `invariants ok/BROKEN`. |
| Element not found by Click | Click must be configured with `--enable-local`. Re-run `install_into_click.sh`, which deletes `userlevel/elements.conf` to force re-discovery. |
| `'Click' has not been declared` | User-level Click uses no namespace. Use `CLICK_USING_DECLS` instead of `Click::`. |
| Golden vectors test fails after a codec change | Regenerate with `./build/telemetry_vectors > tests/data/telemetry_vectors.jsonl`, review the diff, and make sure the Python codec still agrees |
| Integration tests skipped | Run them through CTest or set `MULTOPS_BUILD_DIR=$PWD/build` |
| Rates look ~1/RATIO too small | Expected: rates are not rescaled by RATIO (upstream behaviour, see Phase 2 report F10). |
