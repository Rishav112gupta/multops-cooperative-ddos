#!/usr/bin/env bash
# Build and run every test (Phases 2-5).
#
#   scripts/run_all_tests.sh                    # unit tests only
#   scripts/run_all_tests.sh /path/to/click     # + upstream-EWMA diff test + Click tests
#
# Writes logs to build/test-logs/.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLICK_SRC="${1:-}"
LOGS="$REPO/build/test-logs"
mkdir -p "$LOGS"
cd "$REPO"

echo "== Release build + unit tests"
cmake -S . -B build ${CLICK_SRC:+-DCLICK_SRC=$CLICK_SRC} > /dev/null
cmake --build build -j"$(nproc)" 2>&1 | tee "$LOGS/build.log" | grep -E "warning|error" || true
(cd build && ctest --output-on-failure) 2>&1 | tee "$LOGS/ctest.log"
./build/test_rate_ewma > "$LOGS/test_rate_ewma.log"
./build/test_multops_tree > "$LOGS/test_multops_tree.log"
./build/test_telemetry > "$LOGS/test_telemetry.log"
MULTOPS_BUILD_DIR="$REPO/build" python3 -m unittest discover -s tests/python -t . -v > "$LOGS/python.log" 2>&1

echo "== ASan + UBSan build + unit tests"
cmake -S . -B build-asan -DMULTOPS_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug ${CLICK_SRC:+-DCLICK_SRC=$CLICK_SRC} > /dev/null
cmake --build build-asan -j"$(nproc)" > /dev/null
(cd build-asan && ctest --output-on-failure) 2>&1 | tee "$LOGS/ctest-asan.log" | tail -3

if command -v valgrind > /dev/null; then
    echo "== valgrind (memcheck)"
    valgrind --leak-check=full --error-exitcode=9 -q ./build/test_multops_tree > /dev/null
    valgrind --leak-check=full --error-exitcode=9 -q ./build/test_rate_ewma > /dev/null
    valgrind --leak-check=full --error-exitcode=9 -q ./build/test_telemetry > /dev/null
    echo "valgrind: no errors, no leaks" | tee "$LOGS/valgrind.log"
fi

if [[ -n "$CLICK_SRC" ]]; then
    echo "== Click element: install, build, equivalence test"
    click/install_into_click.sh "$CLICK_SRC" > "$LOGS/click-install.log" 2>&1
    tests/click/run_click_tests.sh "$CLICK_SRC/userlevel/click" "$LOGS"
    echo "== Click telemetry integration (Phase 3, loopback only)"
    python3 tests/click/run_phase3_click.py "$CLICK_SRC/userlevel/click" "$LOGS"
    echo "== Click two-router aggregation (Phase 4, loopback only)"
    python3 tests/click/run_phase4_click.py "$CLICK_SRC/userlevel/click" "$LOGS"
    echo "== Click controlled detection runs (Phase 5, loopback only, no mitigation)"
    python3 tests/click/run_phase5_click.py "$CLICK_SRC/userlevel/click" "$LOGS"
fi
echo "== all tests passed"
