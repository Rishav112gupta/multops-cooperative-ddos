#!/usr/bin/env bash
# Run the Click-level Phase 2 tests.  Usage: tests/click/run_click_tests.sh /path/to/click/userlevel/click [logdir]
set -euo pipefail
CLICK="${1:?usage: $0 /path/to/click-binary [logdir]}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGDIR="${2:-$HERE/../../build/click-logs}"
mkdir -p "$LOGDIR"
OUT="$LOGDIR/phase2_equivalence.out"
timeout 60 "$CLICK" "$HERE/phase2_equivalence.click" > "$OUT" 2>&1
python3 "$HERE/check_equivalence.py" "$OUT" | tee "$LOGDIR/phase2_equivalence.check"
