#!/usr/bin/env bash
# Install the cooperative MULTOPS elements into a Click source tree and rebuild
# the user-level driver.
#
#   click/install_into_click.sh /path/to/click            # copy + build
#   click/install_into_click.sh /path/to/click --no-build # copy only
#
# The Click tree must have been configured with --enable-local, e.g.
#   ./configure --disable-linuxmodule --enable-userlevel --enable-local
set -euo pipefail

CLICK_SRC="${1:?usage: $0 /path/to/click [--no-build]}"
BUILD=1
[[ "${2:-}" == "--no-build" ]] && BUILD=0

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$CLICK_SRC/elements/local"

if [[ ! -f "$CLICK_SRC/userlevel/Makefile" ]]; then
    echo "error: $CLICK_SRC is not a configured Click tree (userlevel/Makefile missing)" >&2
    exit 1
fi
if ! grep -q " local " "$CLICK_SRC/userlevel/Makefile"; then
    echo "error: Click was not configured with --enable-local" >&2
    exit 1
fi

# Core headers go under Click's include/ (already on the compiler's -I path)
# so that their own "multops/..." includes resolve.
mkdir -p "$CLICK_SRC/include/multops"
cp "$REPO"/multops/include/multops/*.hpp "$CLICK_SRC/include/multops/"
cp "$REPO"/click/elements/coopipratemonitor.hh "$REPO"/click/elements/coopipratemonitor.cc \
   "$REPO"/click/elements/multopscore.cc "$DEST/"
cp "$REPO"/multops/src/multops_tree.cpp "$DEST/multops_tree_impl.inc"
cp "$REPO"/multops/src/telemetry.cpp "$DEST/telemetry_impl.inc"
cp "$REPO"/multops/src/udp_sender.cpp "$DEST/udp_sender_impl.inc"
echo "installed into $DEST"

if [[ $BUILD -eq 1 ]]; then
    # Regenerate the element list so the new elements are linked in.
    rm -f "$CLICK_SRC/userlevel/elements.conf"
    make -C "$CLICK_SRC/userlevel" -j"$(nproc)"
    echo "built $CLICK_SRC/userlevel/click"
fi
