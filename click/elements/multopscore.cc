/*
 * multopscore.cc -- compiles the Click-independent multops core library into
 * the Click build. Elements that use it declare ELEMENT_REQUIRES(MultopsCore).
 *
 * install_into_click.sh copies multops/src/multops_tree.cpp next to this file
 * as multops_tree_impl.inc (likewise telemetry.cpp and udp_sender.cpp), and multops/include/multops/ to
 * <click>/include/multops/.
 */
#include <click/config.h>
#include "multops_tree_impl.inc"
#include "telemetry_impl.inc"
#include "udp_sender_impl.inc"
CLICK_DECLS
CLICK_ENDDECLS
ELEMENT_PROVIDES(MultopsCore)
