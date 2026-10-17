/*
 * multopscore.cc -- compiles the Click-independent multops core library into
 * the Click build. Elements that use it declare ELEMENT_REQUIRES(MultopsCore).
 *
 * install_into_click.sh copies multops/src/multops_tree.cpp next to this file
 * as multops_tree_impl.inc, and multops/include/multops/ to
 * <click>/include/multops/.
 */
#include <click/config.h>
#include "multops_tree_impl.inc"
CLICK_DECLS
CLICK_ENDDECLS
ELEMENT_PROVIDES(MultopsCore)
