#include <zebra.h>

#include "prefix.h"
#include "interface.h"

#include "zebra/mpls_lib.h"

int mpls_kernel_set_interface_labelspace (struct interface *ifp, int labelspace) { return 0; }
int mpls_kernel_ilm_register (u_int32_t label) { return 0; }
int mpls_kernel_ilm_unregister (u_int32_t label) { return 0; }
int mpls_kernel_nhlfe_register (struct route_lsp *lsp) { return 0; }
int mpls_kernel_nhlfe_unregister (struct route_lsp *lsp) { return 0; }
int mpls_kernel_xc_register (u_int32_t ilm_label, struct route_lsp *lsp) { return 0; }
int mpls_kernel_xc_unregister (u_int32_t ilm_label, struct route_lsp *lsp) { return 0; }
void mpls_kernel_init (void) { return; }
void mpls_kernel_exit (void) { return; }
