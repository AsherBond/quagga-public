/*
 * MPLS Label Information Base for zebra daemon.
 *
 * Copyright (C) 2004 James R. Leu <jleu@mindspring.com>
 * Copyright (C) 2011 Renato Westphal <rwestphal@inf.ufrgs.br>
 *
 * This file is part of Quagga routing suite.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_MPLS_LIB_H
#define _ZEBRA_MPLS_LIB_H

#include "prefix.h"
#include "if.h"

#define NO_LABEL UINT_MAX
#define MPLS_IPV4_EXPLICIT_NULL 0
#define MPLS_IMPLICIT_NULL      3

struct route_lsp
{
  struct interface *ifp;
  struct in_addr nexthop;
  u_int32_t remote_label;
  u_int32_t nhlfe_index;
};

struct label_bindings
{
  u_int32_t static_in_label;
  u_int32_t ldp_in_label;
  u_int32_t selected_in_label;
  struct list *static_lsps;
  struct route_lsp *ldp_lsp;
  struct route_lsp *selected_lsp;
};

struct mpls_crossconnect
{
  u_int32_t in_label;
  struct route_lsp *lsp;
};

/* mpls_lib.c */
extern int mpls_enabled;
extern struct list *mpls_crossconnect_list;
extern void mpls_init (void);
extern struct route_node *route_node_get_mpls (struct prefix *);
extern int zebra_route_node_active (struct route_node *rn);
extern void mpls_prefix_set_static_input_label (struct prefix *, u_int32_t label);
extern void mpls_prefix_remove_static_input_label (struct prefix *, u_int32_t label);
extern void mpls_prefix_set_ldp_input_label (struct prefix *p, u_int32_t label);
extern void mpls_prefix_add_static_lsp (struct prefix *, struct in_addr, u_int32_t);
extern void mpls_prefix_remove_static_lsp (struct prefix *, struct in_addr *);
extern void mpls_prefix_set_ldp_lsp (struct prefix *, struct in_addr, u_int32_t);
extern void mpls_prefix_remove_ldp_lsp (struct prefix *, struct in_addr, u_int32_t);
extern int mpls_static_crossconnect_add (uint32_t, struct interface *, struct in_addr *, uint32_t);
extern int mpls_static_crossconnect_remove (uint32_t);
extern void mpls_set_bgp_vrf_in_label (const char *, uint32_t, u_char);
extern void mpls_route_install_hook (struct route_node *);
extern void mpls_route_uninstall_hook (struct route_node *);
extern void mpls_close (void);

/* mpls_vty.c */
extern void mpls_vty_init (void);

/* mpls_netlink.c */
extern int mpls_kernel_set_interface_labelspace (struct interface *, int);
extern int mpls_kernel_ilm_register (u_int32_t);
extern int mpls_kernel_ilm_unregister (u_int32_t);
extern int mpls_kernel_nhlfe_register (struct route_lsp *);
extern int mpls_kernel_nhlfe_unregister (struct route_lsp *);
extern int mpls_kernel_xc_register (u_int32_t, struct route_lsp *);
extern int mpls_kernel_xc_unregister (u_int32_t, struct route_lsp *);

extern void mpls_kernel_init (void);
extern void mpls_kernel_exit (void);

#endif /* _ZEBRA_MPLS_VTY_H */
