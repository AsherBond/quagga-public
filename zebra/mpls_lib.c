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

#include <zebra.h>

#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "if.h"

#include "zebra/interface.h"
#include "zebra/mpls_lib.h"

int mpls_enabled;
struct list *mpls_crossconnect_list;
extern struct zebra_t zebrad;

struct route_node *
route_node_get_mpls (struct prefix *p)
{
  struct route_table *table;
  struct route_node *rn;
  struct label_bindings *lb;

  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (! table)
    return NULL;

  rn = route_node_get (table, p);
  if (! rn->mpls)
    {
      lb = XCALLOC (MTYPE_MPLS_BINDINGS, sizeof (struct label_bindings));
      lb->static_in_label = NO_LABEL;
      lb->ldp_in_label = NO_LABEL;
      lb->selected_in_label = NO_LABEL;
      lb->static_lsps = list_new ();
      rn->mpls = lb;
    }

  return rn;
}

/* Check if there's an active route for the given IP prefix.  */
int
zebra_route_node_active (struct route_node *rn)
{
  struct rib *rib;

  RNODE_FOREACH_RIB (rn, rib)
    if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
        && rib->distance != DISTANCE_INFINITY)
      return 1;

  return 0;
}

/* Get the IPv4 nexthop address of the active route
   of a given IP prefix.  */
static struct in_addr *
get_prefix_nexthop (struct route_node *rn)
{
  struct rib *rib;
  struct rib *active;
  struct nexthop *nexthop;

  active = 0;

  RNODE_FOREACH_RIB (rn, rib)
    if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
        && rib->distance != DISTANCE_INFINITY)
      active = rib;

  if (! active)
    return NULL;

  for (nexthop = active->nexthop; nexthop; nexthop = nexthop->next)
    {
      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE)
          && (CHECK_FLAG (nexthop->flags, NEXTHOP_TYPE_IPV4)
              || CHECK_FLAG (nexthop->flags, NEXTHOP_TYPE_IPV4_IFINDEX)
              || CHECK_FLAG (nexthop->flags, NEXTHOP_TYPE_IPV4_IFNAME)))
        return &nexthop->gate.ipv4;
    }

  return NULL;
}

/* Check if the LSP to be removed is active. If so, uninstall it. */
static void
mpls_prefix_remove_lsp (struct route_node *rn, struct route_lsp *lsp)
{
  struct label_bindings *lb;

  lb = rn->mpls;
  if (lb->selected_lsp != lsp)
    return;

  lb->selected_lsp = NULL;

  if (zebra_route_node_active (rn))
    {
      /* Remove XC.  */
      if (lb->selected_in_label != NO_LABEL)
        mpls_kernel_xc_unregister (lb->selected_in_label, lsp);

      /* Remove NHLFE.  */
      mpls_kernel_nhlfe_unregister (lsp);
    }
}

/* Select one MPLS LSP for a given IP prefix.  */
static void
mpls_prefix_select_lsp (struct route_node *rn)
{
  struct route_lsp *selected;
  struct route_lsp *lsp;
  struct label_bindings *lb;
  struct listnode *node;
  struct in_addr *nexthop;

  lb = rn->mpls;
  selected = NULL;

  nexthop = get_prefix_nexthop (rn);
  if (! nexthop)
    {
      char buf[128];
      prefix2str (&rn->p, buf, sizeof (buf));
      zlog_warn ("Could not determine the next hop of route %s", buf);
      return;
    }

  /* The LDP assigned LSP takes precedence over static LSPs.  */
  if (lb->ldp_lsp
      && lb->ldp_lsp->nexthop.s_addr == nexthop->s_addr)
    {
      selected = lb->ldp_lsp;
      goto install_lsp;
    }

  /* Select the static LSP whose nexthop address match the
     active route nexthop.  */
  for (ALL_LIST_ELEMENTS_RO (lb->static_lsps, node, lsp))
    if (lsp->nexthop.s_addr == nexthop->s_addr)
      {
        selected = lsp;
        break;
      }

install_lsp:
  /* If the selected LSP didn't changed, then we are done.  */
  if (lb->selected_lsp && lb->selected_lsp == selected)
    return;

  /* Uninstall the previous selected LSP.  */
  if (lb->selected_lsp)
    mpls_prefix_remove_lsp (rn, lb->selected_lsp);

  /* Update the selected LSP pointer.  */
  lb->selected_lsp = selected;

  /* Is no LSP match the active's route nexthop, then don't
     install any LSP at all.  */
  if (! lb->selected_lsp)
    return;

  /* Install a NHLFE entry.  */
  if (mpls_kernel_nhlfe_register (lb->selected_lsp) < 0)
    return;

  /* Install a XC entry, if necessary.  */
  if (lb->selected_in_label != NO_LABEL)
    mpls_kernel_xc_register (lb->selected_in_label, lb->selected_lsp);

  /* Register FTN.  */
  rib_queue_add (&zebrad, rn);
}

/* Set the static input label for a given IP prefix.  */
void
mpls_prefix_set_static_input_label (struct prefix *p, u_int32_t label)
{
  struct route_node *rn;
  struct label_bindings *lb;
  struct listnode *node;
  struct zserv *client;

  rn = route_node_get_mpls (p);
  lb = rn->mpls;

  /* If the label didn't changed, then we are done.  */
  if (lb->static_in_label == label)
    return;

  /* If necessary, uninstall previous ILM/XC entries.  */
  if (lb->selected_in_label != NO_LABEL && zebra_route_node_active (rn))
    {
      if (lb->selected_lsp)
        mpls_kernel_xc_unregister (lb->selected_in_label,
                                   lb->selected_lsp);

      mpls_kernel_ilm_unregister (lb->selected_in_label);
    }

  /* The static assigned input label takes precedence against
     the LDP assigned input label.  */
  lb->static_in_label = label;
  lb->selected_in_label = label;

  if (! zebra_route_node_active (rn))
    return;

  /* Install ILM/XC.  */
  mpls_kernel_ilm_register (lb->selected_in_label);
  if (lb->selected_lsp)
    mpls_kernel_xc_register (lb->selected_in_label, lb->selected_lsp);

  /* LDP should advertise the static local binding.  */
  for (ALL_LIST_ELEMENTS_RO (zebrad.client_list, node, client))
    if (client->redist_mpls)
      zsend_prefix_in_label (client, rn);

  return;
}

/* Unset the static input label for a given IP prefix.  */
void
mpls_prefix_remove_static_input_label (struct prefix *p, u_int32_t label)
{
  struct route_node *rn;
  struct label_bindings *lb;
  struct listnode *node;
  struct zserv *client;

  rn = route_node_get_mpls (p);
  lb = rn->mpls;

  if (lb->static_in_label == NO_LABEL)
    return;

  if (label != NO_LABEL && lb->static_in_label != label)
    return;

  if (zebra_route_node_active (rn))
    {
      if (lb->selected_lsp)
        mpls_kernel_xc_unregister (lb->selected_in_label,
                                   lb->selected_lsp);

      mpls_kernel_ilm_unregister (lb->selected_in_label);
    }

  lb->static_in_label = NO_LABEL;
  if (lb->ldp_in_label == NO_LABEL)
    lb->selected_in_label = NO_LABEL;
  else if (zebra_route_node_active (rn))
    {
      lb->selected_in_label = lb->ldp_in_label;
      mpls_kernel_ilm_register (lb->selected_in_label);
      if (lb->selected_lsp)
        mpls_kernel_xc_register (lb->selected_in_label,
                                 lb->selected_lsp);
    }

  if (! zebra_route_node_active (rn))
    return;

  for (ALL_LIST_ELEMENTS_RO (zebrad.client_list, node, client))
    if (client->redist_mpls)
      zsend_prefix_in_label (client, rn);

  return;
}

/* Set the LDP input label for a given IP prefix.  */
void
mpls_prefix_set_ldp_input_label (struct prefix *p, u_int32_t label)
{
  struct route_node *rn;
  struct label_bindings *lb;

  rn = route_node_get_mpls (p);
  lb = rn->mpls;

  lb->ldp_in_label = label;

  /* If there is a static assigned input label, then the LDP
     input label is not used.  */
  if (lb->static_in_label != NO_LABEL)
    return;

  if (label != NO_LABEL && label == lb->selected_in_label)
    return;

  if (zebra_route_node_active (rn))
    {
      if (lb->selected_in_label != NO_LABEL)
        {
          if (lb->selected_lsp)
            mpls_kernel_xc_unregister (lb->selected_in_label,
                                       lb->selected_lsp);

          mpls_kernel_ilm_unregister (lb->selected_in_label);
          lb->selected_in_label = NO_LABEL;
        }

      if (label != NO_LABEL)
        {
          lb->selected_in_label = lb->ldp_in_label;
          mpls_kernel_ilm_register (lb->selected_in_label);
          if (lb->selected_lsp)
            mpls_kernel_xc_register (lb->selected_in_label, lb->selected_lsp);
        }
    }
}

/* Add a static MPLS LSP for a given IP prefix.  */
void
mpls_prefix_add_static_lsp (struct prefix *p, struct in_addr nexthop,
                            u_int32_t label)
{
  struct route_node *rn;
  struct label_bindings *lb;
  struct route_lsp *lsp;
  struct listnode *node, *nnode;

  rn = route_node_get_mpls (p);
  lb = rn->mpls;

  /* For each prefix/nexhop combination, there must be only
     one MPLS output label.  */
  for (ALL_LIST_ELEMENTS (lb->static_lsps, node, nnode, lsp))
    if (lsp->nexthop.s_addr == nexthop.s_addr)
      {
        /* If this LSP already exists, then return.  */
        if (lsp->remote_label == label)
          return;

        /* Remove previous LSP.  */
        mpls_prefix_remove_static_lsp (p, &lsp->nexthop);
      }

  /* Create MPLS LSP.  */
  lsp = XCALLOC (MTYPE_MPLS_LSP, sizeof (struct route_lsp));
  lsp->nexthop = nexthop;
  lsp->remote_label = label;
  listnode_add (lb->static_lsps, lsp);

  if (zebra_route_node_active (rn))
    mpls_prefix_select_lsp (rn);
}

/* Remove a static MPLS LSP for a given IP prefix.  */
void
mpls_prefix_remove_static_lsp (struct prefix *p, struct in_addr *nexthop)
{
  struct route_node *rn;
  struct label_bindings *lb;
  struct route_lsp *lsp;
  struct route_lsp *found;
  struct listnode *node, *nnode;

  rn = route_node_get_mpls (p);
  lb = rn->mpls;
  found = NULL;

  for (ALL_LIST_ELEMENTS (lb->static_lsps, node, nnode, lsp))
    if (lsp->nexthop.s_addr == nexthop->s_addr)
      {
        found = lsp;
        break;
      }

  if (! found)
    return;

  mpls_prefix_remove_lsp (rn, lsp);
  listnode_delete (lb->static_lsps, lsp);
  XFREE (MTYPE_MPLS_LSP, lsp);

  if (zebra_route_node_active (rn))
    mpls_prefix_select_lsp (rn);
}

/* Set the LDP assigned LSP for a given IP prefix.  */
void
mpls_prefix_set_ldp_lsp (struct prefix *p, struct in_addr nexthop,
                         u_int32_t label)
{
  struct route_node *rn;
  struct label_bindings *lb;
  struct route_lsp *lsp;

  rn = route_node_get_mpls (p);
  lb = rn->mpls;

  if (lb->ldp_lsp
      && lb->ldp_lsp->nexthop.s_addr == nexthop.s_addr
      && lb->ldp_lsp->remote_label == label)
    return;

  if (lb->ldp_lsp)
    {
      mpls_prefix_remove_lsp (rn, lb->ldp_lsp);
      XFREE (MTYPE_MPLS_LSP, lb->ldp_lsp);
    }

  /* Create MPLS LSP.  */
  lsp = XCALLOC (MTYPE_MPLS_LSP, sizeof (struct route_lsp));
  lsp->nexthop = nexthop;
  lsp->remote_label = label;
  lb->ldp_lsp = lsp;

  if (zebra_route_node_active (rn))
    mpls_prefix_select_lsp (rn);
}

/* Remove the LDP assigned LSP for a given IP prefix.  */
void
mpls_prefix_remove_ldp_lsp (struct prefix *p, struct in_addr nexthop,
                            u_int32_t label)
{
  struct route_node *rn;
  struct label_bindings *lb;

  rn = route_node_get_mpls (p);
  lb = rn->mpls;

  if (! lb->ldp_lsp)
    return;

  if (lb->ldp_lsp->nexthop.s_addr != nexthop.s_addr
      || lb->ldp_lsp->remote_label != label)
    return;

  mpls_prefix_remove_lsp (rn, lb->ldp_lsp);
  XFREE (MTYPE_MPLS_LSP, lb->ldp_lsp);

  if (zebra_route_node_active (rn))
    mpls_prefix_select_lsp (rn);
}

/* Add MPLS crossconnect.  */
int
mpls_static_crossconnect_add (uint32_t in_label, struct interface *ifp,
                              struct in_addr *nexthop, uint32_t out_label)
{
  struct mpls_crossconnect *mc;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (mpls_crossconnect_list, node, nnode, mc))
    if (mc->in_label == in_label)
      {
        if (mc->lsp->ifp == ifp
            && mc->lsp->nexthop.s_addr == nexthop->s_addr
            && mc->lsp->remote_label == out_label)
          return 0;

        mpls_static_crossconnect_remove (in_label);
      }

  mc = XCALLOC (MTYPE_MPLS_CROSSCONNECT, sizeof (struct mpls_crossconnect));
  mc->in_label = in_label;
  mc->lsp = XCALLOC (MTYPE_MPLS_LSP, sizeof (struct route_lsp));
  mc->lsp->ifp = ifp;
  mc->lsp->nexthop.s_addr = nexthop->s_addr;
  mc->lsp->remote_label = out_label;
  listnode_add (mpls_crossconnect_list, mc);

  /* Install MPLS crossconnect in the kernel  */
  if (mpls_kernel_nhlfe_register (mc->lsp) < 0)
    return -1;

  if (mpls_kernel_ilm_register (mc->in_label) < 0)
    goto cleanup_nhlfe;

  if (mpls_kernel_xc_register (mc->in_label, mc->lsp) < 0)
    goto cleanup_ilm;

  return 0;

cleanup_ilm:
  mpls_kernel_ilm_unregister (mc->in_label);
cleanup_nhlfe:
  mpls_kernel_nhlfe_unregister (mc->lsp);

  return -1;
}

/* Remove MPLS crossconnect.  */
int
mpls_static_crossconnect_remove (uint32_t in_label)
{
  struct mpls_crossconnect *mc, *mc_tmp;
  struct listnode *node;

  mc = NULL;
  for (ALL_LIST_ELEMENTS_RO (mpls_crossconnect_list, node, mc_tmp))
    if (mc_tmp->in_label == in_label)
      {
        mc = mc_tmp;
        break;
      }

  /* MPLS crossconnect not found.  */
  if (! mc)
    return -1;

  /* Uninstall MPLS crossconnect from the kernel.  */
  mpls_kernel_xc_unregister (mc->in_label, mc->lsp);
  mpls_kernel_ilm_unregister (mc->in_label);
  mpls_kernel_nhlfe_unregister (mc->lsp);

  listnode_delete (mpls_crossconnect_list, mc);
  XFREE (MTYPE_MPLS_LSP, mc->lsp);
  XFREE (MTYPE_MPLS_CROSSCONNECT, mc);

  return 0;
}

/* Hook function called after a route is installed.  */
void
mpls_route_install_hook (struct route_node *rn)
{
  struct label_bindings *lb;

  lb = rn->mpls;
  if (! lb)
    return;

  /* Do we have an input label set? If so, install an ILM entry. */
  if (lb->selected_in_label != NO_LABEL)
    mpls_kernel_ilm_register (lb->selected_in_label);

  /* Do we have an output label set? If so, install a NHLFE entry
     and a FTN. If we also we have an input label, then also
     install a XC entry.*/
  mpls_prefix_select_lsp (rn);
}

/* Hook function called after a route is uninstalled.  */
void
mpls_route_uninstall_hook (struct route_node *rn)
{
  struct label_bindings *lb;

  lb = rn->mpls;
  if (! lb)
    return;

  if (lb->selected_lsp)
    mpls_prefix_remove_lsp (rn, lb->selected_lsp);

  if (lb->selected_in_label != NO_LABEL)
    mpls_kernel_ilm_unregister (lb->selected_in_label);
}

/* Initialize global data structures.  */
void
mpls_init (void)
{
  mpls_enabled = 0;
  mpls_crossconnect_list = list_new ();
}

/* Clear all created MPLS LSPs.  */
void
mpls_close (void)
{
  struct listnode *node, *nnode;
  struct interface *ifp;
  struct zebra_if *zebra_if;
  struct mpls_crossconnect *mc;
  struct route_table *table;
  struct route_node *rn;

  /* Disable MPLS on all interfaces.  */
  if (mpls_enabled)
    for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
      {
        zebra_if = ifp->info;
        if (zebra_if->mpls_enabled)
          mpls_kernel_set_interface_labelspace (ifp, -1);
      }

  /* Remove MPLS crossconnects.  */
  for (ALL_LIST_ELEMENTS (mpls_crossconnect_list, node, nnode, mc))
    mpls_static_crossconnect_remove (mc->in_label);
  list_free (mpls_crossconnect_list);

  /* Remove all installed MPLS IP bindings.  */
  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (! table)
    return;

  for (rn = route_top (table); rn; rn = route_next (rn))
    if (rn->mpls && zebra_route_node_active (rn))
      mpls_route_uninstall_hook (rn);

  /* Close genetlink sockets.  */
  mpls_kernel_exit ();
}
