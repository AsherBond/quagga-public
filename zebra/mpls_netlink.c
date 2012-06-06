/*
 * MPLS Netlink Interface.
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
#include <linux/mpls.h>
#include <libnetlink.h>

#include "prefix.h"
#include "log.h"

#include "zebra/interface.h"
#include "zebra/mpls_lib.h"

struct rtnl_handle rth_mpls_nhlfe; /* RTNL for NHLFE adds.  */
struct rtnl_handle rth_mpls_cmd;   /* RTNL for all other MPLS entity actions.  */

extern struct zebra_t zebrad;
extern struct zebra_privs_t zserv_privs;

int mpls_kernel_set_interface_labelspace (struct interface *ifp, int labelspace)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req;
  struct mpls_labelspace_req ls;

  memset (&req, 0, sizeof (req));
  memset (&ls, 0, sizeof (ls));

  req.n.nlmsg_len = NLMSG_LENGTH (GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA (&req.n);
  ghdr->cmd = MPLS_CMD_SETLABELSPACE;

  ls.mls_labelspace = (labelspace < 0) ? -1 : labelspace;
  ls.mls_ifindex = ifp->ifindex;

  addattr_l (&req.n, sizeof (req), MPLS_ATTR_LABELSPACE, &ls, sizeof (ls));

  return rtnl_talk(&rth_mpls_cmd, &req.n, 0, 0, NULL, NULL, NULL);
}

static int
mpls_kernel_ilm (int cmd, u_int32_t label)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req;
  struct mpls_in_label_req mil;

  memset (&req, 0, sizeof (req));
  memset (&mil, 0, sizeof (mil));

  req.n.nlmsg_len = NLMSG_LENGTH (GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA (&req.n);
  ghdr->cmd = cmd;

  mil.mil_proto = AF_INET;
  mil.mil_label.ml_type = MPLS_LABEL_GEN;
  mil.mil_label.u.ml_gen = label;

  addattr_l(&req.n, sizeof (req), MPLS_ATTR_ILM, &mil, sizeof (mil));

  return rtnl_talk(&rth_mpls_cmd, &req.n, 0, 0, NULL, NULL, NULL);
}

int
mpls_kernel_ilm_register (u_int32_t label)
{
  if (label == MPLS_IMPLICIT_NULL)
    return 0;

  zlog_info ("mpls_kernel_ilm_register: %u", label);

  return mpls_kernel_ilm (MPLS_CMD_NEWILM, label);
}

int
mpls_kernel_ilm_unregister (u_int32_t label)
{
  if (label == MPLS_IMPLICIT_NULL)
    return 0;

  zlog_info ("mpls_kernel_ilm_unregister: %u", label);

  return mpls_kernel_ilm (MPLS_CMD_DELILM, label);
}

int
mpls_kernel_nhlfe_register (struct route_lsp *lsp)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req;
  struct mpls_out_label_req mol, *molp;
  struct mpls_instr_req mir;
  struct rtattr *tb[MPLS_ATTR_MAX + 1];
  struct rtattr *attrs;
  int result;
  int c = 0;

  memset (&req, 0, sizeof (req));
  memset (&mol, 0, sizeof (mol));
  memset (&mir, 0, sizeof (mir));

  /* Get output interface.  */
  if (! lsp->ifp)
    lsp->ifp = if_lookup_address (lsp->nexthop);

  req.n.nlmsg_len = NLMSG_LENGTH (GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA (&req.n);
  ghdr->cmd = MPLS_CMD_NEWNHLFE;

  mol.mol_label.ml_type = MPLS_LABEL_KEY;
  mol.mol_label.u.ml_key = 0;
  mol.mol_change_flag |= MPLS_CHANGE_INSTR;

  if (lsp->remote_label != MPLS_IMPLICIT_NULL)
    {
      mir.mir_instr[c].mir_opcode = MPLS_OP_PUSH;
      mir.mir_instr[c].mir_data.push.ml_type = MPLS_LABEL_GEN;
      mir.mir_instr[c].mir_data.push.u.ml_gen = lsp->remote_label;
      c++;
    }

  mir.mir_instr[c].mir_opcode = MPLS_OP_SET;
  mir.mir_instr[c].mir_data.set.mni_if = lsp->ifp->ifindex;

  if (! if_is_pointopoint (lsp->ifp))
    {
      struct sockaddr_in addr;
      addr.sin_family = AF_INET;
      addr.sin_addr = lsp->nexthop;
      memcpy (&mir.mir_instr[c].mir_data.set.mni_addr, &addr, sizeof (addr));
    }

  mir.mir_instr_length = c + 1;
  addattr_l (&req.n, sizeof (req), MPLS_ATTR_NHLFE, &mol, sizeof (mol));
  addattr_l (&req.n, sizeof (req), MPLS_ATTR_INSTR, &mir, sizeof (mir));

  result = rtnl_talk (&rth_mpls_nhlfe, &req.n, 0, 0, &req.n, NULL, NULL);

  ghdr = NLMSG_DATA (&req.n);

  attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
  parse_rtattr (tb, MPLS_ATTR_MAX, attrs,
                req.n.nlmsg_len - NLMSG_LENGTH (GENL_HDRLEN));

  molp = RTA_DATA (tb[MPLS_ATTR_NHLFE]);

  lsp->nhlfe_index = molp->mol_label.u.ml_key;
  zlog_info ("mpls_kernel_nhlfe_register: label = %u, NHLFE = %u",
             lsp->remote_label, lsp->nhlfe_index);

  return result;
}

int
mpls_kernel_nhlfe_unregister (struct route_lsp *lsp)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req;
  struct mpls_out_label_req mol;

  zlog_info ("mpls_kernel_nhlfe_unregister: %u", lsp->remote_label);

  memset (&req, 0, sizeof (req));
  memset (&mol, 0, sizeof (mol));

  req.n.nlmsg_len = NLMSG_LENGTH (GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA (&req.n);
  ghdr->cmd = MPLS_CMD_DELNHLFE;

  mol.mol_label.ml_type = MPLS_LABEL_KEY;
  mol.mol_label.u.ml_key = lsp->nhlfe_index;

  addattr_l(&req.n, sizeof(req), MPLS_ATTR_NHLFE, &mol, sizeof (mol));

  return rtnl_talk (&rth_mpls_cmd, &req.n, 0, 0, NULL, NULL, NULL);
}

static int
mpls_kernel_xc (int cmd, u_int32_t ilm_label, struct route_lsp *lsp)
{
  struct genlmsghdr *ghdr;
  struct
  {
    struct nlmsghdr n;
    char buf[4096];
  } req;
  struct mpls_xconnect_req mx;

  memset (&req, 0, sizeof (req));
  memset (&mx, 0, sizeof (mx));

  req.n.nlmsg_len = NLMSG_LENGTH (GENL_HDRLEN);
  req.n.nlmsg_flags = NLM_F_CREATE|NLM_F_REQUEST;
  req.n.nlmsg_type = AF_MPLS;

  ghdr = NLMSG_DATA (&req.n);
  ghdr->cmd = cmd;

  mx.mx_in.ml_type = MPLS_LABEL_GEN;
  mx.mx_in.u.ml_gen = ilm_label;
  mx.mx_out.ml_type = MPLS_LABEL_KEY;
  mx.mx_out.u.ml_key = lsp->nhlfe_index;

  addattr_l (&req.n, sizeof (req), MPLS_ATTR_XC, &mx, sizeof (mx));

  return rtnl_talk (&rth_mpls_cmd, &req.n, 0, 0, NULL, NULL, NULL);
}

int
mpls_kernel_xc_register (u_int32_t ilm_label, struct route_lsp *lsp)
{
  zlog_info ("mpls_kernel_xc_register: %u <-> %u", ilm_label, lsp->remote_label);

  return mpls_kernel_xc (MPLS_CMD_NEWXC, ilm_label, lsp);
}

int
mpls_kernel_xc_unregister (u_int32_t ilm_label, struct route_lsp *lsp)
{
  zlog_info ("mpls_kernel_xc_unregister: %u <-> %u", ilm_label, lsp->remote_label);

  return mpls_kernel_xc (MPLS_CMD_DELXC, ilm_label, lsp);
}

/* Exported interface function.  This function simply calls
   netlink_socket (). */
void
mpls_kernel_init (void)
{
  if (rtnl_open_byproto (&rth_mpls_nhlfe, MPLS_GRP_NHLFE, NETLINK_GENERIC) < 0)
    {
      zlog_err ("Error opening NHLFE rtnl");
      exit (1);
    }
  if (rtnl_open_byproto (&rth_mpls_cmd, 0, NETLINK_GENERIC) < 0)
    {
      zlog_err ("Error opening generic rtnl");
      exit (1);
    }
}

void
mpls_kernel_exit (void)
{
  rtnl_close (&rth_mpls_nhlfe);
  rtnl_close (&rth_mpls_cmd);
}
