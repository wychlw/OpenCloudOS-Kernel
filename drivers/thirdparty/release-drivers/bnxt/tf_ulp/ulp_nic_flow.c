// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2024 Broadcom
 * All rights reserved.
 */

#include <linux/vmalloc.h>
#include <linux/if_ether.h>
#include <linux/atomic.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/err.h>

#include "bnxt_compat.h"
#include "bnxt_hsi.h"
#include "bnxt.h"
#include "bnxt_vfr.h"
#include "bnxt_tf_ulp.h"
#include "bnxt_udcc.h"
#include "ulp_nic_flow.h"
#include "tfc.h"
#include "tfc_util.h"
#include "ulp_generic_flow_offload.h"

#if defined(CONFIG_BNXT_FLOWER_OFFLOAD)

static int l2_filter_roce_flow_create(struct bnxt *bp, __le64 l2_filter_id,
				      u32 *flow_id, u64 *flow_cnt_hndl)
{
	struct bnxt_ulp_gen_bth_hdr bth_spec = { 0 }, bth_mask = { 0 };
	struct bnxt_ulp_gen_ipv6_hdr v6_spec = { 0 }, v6_mask = { 0 };
	struct bnxt_ulp_gen_l2_hdr_parms l2_parms = { 0 };
	struct bnxt_ulp_gen_l3_hdr_parms l3_parms = { 0 };
	struct bnxt_ulp_gen_l4_hdr_parms l4_parms = { 0 };
	struct bnxt_ulp_gen_action_parms actions = { 0 };
	struct bnxt_ulp_gen_flow_parms parms = { 0 };
	u8 l4_proto = IPPROTO_UDP;
	u8 l4_proto_mask = 0xff;
	int rc = 0;

	l2_parms.type = BNXT_ULP_GEN_L2_L2_FILTER_ID;
	l2_parms.l2_filter_id = &l2_filter_id;

	/* Pack the L3 Data */
	v6_spec.proto6 = &l4_proto;
	v6_mask.proto6 = &l4_proto_mask;
	v6_spec.dip6 = NULL;
	v6_mask.dip6 = NULL;
	v6_spec.sip6 = NULL;
	v6_mask.sip6 = NULL;

	l3_parms.type = BNXT_ULP_GEN_L3_IPV6;
	l3_parms.v6_spec = &v6_spec;
	l3_parms.v6_mask = &v6_mask;

	/* Pack the L4 Data */
	l4_parms.type = BNXT_ULP_GEN_L4_BTH;
	bth_spec.op_code = NULL;
	bth_mask.op_code = NULL;
	bth_spec.dst_qpn = NULL;
	bth_mask.dst_qpn = NULL;
	l4_parms.bth_spec = &bth_spec;
	l4_parms.bth_mask = &bth_mask;

	/* Pack the actions - NIC template will use RoCE VNIC always by default */
	actions.enables = BNXT_ULP_GEN_ACTION_ENABLES_COUNT;
	actions.dst_fid = bp->pf.fw_fid;

	parms.dir = BNXT_ULP_GEN_RX;
	parms.flow_id = flow_id;
	parms.counter_hndl = flow_cnt_hndl;
	parms.l2 = &l2_parms;
	parms.l3 = &l3_parms;
	parms.l4 = &l4_parms;
	parms.actions = &actions;

	rc = bnxt_ulp_gen_flow_create(bp, bp->pf.fw_fid, &parms);
	if (rc)
		return rc;

	netdev_dbg(bp->dev, "%s: L2 filter(%llx) ROCE Add Rx flow_id: %d, ctr: 0x%llx\n",
		   __func__,
		   l2_filter_id,
		   *flow_id,
		   *flow_cnt_hndl);
	return rc;
}

static int l2_filter_roce_cnp_flow_create(struct bnxt *bp, __le64 l2_filter_id,
					  u32 *cnp_flow_id, u64 *cnp_flow_cnt_hndl)
{
	struct bnxt_ulp_gen_bth_hdr bth_spec = { 0 }, bth_mask = { 0 };
	struct bnxt_ulp_gen_ipv6_hdr v6_spec = { 0 }, v6_mask = { 0 };
	struct bnxt_ulp_gen_l2_hdr_parms l2_parms = { 0 };
	struct bnxt_ulp_gen_l3_hdr_parms l3_parms = { 0 };
	struct bnxt_ulp_gen_l4_hdr_parms l4_parms = { 0 };
	struct bnxt_ulp_gen_action_parms actions = { 0 };
	struct bnxt_ulp_gen_flow_parms parms = { 0 };
	u16 op_code = cpu_to_be16(0x81); /* RoCE CNP */
	u16 op_code_mask = cpu_to_be16(0xffff);
	u8 l4_proto = IPPROTO_UDP;
	u8 l4_proto_mask = 0xff;
	int rc = 0;

	l2_parms.type = BNXT_ULP_GEN_L2_L2_FILTER_ID;
	l2_parms.l2_filter_id = &l2_filter_id;

	/* Pack the L3 Data */
	v6_spec.proto6 = &l4_proto;
	v6_mask.proto6 = &l4_proto_mask;
	v6_spec.dip6 = NULL;
	v6_mask.dip6 = NULL;
	v6_spec.sip6 = NULL;
	v6_mask.sip6 = NULL;

	l3_parms.type = BNXT_ULP_GEN_L3_IPV6;
	l3_parms.v6_spec = &v6_spec;
	l3_parms.v6_mask = &v6_mask;

	/* Pack the L4 Data */
	bth_spec.op_code = &op_code;
	bth_mask.op_code = &op_code_mask;
	bth_spec.dst_qpn = NULL;
	bth_mask.dst_qpn = NULL;
	l4_parms.type = BNXT_ULP_GEN_L4_BTH;
	l4_parms.bth_spec = &bth_spec;
	l4_parms.bth_mask = &bth_mask;

	/* Pack the actions - NIC template will use RoCE VNIC always by default */
	actions.enables = BNXT_ULP_GEN_ACTION_ENABLES_COUNT;
	actions.dst_fid = bp->pf.fw_fid;

	parms.dir = BNXT_ULP_GEN_RX;
	parms.flow_id = cnp_flow_id;
	parms.counter_hndl = cnp_flow_cnt_hndl;
	parms.l2 = &l2_parms;
	parms.l3 = &l3_parms;
	parms.l4 = &l4_parms;
	parms.actions = &actions;
	parms.priority = 1; /* must be lower priority than UDCC CNP */

	rc = bnxt_ulp_gen_flow_create(bp, bp->pf.fw_fid, &parms);
	if (rc)
		return rc;

	netdev_dbg(bp->dev, "%s: ROCE CNP Add Rx flow for fid(%d) flow_id: %d, ctr: 0x%llx\n",
		   __func__,
		   bp->pf.fw_fid,
		   *cnp_flow_id,
		   *cnp_flow_cnt_hndl);

	return rc;
}

int bnxt_ulp_nic_flows_roce_add(struct bnxt *bp, __le64 l2_filter_id,
				u32 *l2_ctxt_id, u32 *prof_func,
				u32 *flow_id, u64 *flow_cnt_hndl,
				u32 *cnp_flow_id, u64 *cnp_flow_cnt_hndl)
{
	struct tfc_identifier_info l2_ident_info = { 0 };
	struct tfc_identifier_info prof_ident_info = { 0 };
	struct tfc *tfcp = (struct tfc *)(bp->tfp);
	int rc;

	if (!tfcp) {
		netdev_dbg(bp->dev, "%s TF core not initialized\n", __func__);
		return -EINVAL;
	}

	*prof_func = 0;
	*l2_ctxt_id  = 0;
	*flow_id = 0;
	*cnp_flow_id = 0;
	*flow_cnt_hndl = 0;
	*cnp_flow_cnt_hndl = 0;

	l2_ident_info.dir = (enum cfa_dir)TF_DIR_RX;
	l2_ident_info.rsubtype = CFA_RSUBTYPE_IDENT_L2CTX;

	rc = tfc_identifier_alloc(tfcp, bp->pf.fw_fid, CFA_TRACK_TYPE_FID,
				  &l2_ident_info);
	if (rc) {
		netdev_dbg(bp->dev, "%s: RoCE flow ident alloc failed %d\n",
			   __func__, rc);
		return rc;
	}
	*l2_ctxt_id = l2_ident_info.id;

	netdev_dbg(bp->dev, "%s: NIC Flow allocate l2 ctxt:%d\n", __func__,
		   *l2_ctxt_id);

	prof_ident_info.dir = (enum cfa_dir)TF_DIR_RX;
	prof_ident_info.rsubtype = CFA_RSUBTYPE_IDENT_PROF_FUNC;

	rc = tfc_identifier_alloc(tfcp, bp->pf.fw_fid, CFA_TRACK_TYPE_FID,
				  &prof_ident_info);
	if (rc) {
		netdev_dbg(bp->dev, "%s: RoCE flow prof_func alloc failed %d\n",
			   __func__, rc);
		goto cleanup;
	}

	*prof_func = prof_ident_info.id;

	netdev_dbg(bp->dev, "%s: NIC Flow allocate prof_func:%d\n",
		   __func__, *prof_func);

	rc = l2_filter_roce_flow_create(bp, l2_filter_id, flow_id,
					flow_cnt_hndl);
	if (rc)
		goto cleanup;

	rc = l2_filter_roce_cnp_flow_create(bp, l2_filter_id, cnp_flow_id,
					    cnp_flow_cnt_hndl);

	if (rc)
		goto cleanup;

	return rc;

cleanup:
	bnxt_ulp_nic_flows_roce_del(bp, l2_filter_id, *l2_ctxt_id, *prof_func,
				    *flow_id, *cnp_flow_id);
	return rc;
}

int bnxt_ulp_nic_flows_roce_del(struct bnxt *bp, __le64 l2_filter_id,
				u32 l2_ctxt_id, u32 prof_func,
				u32 roce_flow_id, u32 roce_cnp_flow_id)
{
	struct tfc_identifier_info l2_ident_info = { 0 };
	struct tfc_identifier_info prof_ident_info = { 0 };
	struct tfc *tfcp = (struct tfc *)(bp->tfp);
	int rc_save = 0, rc = 0;

	if (!tfcp) {
		netdev_dbg(bp->dev, "%s TF core not initialized\n", __func__);
		return -EINVAL;
	}
	if (l2_ctxt_id) {
		l2_ident_info.dir = CFA_DIR_RX;
		l2_ident_info.rsubtype = CFA_RSUBTYPE_IDENT_L2CTX;
		l2_ident_info.id = l2_ctxt_id;

		rc = tfc_identifier_free(tfcp, bp->pf.fw_fid, &l2_ident_info);
		if (rc) {
			netdev_dbg(bp->dev, "%s: l2ctx free failed %d\n", __func__, rc);
			rc_save = rc;
		}
	}
	if (prof_func) {
		prof_ident_info.dir = CFA_DIR_RX;
		prof_ident_info.rsubtype = CFA_RSUBTYPE_IDENT_PROF_FUNC;
		prof_ident_info.id = prof_func;

		rc = tfc_identifier_free(tfcp, bp->pf.fw_fid, &prof_ident_info);
		if (rc) {
			netdev_dbg(bp->dev, "%s: prof_func free failed %d\n", __func__, rc);
			rc_save = rc;
		}
	}
	if (roce_flow_id) {
		rc = bnxt_ulp_gen_flow_destroy(bp, bp->pf.fw_fid, roce_flow_id);
		if (rc) {
			netdev_dbg(bp->dev, "%s: delete Rx RoCE flow_id: %d failed %d\n",
				   __func__, roce_flow_id, rc);
			rc_save = rc;
		}
	}
	if (roce_cnp_flow_id) {
		rc = bnxt_ulp_gen_flow_destroy(bp, bp->pf.fw_fid, roce_cnp_flow_id);
		if (rc) {
			netdev_dbg(bp->dev, "%s: delete Rx RoCE CNP flow_id: %d failed %d\n",
				   __func__, roce_cnp_flow_id, rc);
			rc_save = rc;
		}
	}
	return rc_save;
}

#endif /* if defined(CONFIG_BNXT_FLOWER_OFFLOAD) */
