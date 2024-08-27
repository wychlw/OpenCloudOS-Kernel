// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2024 Broadcom
 * All rights reserved.
 */
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "bnxt_compat.h"
#include "bnxt_hsi.h"
#include "bnxt.h"
#include "bnxt_hwrm.h"
#include "bnxt_ulp_flow.h"
#include "bnxt_nic_flow.h"
#include "ulp_nic_flow.h"
#include "bnxt_vfr.h"
#include "tfc.h"

#if defined(CONFIG_BNXT_FLOWER_OFFLOAD)

/* Max number of filters per PF */
#define NIC_FLOW_FILTER_MAX 2

/* Per L2 filter RoCE flow data */
struct nic_flow_roce {
	__le64	l2_filter_id;
	u8      mac_addr[ETH_ALEN];
	u32	l2_ctxt_id;
	u32	prof_func;
	u32	flow_id;
	u64	flow_cnt_hndl;
	u32	cnp_flow_id;
	u64	cnp_flow_cnt_hndl;
	bool	in_use;
};

#define NIC_FLOW_SUPPORTED(bp)				\
	(BNXT_PF(bp) && BNXT_TF_RX_NIC_FLOW_CAP(bp) && BNXT_UDCC_CAP(bp))

/* NIC flow database */
struct nic_flow_db {
	struct nic_flow_roce roce[NIC_FLOW_FILTER_MAX];
};

static int bnxt_hwrm_l2_filter_cfg(struct bnxt *bp, __le64 l2_filter_id,
				   u32 l2_ctxt_id, u32 prof_func)
{
	struct hwrm_cfa_l2_filter_cfg_input *req;
	u32 flags;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_CFA_L2_FILTER_CFG);
	if (rc)
		return rc;

	req->target_id = cpu_to_le16(0xffff);
	flags = CFA_L2_FILTER_CFG_REQ_FLAGS_PATH_RX |
		CFA_L2_FILTER_CFG_REQ_FLAGS_REMAP_OP_ENABLE_LKUP;

	req->flags = cpu_to_le32(flags);
	req->enables = cpu_to_le32(CFA_L2_FILTER_CFG_REQ_ENABLES_L2_CONTEXT_ID |
				   CFA_L2_FILTER_CFG_REQ_ENABLES_PROF_FUNC);

	req->l2_filter_id = l2_filter_id;
	req->l2_context_id = l2_ctxt_id;
	req->prof_func = prof_func;

	return hwrm_req_send(bp, req);
}

/* This function initializes the NIC Flow feature which allows
 * TF to insert NIC flows into the CFA.
 */
int bnxt_nic_flows_init(struct bnxt *bp)
{
	struct nic_flow_db *nfdb;
	u16 sid = 0;
	int rc = 0;

	if (!NIC_FLOW_SUPPORTED(bp))
		return 0;

	nfdb = kzalloc(sizeof(*nfdb), GFP_ATOMIC);
	if (!nfdb)
		return -ENOMEM;

	bp->nic_flow_info = nfdb;

	/* Set the session id in TF core to the AFM session */
	rc = tfc_session_id_set(bp->tfp, sid);
	return rc;
}

void bnxt_nic_flows_deinit(struct bnxt *bp)
{
	if (!NIC_FLOW_SUPPORTED(bp))
		return;
	kfree(bp->nic_flow_info);
	bp->nic_flow_info = NULL;
}

int bnxt_nic_flows_open(struct bnxt *bp)
{
	int rc = 0;
	if (!NIC_FLOW_SUPPORTED(bp))
		return rc;

	rc = bnxt_tf_port_init(bp, BNXT_TF_FLAG_NICFLOW);
	if (rc)
		return rc;
	rc = bnxt_nic_flows_roce_add(bp);

	return rc;
}

void bnxt_nic_flows_close(struct bnxt *bp)
{
	if (!NIC_FLOW_SUPPORTED(bp))
		return;
	bnxt_nic_flows_deinit(bp);
	bnxt_tf_port_deinit(bp, BNXT_TF_FLAG_NICFLOW);
}

int bnxt_nic_flows_filter_add(struct bnxt *bp, __le64 l2_filter_id, const u8 *mac_addr)
{
	struct nic_flow_db *nfdb = bp->nic_flow_info;
	struct nic_flow_roce *nfr;
	int i;

	if (!NIC_FLOW_SUPPORTED(bp))
		return 0;
	for (i = 0; i < NIC_FLOW_FILTER_MAX; i++) {
		nfr = &nfdb->roce[i];
		if (nfr->in_use)
			continue;
		nfr->l2_filter_id = l2_filter_id;
		ether_addr_copy(nfr->mac_addr, mac_addr);
		nfr->in_use = true;
		netdev_dbg(bp->dev, "%s: filter_id(%llx) mac(%pM)\n", __func__,
			   l2_filter_id, mac_addr);
		return 0;
	}
	netdev_dbg(bp->dev, "%s: no free NIC flow l2 filter entry\n", __func__);
	return -EINVAL;
}

int bnxt_nic_flows_roce_add(struct bnxt *bp)
{
	struct nic_flow_db *nfdb = bp->nic_flow_info;
	struct nic_flow_roce *nfr;
	int rc = 0;
	u8 i;

	if (!NIC_FLOW_SUPPORTED(bp))
		return rc;
	/* Return until init complete */
	if (!bp->nic_flow_info) {
		netdev_dbg(bp->dev, "%s: Attempt to add RoCE but db not init\n",
			   __func__);
		return -EINVAL;
	}

	for (i = 0; i < NIC_FLOW_FILTER_MAX; i++) {
		nfr = &nfdb->roce[i];
		if (!nfr->in_use)
			continue;

		rc = bnxt_ulp_nic_flows_roce_add(bp, nfr->l2_filter_id, &nfr->l2_ctxt_id,
						 &nfr->prof_func, &nfr->flow_id,
						 &nfr->flow_cnt_hndl, &nfr->cnp_flow_id,
						 &nfr->cnp_flow_cnt_hndl);
		if (rc) {
			netdev_dbg(bp->dev, "%s: RoCE NIC flow creation failure(%d)\n",
				   __func__, rc);
			goto error;
		}
		rc = bnxt_hwrm_l2_filter_cfg(bp, nfr->l2_filter_id, nfr->l2_ctxt_id,
					     nfr->prof_func);
		if (rc) {
			netdev_dbg(bp->dev, "%s: L2 filter cfg error(%d)\n",
				   __func__, rc);
			goto error;
		}
	}
	return rc;
error:
	rc = bnxt_nic_flows_roce_rem(bp, nfr->l2_filter_id);
	return rc;
}

int bnxt_nic_flows_roce_rem(struct bnxt *bp, __le64 l2_filter_id)
{
	struct nic_flow_db *nfdb = bp->nic_flow_info;
	struct nic_flow_roce *nfr;
	int rc = 0;
	u8 i;

	if (!NIC_FLOW_SUPPORTED(bp))
		return 0;

	/* Return until init complete */
	if (!bp->nic_flow_info)
		return 0;

	for (i = 0; i < NIC_FLOW_FILTER_MAX; i++) {
		nfr = &nfdb->roce[i];
		if ((nfr->in_use) && (nfr->l2_filter_id == l2_filter_id)) {
			rc = bnxt_ulp_nic_flows_roce_del(bp, l2_filter_id, nfr->l2_ctxt_id,
							 nfr->prof_func, nfr->flow_id,
							 nfr->cnp_flow_id);
			if (rc)
				netdev_dbg(bp->dev, "%s: delete l2_filter_id(%llx) failed rc(%d)\n",
					   __func__, l2_filter_id, rc);
			nfr->l2_filter_id = 0;
			nfr->in_use = false;
		}
	}
	return rc;
}

int bnxt_nic_flows_filter_info_get(struct bnxt *bp, __le64 l2_filter_id,
				   u32 *l2_ctxt_id, u32 *prof_func)
{
	struct nic_flow_db *nfdb = bp->nic_flow_info;
	struct nic_flow_roce *nfr;
	u8 i;

	if (!NIC_FLOW_SUPPORTED(bp))
		return 0;

	if (!bp->nic_flow_info)
		return -EINVAL;

	for (i = 0; i < NIC_FLOW_FILTER_MAX; i++) {
		nfr = &nfdb->roce[i];
		if ((nfr->in_use) && (nfr->l2_filter_id == l2_filter_id)) {
			*l2_ctxt_id = nfr->l2_ctxt_id;
			*prof_func = nfr->prof_func;
			return 0;
		}
	}
	netdev_dbg(bp->dev, "%s: l2_filter_id(%llx) not found\n",
		   __func__, l2_filter_id);
	return -ENOENT;
}

int bnxt_nic_flow_dmac_filter_get(struct bnxt *bp, u8 *dmac, __le64 *filter_id)
{
	struct nic_flow_db *nfdb = bp->nic_flow_info;
	struct nic_flow_roce *nfr;
	u8 i;

	if (!NIC_FLOW_SUPPORTED(bp))
		return 0;

	if (!bp->nic_flow_info)
		return -EINVAL;

	for (i = 0; i < NIC_FLOW_FILTER_MAX; i++) {
		nfr = &nfdb->roce[i];
		if (!nfr->in_use)
			continue;
		if (ether_addr_equal(nfr->mac_addr, dmac)) {
			*filter_id = nfr->l2_filter_id;
			netdev_dbg(bp->dev, "%s: %pM filter=%llx\n", __func__, dmac,
				   *filter_id);
			return 0;
		}
	}
	netdev_dbg(bp->dev, "%s: No matching filter for dmac%pM\n", __func__, dmac);
	return -ENOENT;
}

#else /* if defined(CONFIG_BNXT_FLOWER_OFFLOAD) */
int bnxt_nic_flows_init(struct bnxt *bp)
{
	return 0;
}

void bnxt_nic_flows_deinit(struct bnxt *bp)
{
}

int bnxt_nic_flows_open(struct bnxt *bp)
{
	return 0;
}

void bnxt_nic_flows_close(struct bnxt *bp)
{
}

int bnxt_nic_flows_filter_add(struct bnxt *bp, __le64 filter_id, const u8 *mac_addr)
{
	return 0;
}

int bnxt_nic_flows_roce_add(struct bnxt *bp)
{
	return 0;
}

int bnxt_nic_flows_roce_rem(struct bnxt *bp, __le64 filter_id)
{
	return 0;
}

int bnxt_nic_flows_filter_info_get(struct bnxt *bp, __le64 filter_id,
				   u32 *l2_ctxt_id, u32 *prof_func)
{
	return 0;
}

#endif /* if defined(CONFIG_BNXT_FLOWER_OFFLOAD) */
