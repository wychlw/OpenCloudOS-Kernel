/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2014-2016 Broadcom Corporation
 * Copyright (c) 2016-2018 Broadcom Limited
 * Copyright (c) 2018-2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/rtnetlink.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include "bnxt_compat.h"
#include "bnxt_hsi.h"
#include "bnxt.h"
#include "bnxt_hwrm.h"
#include "bnxt_ulp.h"
#include "bnxt_sriov.h"
#include "bnxt_vfr.h"
#include "bnxt_ethtool.h"
#include "bnxt_tc.h"
#include "bnxt_devlink.h"
#include "bnxt_sriov_sysfs.h"
#include "tfc_vf2pf_msg.h"

#ifdef CONFIG_BNXT_SRIOV
static int bnxt_hwrm_fwd_async_event_cmpl(struct bnxt *bp,
					  struct bnxt_vf_info *vf,
					  u16 event_id)
{
	struct hwrm_fwd_async_event_cmpl_input *req;
	struct hwrm_async_event_cmpl *async_cmpl;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_FWD_ASYNC_EVENT_CMPL);
	if (rc)
		goto exit;

	if (vf)
		req->encap_async_event_target_id = cpu_to_le16(vf->fw_fid);
	else
		/* broadcast this async event to all VFs */
		req->encap_async_event_target_id = cpu_to_le16(0xffff);
	async_cmpl =
		(struct hwrm_async_event_cmpl *)req->encap_async_event_cmpl;
	async_cmpl->type = cpu_to_le16(ASYNC_EVENT_CMPL_TYPE_HWRM_ASYNC_EVENT);
	async_cmpl->event_id = cpu_to_le16(event_id);

	rc = hwrm_req_send(bp, req);
exit:
	if (rc)
		netdev_err(bp->dev, "hwrm_fwd_async_event_cmpl failed. rc:%d\n",
			   rc);
	return rc;
}

#ifdef HAVE_NDO_GET_VF_CONFIG
static struct bnxt_vf_info *bnxt_vf_ndo_prep(struct bnxt *bp, int vf_id)
	__acquires(&bp->sriov_lock)
{
	struct bnxt_vf_info *vf;

	mutex_lock(&bp->sriov_lock);
	if (!bp->pf.active_vfs) {
		mutex_unlock(&bp->sriov_lock);
		netdev_err(bp->dev, "vf ndo called though sriov is disabled\n");
		return ERR_PTR(-EINVAL);
	}
	if (vf_id >= bp->pf.active_vfs) {
		mutex_unlock(&bp->sriov_lock);
		netdev_err(bp->dev, "Invalid VF id %d\n", vf_id);
		return ERR_PTR(-EINVAL);
	}
	vf = rcu_dereference_protected(bp->pf.vf,
				       lockdep_is_held(&bp->sriov_lock));
	if (!vf) {
		mutex_unlock(&bp->sriov_lock);
		netdev_warn(bp->dev, "VF structure freed\n");
		return ERR_PTR(-ENODEV);
	}
	return &vf[vf_id];
}

static void bnxt_vf_ndo_end(struct bnxt *bp)
	__releases(&bp->sriov_lock)
{
	mutex_unlock(&bp->sriov_lock);
}

#ifdef HAVE_VF_SPOOFCHK
int bnxt_set_vf_spoofchk(struct net_device *dev, int vf_id, bool setting)
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_func_cfg_input *req;
	bool old_setting = false;
	struct bnxt_vf_info *vf;
	u32 func_flags;
	int rc;

	if (bp->hwrm_spec_code < 0x10701)
		return -ENOTSUPP;

	vf = bnxt_vf_ndo_prep(bp, vf_id);
	if (IS_ERR(vf))
		return PTR_ERR(vf);

	if (vf->flags & BNXT_VF_SPOOFCHK)
		old_setting = true;
	if (old_setting == setting) {
		bnxt_vf_ndo_end(bp);
		return 0;
	}

	if (setting)
		func_flags = FUNC_CFG_REQ_FLAGS_SRC_MAC_ADDR_CHECK_ENABLE;
	else
		func_flags = FUNC_CFG_REQ_FLAGS_SRC_MAC_ADDR_CHECK_DISABLE;
	/*TODO: if the driver supports VLAN filter on guest VLAN,
	 * the spoof check should also include vlan anti-spoofing
	 */
	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
	if (!rc) {
		req->fid = cpu_to_le16(vf->fw_fid);
		req->flags = cpu_to_le32(func_flags);
		rc = hwrm_req_send(bp, req);
		if (!rc) {
			if (setting)
				vf->flags |= BNXT_VF_SPOOFCHK;
			else
				vf->flags &= ~BNXT_VF_SPOOFCHK;
		}
	}
	bnxt_vf_ndo_end(bp);
	return rc;
}
#endif

static int bnxt_hwrm_func_qcfg_flags(struct bnxt *bp, struct bnxt_vf_info *vf)
{
	struct hwrm_func_qcfg_output *resp;
	struct hwrm_func_qcfg_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_FUNC_QCFG);
	if (rc)
		return rc;

	req->fid = cpu_to_le16(BNXT_PF(bp) ? vf->fw_fid : 0xffff);
	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc)
		vf->func_qcfg_flags = cpu_to_le16(resp->flags);
	hwrm_req_drop(bp, req);
	return rc;
}

bool bnxt_is_trusted_vf(struct bnxt *bp, struct bnxt_vf_info *vf)
{
	if (BNXT_PF(bp) && !(bp->fw_cap & BNXT_FW_CAP_TRUSTED_VF))
		return !!(vf->flags & BNXT_VF_TRUST);

	if (!(bp->fw_cap & BNXT_FW_CAP_VF_CFG_FOR_PF))
		bnxt_hwrm_func_qcfg_flags(bp, vf);
	return !!(vf->func_qcfg_flags & FUNC_QCFG_RESP_FLAGS_TRUSTED_VF);
}

#ifdef HAVE_NDO_SET_VF_TRUST
static int bnxt_hwrm_set_trusted_vf(struct bnxt *bp, struct bnxt_vf_info *vf)
{
	struct hwrm_func_cfg_input *req;
	int rc;

	if (!(bp->fw_cap & BNXT_FW_CAP_TRUSTED_VF))
		return 0;

	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
	if (rc)
		return rc;

	req->fid = cpu_to_le16(vf->fw_fid);
	if (vf->flags & BNXT_VF_TRUST)
		req->flags = cpu_to_le32(FUNC_CFG_REQ_FLAGS_TRUSTED_VF_ENABLE);
	else
		req->flags = cpu_to_le32(FUNC_CFG_REQ_FLAGS_TRUSTED_VF_DISABLE);
	return hwrm_req_send(bp, req);
}

int bnxt_set_vf_trust(struct net_device *dev, int vf_id, bool trusted)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_vf_info *vf;

	vf = bnxt_vf_ndo_prep(bp, vf_id);
	if (IS_ERR(vf))
		return -EINVAL;

	if (trusted)
		vf->flags |= BNXT_VF_TRUST;
	else
		vf->flags &= ~BNXT_VF_TRUST;

	bnxt_hwrm_set_trusted_vf(bp, vf);
	bnxt_vf_ndo_end(bp);
	return 0;
}
#endif

#ifdef HAVE_NDO_SET_VF_QUEUES
static bool bnxt_param_ok(int new, u16 curr, u16 avail)
{
	int delta;

	if (new <= curr)
		return true;

	delta = new - curr;
	if (delta <= avail)
		return true;
	return false;
}

static void bnxt_adjust_ring_resc(struct bnxt *bp, struct bnxt_vf_info *vf,
				  struct hwrm_func_vf_resource_cfg_input *req)
{
	struct bnxt_hw_resc *hw_resc = &bp->hw_resc;
	u16 cp = 0, grp = 0, stat = 0, vnic = 0;
	u16 min_l2, max_l2, min_rss, max_rss;
	u16 min_tx, max_tx, min_rx, max_rx;

	min_tx = le16_to_cpu(req->min_tx_rings);
	max_tx = le16_to_cpu(req->max_tx_rings);
	min_rx = le16_to_cpu(req->min_rx_rings);
	max_rx = le16_to_cpu(req->max_rx_rings);
	min_rss = le16_to_cpu(req->min_rsscos_ctx);
	max_rss = le16_to_cpu(req->max_rsscos_ctx);
	min_l2 = le16_to_cpu(req->min_l2_ctxs);
	max_l2 = le16_to_cpu(req->max_l2_ctxs);
	if (!min_tx && !max_tx && !min_rx && !max_rx) {
		min_rss = 0;
		max_rss = 0;
		min_l2 = 0;
		max_l2 = 0;
	} else if (bp->pf.vf_resv_strategy == BNXT_VF_RESV_STRATEGY_MAXIMAL) {
		u16 avail_cp_rings, avail_stat_ctx;
		u16 avail_vnics, avail_ring_grps;

		avail_cp_rings = bnxt_get_avail_cp_rings_for_en(bp);
		avail_stat_ctx = bnxt_get_avail_stat_ctxs_for_en(bp);
		avail_ring_grps = hw_resc->max_hw_ring_grps - bp->rx_nr_rings;
		avail_vnics = hw_resc->max_vnics - bp->nr_vnics;

		cp = max_t(u16, 2 * min_tx, min_rx);
		if (cp > vf->min_cp_rings)
			cp = min_t(u16, cp, avail_cp_rings + vf->min_cp_rings);
		grp = min_tx;
		if (grp > vf->min_ring_grps)
			grp = min_t(u16, avail_ring_grps + vf->min_ring_grps,
				    grp);
		stat = min_rx;
		if (stat > vf->min_stat_ctxs)
			stat = min_t(u16, avail_stat_ctx + vf->min_stat_ctxs,
				     stat);
		vnic = min_rx;
		if (vnic > vf->min_vnics)
			vnic = min_t(u16, vnic, avail_vnics + vf->min_vnics);

	} else {
		return;
	}
	req->min_cmpl_rings = cpu_to_le16(cp);
	req->max_cmpl_rings = cpu_to_le16(cp);
	req->min_hw_ring_grps = cpu_to_le16(grp);
	req->max_hw_ring_grps = cpu_to_le16(grp);
	req->min_stat_ctx = cpu_to_le16(stat);
	req->max_stat_ctx = cpu_to_le16(stat);
	req->min_vnics = cpu_to_le16(vnic);
	req->max_vnics = cpu_to_le16(vnic);
	req->min_rsscos_ctx = cpu_to_le16(min_rss);
	req->max_rsscos_ctx = cpu_to_le16(max_rss);
	req->min_l2_ctxs = cpu_to_le16(min_l2);
	req->max_l2_ctxs = cpu_to_le16(max_l2);
}

static void bnxt_record_ring_resc(struct bnxt *bp, struct bnxt_vf_info *vf,
				  struct hwrm_func_vf_resource_cfg_input *req)
{
	struct bnxt_hw_resc *hw_resc = &bp->hw_resc;

	hw_resc->max_tx_rings += vf->min_tx_rings;
	hw_resc->max_rx_rings += vf->min_rx_rings;
	vf->min_tx_rings = le16_to_cpu(req->min_tx_rings);
	vf->max_tx_rings = le16_to_cpu(req->max_tx_rings);
	vf->min_rx_rings = le16_to_cpu(req->min_rx_rings);
	vf->max_rx_rings = le16_to_cpu(req->max_rx_rings);
	hw_resc->max_tx_rings -= vf->min_tx_rings;
	hw_resc->max_rx_rings -= vf->min_rx_rings;
	if (bp->pf.vf_resv_strategy == BNXT_VF_RESV_STRATEGY_MAXIMAL) {
		hw_resc->max_cp_rings += vf->min_cp_rings;
		hw_resc->max_hw_ring_grps += vf->min_ring_grps;
		hw_resc->max_stat_ctxs += vf->min_stat_ctxs;
		hw_resc->max_vnics += vf->min_vnics;
		vf->min_cp_rings = le16_to_cpu(req->min_cmpl_rings);
		vf->min_ring_grps = le16_to_cpu(req->min_hw_ring_grps);
		vf->min_stat_ctxs = le16_to_cpu(req->min_stat_ctx);
		vf->min_vnics = le16_to_cpu(req->min_vnics);
		hw_resc->max_cp_rings -= vf->min_cp_rings;
		hw_resc->max_hw_ring_grps -= vf->min_ring_grps;
		hw_resc->max_stat_ctxs -= vf->min_stat_ctxs;
		hw_resc->max_vnics -= vf->min_vnics;
	}
}

int bnxt_set_vf_queues(struct net_device *dev, int vf_id, int min_txq,
		       int max_txq, int min_rxq, int max_rxq)
{
	struct hwrm_func_vf_resource_cfg_input *req;
	struct bnxt *bp = netdev_priv(dev);
	u16 avail_tx_rings, avail_rx_rings;
	struct bnxt_hw_resc *hw_resc;
	struct bnxt_vf_info *vf;
	int rc;

	vf = bnxt_vf_ndo_prep(bp, vf_id);
	if (IS_ERR(vf))
		return -EINVAL;

	if (!BNXT_NEW_RM(bp) ||
	    !(bp->fw_cap & BNXT_FW_CAP_VF_RES_MIN_GUARANTEED)) {
		bnxt_vf_ndo_end(bp);
		return -EOPNOTSUPP;
	}

	hw_resc = &bp->hw_resc;

	avail_tx_rings = hw_resc->max_tx_rings - bp->tx_nr_rings;
	if (bp->flags & BNXT_FLAG_AGG_RINGS)
		avail_rx_rings = hw_resc->max_rx_rings - bp->rx_nr_rings * 2;
	else
		avail_rx_rings = hw_resc->max_rx_rings - bp->rx_nr_rings;

	if (!bnxt_param_ok(min_txq, vf->min_tx_rings, avail_tx_rings) ||
	    !bnxt_param_ok(min_rxq, vf->min_rx_rings, avail_rx_rings) ||
	    !bnxt_param_ok(max_txq, vf->max_tx_rings, avail_tx_rings) ||
	    !bnxt_param_ok(max_rxq, vf->max_rx_rings, avail_rx_rings)) {
		bnxt_vf_ndo_end(bp);
		return -ENOBUFS;
	}

	rc = hwrm_req_init(bp, req, HWRM_FUNC_VF_RESOURCE_CFG);
	if (rc) {
		bnxt_vf_ndo_end(bp);
		return rc;
	}

	rc = hwrm_req_replace(bp, req, &bp->vf_resc_cfg_input, sizeof(*req));
	if (rc) {
		bnxt_vf_ndo_end(bp);
		return rc;
	}

	req->vf_id = cpu_to_le16(vf->fw_fid);
	req->min_tx_rings = cpu_to_le16(min_txq);
	req->min_rx_rings = cpu_to_le16(min_rxq);
	req->max_tx_rings = cpu_to_le16(max_txq);
	req->max_rx_rings = cpu_to_le16(max_rxq);
	req->flags = cpu_to_le16(FUNC_VF_RESOURCE_CFG_REQ_FLAGS_MIN_GUARANTEED);

	bnxt_adjust_ring_resc(bp, vf, req);

	bnxt_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc)
		bnxt_record_ring_resc(bp, vf, req);
	bnxt_req_drop(bp, req);
	bnxt_vf_ndo_end(bp);
	return rc;
}
#endif

int bnxt_get_vf_config(struct net_device *dev, int vf_id,
		       struct ifla_vf_info *ivi)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_vf_info *vf;

	vf = bnxt_vf_ndo_prep(bp, vf_id);
	if (IS_ERR(vf))
		return PTR_ERR(vf);

	ivi->vf = vf_id;

	if (is_valid_ether_addr(vf->mac_addr))
		memcpy(&ivi->mac, vf->mac_addr, ETH_ALEN);
	else
		memcpy(&ivi->mac, vf->vf_mac_addr, ETH_ALEN);
#ifdef HAVE_IFLA_TX_RATE
	ivi->max_tx_rate = vf->max_tx_rate;
	ivi->min_tx_rate = vf->min_tx_rate;
#else
	ivi->tx_rate = vf->max_tx_rate;
#endif
	ivi->vlan = vf->vlan & VLAN_VID_MASK;
	ivi->qos = vf->vlan >> VLAN_PRIO_SHIFT;
#ifdef HAVE_VF_SPOOFCHK
	ivi->spoofchk = !!(vf->flags & BNXT_VF_SPOOFCHK);
#endif
#ifdef HAVE_NDO_SET_VF_TRUST
	ivi->trusted = bnxt_is_trusted_vf(bp, vf);
#endif
#ifdef HAVE_NDO_SET_VF_LINK_STATE
	if (!(vf->flags & BNXT_VF_LINK_FORCED))
		ivi->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vf->flags & BNXT_VF_LINK_UP)
		ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		ivi->linkstate = IFLA_VF_LINK_STATE_DISABLE;
#endif
#ifdef HAVE_NDO_SET_VF_QUEUES
	ivi->min_tx_queues = vf->min_tx_rings;
	ivi->max_tx_queues = vf->max_tx_rings;
	ivi->min_rx_queues = vf->min_rx_rings;
	ivi->max_rx_queues = vf->max_rx_rings;
#endif

	bnxt_vf_ndo_end(bp);
	return 0;
}

int bnxt_set_vf_mac(struct net_device *dev, int vf_id, u8 *mac)
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_func_cfg_input *req;
	struct bnxt_vf_info *vf;
	u16 fw_fid;
	int rc;

	vf = bnxt_vf_ndo_prep(bp, vf_id);
	if (IS_ERR(vf))
		return PTR_ERR(vf);
	/* reject bc or mc mac addr, zero mac addr means allow
	 * VF to use its own mac addr
	 */
	if (is_multicast_ether_addr(mac)) {
		bnxt_vf_ndo_end(bp);
		netdev_err(dev, "Invalid VF ethernet address\n");
		return -EINVAL;
	}

	memcpy(vf->mac_addr, mac, ETH_ALEN);
	fw_fid = vf->fw_fid;
	bnxt_vf_ndo_end(bp);

	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
	if (rc)
		return rc;

	req->fid = cpu_to_le16(fw_fid);
	req->enables = cpu_to_le32(FUNC_CFG_REQ_ENABLES_DFLT_MAC_ADDR);
	memcpy(req->dflt_mac_addr, mac, ETH_ALEN);
	return hwrm_req_send(bp, req);
}

#ifdef NEW_NDO_SET_VF_VLAN
int bnxt_set_vf_vlan(struct net_device *dev, int vf_id, u16 vlan_id, u8 qos,
		     __be16 vlan_proto)
#else
int bnxt_set_vf_vlan(struct net_device *dev, int vf_id, u16 vlan_id, u8 qos)
#endif
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_func_cfg_input *req;
	struct bnxt_vf_info *vf;
	u16 vlan_tag;
	int rc;

	if (bp->hwrm_spec_code < 0x10201)
		return -ENOTSUPP;

#ifdef NEW_NDO_SET_VF_VLAN
	if (vlan_proto != htons(ETH_P_8021Q) &&
	    (vlan_proto != htons(ETH_P_8021AD) || !(bp->fw_cap & BNXT_FW_CAP_DFLT_VLAN_TPID_PCP)))
		return -EPROTONOSUPPORT;
#endif

	vf = bnxt_vf_ndo_prep(bp, vf_id);
	if (IS_ERR(vf))
		return PTR_ERR(vf);

	if (vlan_id >= VLAN_N_VID || qos >= IEEE_8021Q_MAX_PRIORITIES || (!vlan_id && qos)) {
		bnxt_vf_ndo_end(bp);
		return -EINVAL;
	}

	vlan_tag = vlan_id | (u16)qos << VLAN_PRIO_SHIFT;
	if (vlan_tag == vf->vlan) {
		bnxt_vf_ndo_end(bp);
		return 0;
	}

	if (!netif_running(bp->dev)) {
		bnxt_vf_ndo_end(bp);
		return -ENETDOWN;
	}
	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
	if (!rc) {
		req->fid = cpu_to_le16(vf->fw_fid);
		req->dflt_vlan = cpu_to_le16(vlan_tag);
		req->enables = cpu_to_le32(FUNC_CFG_REQ_ENABLES_DFLT_VLAN);
#ifdef NEW_NDO_SET_VF_VLAN
		if (bp->fw_cap & BNXT_FW_CAP_DFLT_VLAN_TPID_PCP) {
			req->enables |= cpu_to_le32(FUNC_CFG_REQ_ENABLES_TPID);
			req->tpid = vlan_proto;
		}
#endif
		rc = hwrm_req_send(bp, req);
		if (!rc)
			vf->vlan = vlan_tag;
	}
	bnxt_vf_ndo_end(bp);
	return rc;
}

#ifdef HAVE_IFLA_TX_RATE
int bnxt_set_vf_bw(struct net_device *dev, int vf_id, int min_tx_rate,
		   int max_tx_rate)
#else
int bnxt_set_vf_bw(struct net_device *dev, int vf_id, int max_tx_rate)
#endif
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_func_cfg_input *req;
	struct bnxt_vf_info *vf;
	u32 pf_link_speed;
	int rc;

	vf = bnxt_vf_ndo_prep(bp, vf_id);
	if (IS_ERR(vf))
		return PTR_ERR(vf);

	pf_link_speed = bnxt_fw_to_ethtool_speed(bp->link_info.link_speed);
	if (max_tx_rate > pf_link_speed) {
		bnxt_vf_ndo_end(bp);
		netdev_info(bp->dev, "max tx rate %d exceed PF link speed for VF %d\n",
			    max_tx_rate, vf_id);
		return -EINVAL;
	}

#ifdef HAVE_IFLA_TX_RATE
	if (min_tx_rate > pf_link_speed || min_tx_rate > max_tx_rate) {
		bnxt_vf_ndo_end(bp);
		netdev_info(bp->dev, "min tx rate %d is invalid for VF %d\n",
			    min_tx_rate, vf_id);
		return -EINVAL;
	}
	if (min_tx_rate == vf->min_tx_rate && max_tx_rate == vf->max_tx_rate) {
		bnxt_vf_ndo_end(bp);
		return 0;
	}
#else
	if (max_tx_rate == vf->max_tx_rate) {
		bnxt_vf_ndo_end(bp);
		return 0;
	}
#endif
	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
	if (!rc) {
		req->fid = cpu_to_le16(vf->fw_fid);
		req->enables = cpu_to_le32(FUNC_CFG_REQ_ENABLES_MAX_BW);
		req->max_bw = cpu_to_le32(max_tx_rate);
#ifdef HAVE_IFLA_TX_RATE
		req->enables |= cpu_to_le32(FUNC_CFG_REQ_ENABLES_MIN_BW);
		req->min_bw = cpu_to_le32(min_tx_rate);
#endif
		rc = hwrm_req_send(bp, req);
		if (!rc) {
#ifdef HAVE_IFLA_TX_RATE
			vf->min_tx_rate = min_tx_rate;
#endif
			vf->max_tx_rate = max_tx_rate;
		}
	}
	bnxt_vf_ndo_end(bp);
	return rc;
}

static int bnxt_set_vf_link_admin_state(struct bnxt *bp, int vf_id)
{
	struct hwrm_func_cfg_input *req;
	struct bnxt_vf_info *vf;
	int rc;

	if (!(bp->fw_cap & BNXT_FW_CAP_LINK_ADMIN))
		return 0;

	vf = &bp->pf.vf[vf_id];

	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
	if (rc)
		return rc;

	req->fid = cpu_to_le16(vf->fw_fid);
	switch (vf->flags & (BNXT_VF_LINK_FORCED | BNXT_VF_LINK_UP)) {
	case BNXT_VF_LINK_FORCED:
		req->options =
			FUNC_CFG_REQ_OPTIONS_LINK_ADMIN_STATE_FORCED_DOWN;
		break;
	case (BNXT_VF_LINK_FORCED | BNXT_VF_LINK_UP):
		req->options = FUNC_CFG_REQ_OPTIONS_LINK_ADMIN_STATE_FORCED_UP;
		break;
	default:
		req->options = FUNC_CFG_REQ_OPTIONS_LINK_ADMIN_STATE_AUTO;
		break;
	}
	req->enables = cpu_to_le32(FUNC_CFG_REQ_ENABLES_ADMIN_LINK_STATE);
	return hwrm_req_send(bp, req);
}

#ifdef HAVE_NDO_SET_VF_LINK_STATE
int bnxt_set_vf_link_state(struct net_device *dev, int vf_id, int link)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_vf_info *vf;
	int rc;

	vf = bnxt_vf_ndo_prep(bp, vf_id);
	if (IS_ERR(vf))
		return PTR_ERR(vf);

	vf->flags &= ~(BNXT_VF_LINK_UP | BNXT_VF_LINK_FORCED);
	switch (link) {
	case IFLA_VF_LINK_STATE_AUTO:
		vf->flags |= BNXT_VF_LINK_UP;
		break;
	case IFLA_VF_LINK_STATE_DISABLE:
		vf->flags |= BNXT_VF_LINK_FORCED;
		break;
	case IFLA_VF_LINK_STATE_ENABLE:
		vf->flags |= BNXT_VF_LINK_UP | BNXT_VF_LINK_FORCED;
		break;
	default:
		netdev_err(bp->dev, "Invalid link option\n");
		bnxt_vf_ndo_end(bp);
		return -EINVAL;
	}

	if (!(bp->fw_cap & BNXT_FW_CAP_LINK_ADMIN))
		rc = bnxt_hwrm_fwd_async_event_cmpl(bp, vf,
			ASYNC_EVENT_CMPL_EVENT_ID_LINK_STATUS_CHANGE);
	else
		rc = bnxt_set_vf_link_admin_state(bp, vf_id);

	if (rc)
		rc = -EIO;
	bnxt_vf_ndo_end(bp);
	return rc;
}
#endif
#endif

static void bnxt_set_vf_attr(struct bnxt *bp, int num_vfs)
{
	int i;
	struct bnxt_vf_info *vf;

	for (i = 0; i < num_vfs; i++) {
		vf = &bp->pf.vf[i];
		memset(vf, 0, sizeof(*vf));
	}
}

static int bnxt_hwrm_func_vf_resource_free(struct bnxt *bp, int num_vfs)
{
	struct hwrm_func_vf_resc_free_input *req;
	struct bnxt_pf_info *pf = &bp->pf;
	int i, rc;

	rc = hwrm_req_init(bp, req, HWRM_FUNC_VF_RESC_FREE);
	if (rc)
		return rc;

	hwrm_req_hold(bp, req);
	for (i = pf->first_vf_id; i < pf->first_vf_id + num_vfs; i++) {
		req->vf_id = cpu_to_le16(i);
		rc = hwrm_req_send(bp, req);
		if (rc)
			break;
	}
	hwrm_req_drop(bp, req);
	return rc;
}

void bnxt_free_vf_stats_mem(struct bnxt *bp)
{
	int num_vfs = pci_num_vf(bp->pdev);
	struct bnxt_vf_info *vf;
	int i;

	mutex_lock(&bp->sriov_lock);
	vf = rcu_dereference_protected(bp->pf.vf,
				       lockdep_is_held(&bp->sriov_lock));
	if (!vf) {
		mutex_unlock(&bp->sriov_lock);
		return;
	}

	for (i = 0; i < num_vfs; i++) {
		if (vf[i].stats.hw_stats)
			bnxt_free_stats_mem(bp, &vf[i].stats);
	}
	mutex_unlock(&bp->sriov_lock);
}

static void bnxt_free_vf_resources(struct bnxt *bp)
{
	struct pci_dev *pdev = bp->pdev;
	struct bnxt_vf_info *vf;
	int i;

	mutex_lock(&bp->sriov_lock);
	bp->pf.active_vfs = 0;
	vf = rcu_dereference_protected(bp->pf.vf,
				       lockdep_is_held(&bp->sriov_lock));
	RCU_INIT_POINTER(bp->pf.vf, NULL);
	synchronize_rcu();
	kfree(vf);

	kfree(bp->pf.vf_event_bmap);
	bp->pf.vf_event_bmap = NULL;

	for (i = 0; i < BNXT_MAX_VF_CMD_FWD_PAGES; i++) {
		if (bp->pf.hwrm_cmd_req_addr[i]) {
			dma_free_coherent(&pdev->dev, 1 << bp->pf.vf_hwrm_cmd_req_page_shift,
					  bp->pf.hwrm_cmd_req_addr[i],
					  bp->pf.hwrm_cmd_req_dma_addr[i]);
			bp->pf.hwrm_cmd_req_addr[i] = NULL;
		}
	}
	mutex_unlock(&bp->sriov_lock);
}

int bnxt_alloc_vf_stats_mem(struct bnxt *bp)
{
	int num_vfs = pci_num_vf(bp->pdev);
	struct bnxt_vf_info *vf;
	int rc = 0;
	int i;

	mutex_lock(&bp->sriov_lock);
	vf = rcu_dereference_protected(bp->pf.vf,
				       lockdep_is_held(&bp->sriov_lock));
	if (!vf) {
		mutex_unlock(&bp->sriov_lock);
		return -EINVAL;
	}

	for (i = 0; i < num_vfs; i++) {
		bp->pf.vf[i].stats.len = sizeof(struct ctx_hw_stats);
		if (bp->pf.vf[i].stats.hw_stats)
			continue;

		rc = bnxt_alloc_stats_mem(bp, &bp->pf.vf[i].stats, !i);
		if (rc)
			break;
	}

	/* Query function stat mask to the vf[0]
	 * stat structure for overflow processing.
	 */
	if (!rc)
		bnxt_get_func_stats_ext_mask(bp, &bp->pf.vf[0].stats);
	mutex_unlock(&bp->sriov_lock);

	if (rc)
		bnxt_free_vf_stats_mem(bp);
	return rc;
}

static int bnxt_alloc_vf_resources(struct bnxt *bp, int num_vfs)
{
	struct pci_dev *pdev = bp->pdev;
	u32 nr_pages, size, i, j, k = 0;
	u32 page_size, reqs_per_page;
	void *p;

	p = kcalloc(num_vfs, sizeof(struct bnxt_vf_info), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	rcu_assign_pointer(bp->pf.vf, p);
	bnxt_set_vf_attr(bp, num_vfs);

	size = num_vfs * BNXT_HWRM_REQ_MAX_SIZE;
	page_size = BNXT_PAGE_SIZE;
	bp->pf.vf_hwrm_cmd_req_page_shift = BNXT_PAGE_SHIFT;
	/* Adjust the page size to make sure we fit all VFs to up to 4 chunks*/
	while (size > page_size * BNXT_MAX_VF_CMD_FWD_PAGES) {
		page_size *= 2;
		bp->pf.vf_hwrm_cmd_req_page_shift++;
	}
	nr_pages = DIV_ROUND_UP(size, page_size);
	reqs_per_page = page_size / BNXT_HWRM_REQ_MAX_SIZE;

	for (i = 0; i < nr_pages; i++) {
		bp->pf.hwrm_cmd_req_addr[i] =
			dma_alloc_coherent(&pdev->dev, page_size,
					   &bp->pf.hwrm_cmd_req_dma_addr[i],
					   GFP_KERNEL);

		if (!bp->pf.hwrm_cmd_req_addr[i])
			return -ENOMEM;

		for (j = 0; j < reqs_per_page && k < num_vfs; j++) {
			struct bnxt_vf_info *vf = &bp->pf.vf[k];

			vf->hwrm_cmd_req_addr = bp->pf.hwrm_cmd_req_addr[i] +
						j * BNXT_HWRM_REQ_MAX_SIZE;
			vf->hwrm_cmd_req_dma_addr =
				bp->pf.hwrm_cmd_req_dma_addr[i] + j *
				BNXT_HWRM_REQ_MAX_SIZE;
			k++;
		}
	}

	bp->pf.vf_event_bmap = kzalloc(ALIGN(DIV_ROUND_UP(num_vfs, 8), sizeof(long)), GFP_KERNEL);
	if (!bp->pf.vf_event_bmap)
		return -ENOMEM;

	bp->pf.hwrm_cmd_req_pages = nr_pages;
	return 0;
}

static int bnxt_hwrm_func_buf_rgtr(struct bnxt *bp)
{
	struct hwrm_func_buf_rgtr_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_FUNC_BUF_RGTR);
	if (rc)
		return rc;

	req->req_buf_num_pages = cpu_to_le16(bp->pf.hwrm_cmd_req_pages);
	req->req_buf_page_size = cpu_to_le16(bp->pf.vf_hwrm_cmd_req_page_shift);
	req->req_buf_len = cpu_to_le16(BNXT_HWRM_REQ_MAX_SIZE);
	req->req_buf_page_addr0 = cpu_to_le64(bp->pf.hwrm_cmd_req_dma_addr[0]);
	req->req_buf_page_addr1 = cpu_to_le64(bp->pf.hwrm_cmd_req_dma_addr[1]);
	req->req_buf_page_addr2 = cpu_to_le64(bp->pf.hwrm_cmd_req_dma_addr[2]);
	req->req_buf_page_addr3 = cpu_to_le64(bp->pf.hwrm_cmd_req_dma_addr[3]);

	return hwrm_req_send(bp, req);
}

static int __bnxt_set_vf_params(struct bnxt *bp, int vf_id)
{
	struct hwrm_func_cfg_input *req;
	struct bnxt_vf_info *vf;
	int rc;

	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
	if (rc)
		return rc;

	vf = &bp->pf.vf[vf_id];
	req->fid = cpu_to_le16(vf->fw_fid);

	if (is_valid_ether_addr(vf->mac_addr)) {
		req->enables |= cpu_to_le32(FUNC_CFG_REQ_ENABLES_DFLT_MAC_ADDR);
		memcpy(req->dflt_mac_addr, vf->mac_addr, ETH_ALEN);
	}
	if (vf->vlan) {
		req->enables |= cpu_to_le32(FUNC_CFG_REQ_ENABLES_DFLT_VLAN);
		req->dflt_vlan = cpu_to_le16(vf->vlan);
	}
	if (vf->max_tx_rate) {
		req->enables |= cpu_to_le32(FUNC_CFG_REQ_ENABLES_MAX_BW);
		req->max_bw = cpu_to_le32(vf->max_tx_rate);
#ifdef HAVE_IFLA_TX_RATE
		req->enables |= cpu_to_le32(FUNC_CFG_REQ_ENABLES_MIN_BW);
		req->min_bw = cpu_to_le32(vf->min_tx_rate);
#endif
	}
	if (vf->flags & BNXT_VF_TRUST)
		req->flags |= cpu_to_le32(FUNC_CFG_REQ_FLAGS_TRUSTED_VF_ENABLE);

	return hwrm_req_send(bp, req);
}

static void bnxt_hwrm_roce_sriov_cfg(struct bnxt *bp, int num_vfs)
{
	struct hwrm_func_qcaps_output *resp;
	struct hwrm_func_cfg_input *cfg_req;
	struct hwrm_func_qcaps_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_FUNC_QCAPS);
	if (rc)
		return;

	req->fid = cpu_to_le16(0xffff);
	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto err;

	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &cfg_req);
	if (rc)
		goto err;

	cfg_req->fid = cpu_to_le16(0xffff);
	cfg_req->enables2 = cpu_to_le32(FUNC_CFG_REQ_ENABLES2_ROCE_MAX_AV_PER_VF |
				    FUNC_CFG_REQ_ENABLES2_ROCE_MAX_CQ_PER_VF |
				    FUNC_CFG_REQ_ENABLES2_ROCE_MAX_MRW_PER_VF |
				    FUNC_CFG_REQ_ENABLES2_ROCE_MAX_QP_PER_VF |
				    FUNC_CFG_REQ_ENABLES2_ROCE_MAX_SRQ_PER_VF |
				    FUNC_CFG_REQ_ENABLES2_ROCE_MAX_GID_PER_VF);
	cfg_req->roce_max_av_per_vf = cpu_to_le32(le32_to_cpu(resp->roce_vf_max_av) / num_vfs);
	cfg_req->roce_max_cq_per_vf = cpu_to_le32(le32_to_cpu(resp->roce_vf_max_cq) / num_vfs);
	cfg_req->roce_max_mrw_per_vf = cpu_to_le32(le32_to_cpu(resp->roce_vf_max_mrw) / num_vfs);
	cfg_req->roce_max_qp_per_vf = cpu_to_le32(le32_to_cpu(resp->roce_vf_max_qp) / num_vfs);
	cfg_req->roce_max_srq_per_vf = cpu_to_le32(le32_to_cpu(resp->roce_vf_max_srq) / num_vfs);
	cfg_req->roce_max_gid_per_vf = cpu_to_le32(le32_to_cpu(resp->roce_vf_max_gid) / num_vfs);

	rc = hwrm_req_send(bp, cfg_req);
	if (rc)
		goto err;

	hwrm_req_drop(bp, req);
	return;

err:
	hwrm_req_drop(bp, req);
	netdev_err(bp->dev, "RoCE sriov configuration failed\n");
}

/* Only called by PF to reserve resources for VFs, returns actual number of
 * VFs configured, or < 0 on error.
 */
static int bnxt_hwrm_func_vf_resc_cfg(struct bnxt *bp, int num_vfs, bool reset)
{
	struct hwrm_func_vf_resource_cfg_input *req;
	struct bnxt_hw_resc *hw_resc = &bp->hw_resc;
	u16 vf_tx_rings, vf_rx_rings, vf_cp_rings;
	u16 vf_stat_ctx, vf_vnics, vf_ring_grps;
	struct bnxt_pf_info *pf = &bp->pf;
	int i, rc, min = 1;
	u16 vf_msix = 0;
	u16 vf_rss;

	rc = hwrm_req_init(bp, req, HWRM_FUNC_VF_RESOURCE_CFG);
	if (rc)
		return rc;

	if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS) {
		vf_msix = hw_resc->max_nqs - bnxt_min_nq_rings_in_use(bp);
		vf_ring_grps = 0;
	} else {
		vf_ring_grps = hw_resc->max_hw_ring_grps - bp->rx_nr_rings;
	}
	vf_cp_rings = bnxt_get_avail_cp_rings_for_en(bp);
	vf_stat_ctx = bnxt_get_avail_stat_ctxs_for_en(bp);
	if (bp->flags & BNXT_FLAG_AGG_RINGS)
		vf_rx_rings = hw_resc->max_rx_rings - bp->rx_nr_rings * 2;
	else
		vf_rx_rings = hw_resc->max_rx_rings - bp->rx_nr_rings;
	vf_tx_rings = hw_resc->max_tx_rings - bnxt_total_tx_rings(bp);
	vf_vnics = hw_resc->max_vnics - bp->nr_vnics;
	vf_rss = hw_resc->max_rsscos_ctxs - bp->rsscos_nr_ctxs;

	req->min_rsscos_ctx = cpu_to_le16(BNXT_VF_MIN_RSS_CTX);
	if (pf->vf_resv_strategy == BNXT_VF_RESV_STRATEGY_MINIMAL_STATIC) {
		min = 0;
		req->min_rsscos_ctx = cpu_to_le16(min);
	}
	if (pf->vf_resv_strategy == BNXT_VF_RESV_STRATEGY_MINIMAL ||
	    pf->vf_resv_strategy == BNXT_VF_RESV_STRATEGY_MINIMAL_STATIC) {
		req->min_cmpl_rings = cpu_to_le16(min);
		req->min_tx_rings = cpu_to_le16(min);
		req->min_rx_rings = cpu_to_le16(min);
		req->min_l2_ctxs = cpu_to_le16(min);
		req->min_vnics = cpu_to_le16(min);
		req->min_stat_ctx = cpu_to_le16(min);
		if (!(bp->flags & BNXT_FLAG_CHIP_P5_PLUS))
			req->min_hw_ring_grps = cpu_to_le16(min);
	} else {
		vf_cp_rings /= num_vfs;
		vf_tx_rings /= num_vfs;
		vf_rx_rings /= num_vfs;
		if ((bp->fw_cap & BNXT_FW_CAP_VF_RESV_VNICS_MAXVFS) &&
		    vf_vnics >= pf->max_vfs) {
			/* Take into account that FW has reserved 1 VNIC for each pf->max_vfs */
			vf_vnics = (vf_vnics - pf->max_vfs + num_vfs) / num_vfs;
		} else {
			vf_vnics /= num_vfs;
		}
		vf_stat_ctx /= num_vfs;
		vf_ring_grps /= num_vfs;
		vf_rss /= num_vfs;

		vf_vnics = min_t(u16, vf_vnics, vf_rx_rings);
		req->min_cmpl_rings = cpu_to_le16(vf_cp_rings);
		req->min_tx_rings = cpu_to_le16(vf_tx_rings);
		req->min_rx_rings = cpu_to_le16(vf_rx_rings);
		req->min_l2_ctxs = cpu_to_le16(BNXT_VF_MAX_L2_CTX);
		req->min_vnics = cpu_to_le16(vf_vnics);
		req->min_stat_ctx = cpu_to_le16(vf_stat_ctx);
		req->min_hw_ring_grps = cpu_to_le16(vf_ring_grps);
		req->min_rsscos_ctx = cpu_to_le16(vf_rss);
	}
	req->max_cmpl_rings = cpu_to_le16(vf_cp_rings);
	req->max_tx_rings = cpu_to_le16(vf_tx_rings);
	req->max_rx_rings = cpu_to_le16(vf_rx_rings);
	req->max_l2_ctxs = cpu_to_le16(BNXT_VF_MAX_L2_CTX);
	req->max_vnics = cpu_to_le16(vf_vnics);
	req->max_stat_ctx = cpu_to_le16(vf_stat_ctx);
	req->max_hw_ring_grps = cpu_to_le16(vf_ring_grps);
	req->max_rsscos_ctx = cpu_to_le16(vf_rss);
	if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
		req->max_msix = cpu_to_le16(vf_msix / num_vfs);

	hwrm_req_hold(bp, req);
	for (i = 0; i < num_vfs; i++) {
		struct bnxt_vf_info *vf = &pf->vf[i];

		vf->fw_fid = pf->first_vf_id + i;
		if (bnxt_set_vf_link_admin_state(bp, i)) {
			rc = -EIO;
			break;
		}

		if (reset) {
			rc = __bnxt_set_vf_params(bp, i);
			if (rc)
				break;
		}

		req->vf_id = cpu_to_le16(vf->fw_fid);
		rc = hwrm_req_send(bp, req);
		if (rc)
			break;
		pf->active_vfs = i + 1;
		vf->min_tx_rings = le16_to_cpu(req->min_tx_rings);
		vf->max_tx_rings = vf_tx_rings;
		vf->min_rx_rings = le16_to_cpu(req->min_rx_rings);
		vf->max_rx_rings = vf_rx_rings;
		vf->min_cp_rings = le16_to_cpu(req->min_cmpl_rings);
		vf->min_stat_ctxs = le16_to_cpu(req->min_stat_ctx);
		vf->min_ring_grps = le16_to_cpu(req->min_hw_ring_grps);
		vf->min_vnics = le16_to_cpu(req->min_vnics);
	}

	if (pf->active_vfs) {
		u16 n = pf->active_vfs;

		hw_resc->max_tx_rings -= le16_to_cpu(req->min_tx_rings) * n;
		hw_resc->max_rx_rings -= le16_to_cpu(req->min_rx_rings) * n;
		hw_resc->max_hw_ring_grps -=
			le16_to_cpu(req->min_hw_ring_grps) * n;
		hw_resc->max_cp_rings -= le16_to_cpu(req->min_cmpl_rings) * n;
		hw_resc->max_rsscos_ctxs -=
			le16_to_cpu(req->min_rsscos_ctx) * n;
		hw_resc->max_stat_ctxs -= le16_to_cpu(req->min_stat_ctx) * n;
		hw_resc->max_vnics -= le16_to_cpu(req->min_vnics) * n;
		if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
			hw_resc->max_nqs -= vf_msix;

		memcpy(&bp->vf_resc_cfg_input, req, sizeof(*req));
		rc = pf->active_vfs;
	}
	hwrm_req_drop(bp, req);
	return rc;
}

/* Only called by PF to reserve resources for VFs, returns actual number of
 * VFs configured, or < 0 on error.
 */
static int bnxt_hwrm_func_cfg(struct bnxt *bp, int num_vfs)
{
	u16 vf_tx_rings, vf_rx_rings, vf_cp_rings, vf_stat_ctx, vf_vnics;
	struct bnxt_hw_resc *hw_resc = &bp->hw_resc;
	struct bnxt_pf_info *pf = &bp->pf;
	struct hwrm_func_cfg_input *req;
	int total_vf_tx_rings = 0;
	u16 vf_ring_grps;
	u32 rc, mtu, i;

	rc = bnxt_hwrm_func_cfg_short_req_init(bp, &req);
	if (rc)
		return rc;

	/* Remaining rings are distributed equally amongs VF's for now */
	vf_cp_rings = bnxt_get_avail_cp_rings_for_en(bp) / num_vfs;
	vf_stat_ctx = bnxt_get_avail_stat_ctxs_for_en(bp) / num_vfs;
	if (bp->flags & BNXT_FLAG_AGG_RINGS)
		vf_rx_rings = (hw_resc->max_rx_rings - bp->rx_nr_rings * 2) /
			      num_vfs;
	else
		vf_rx_rings = (hw_resc->max_rx_rings - bp->rx_nr_rings) /
			      num_vfs;
	vf_ring_grps = (hw_resc->max_hw_ring_grps - bp->rx_nr_rings) / num_vfs;
	vf_tx_rings = (hw_resc->max_tx_rings - bp->tx_nr_rings) / num_vfs;
	vf_vnics = (hw_resc->max_vnics - bp->nr_vnics) / num_vfs;
	vf_vnics = min_t(u16, vf_vnics, vf_rx_rings);

	req->enables = cpu_to_le32(FUNC_CFG_REQ_ENABLES_ADMIN_MTU |
				   FUNC_CFG_REQ_ENABLES_MRU |
				   FUNC_CFG_REQ_ENABLES_NUM_RSSCOS_CTXS |
				   FUNC_CFG_REQ_ENABLES_NUM_STAT_CTXS |
				   FUNC_CFG_REQ_ENABLES_NUM_CMPL_RINGS |
				   FUNC_CFG_REQ_ENABLES_NUM_TX_RINGS |
				   FUNC_CFG_REQ_ENABLES_NUM_RX_RINGS |
				   FUNC_CFG_REQ_ENABLES_NUM_L2_CTXS |
				   FUNC_CFG_REQ_ENABLES_NUM_VNICS |
				   FUNC_CFG_REQ_ENABLES_NUM_HW_RING_GRPS);

	if (bp->fw_cap & BNXT_FW_CAP_LINK_ADMIN) {
		req->options = FUNC_CFG_REQ_OPTIONS_LINK_ADMIN_STATE_AUTO;
		req->enables |=
			cpu_to_le32(FUNC_CFG_REQ_ENABLES_ADMIN_LINK_STATE);
	}

	mtu = bp->dev->mtu + ETH_HLEN + VLAN_HLEN;
	req->mru = cpu_to_le16(mtu);
	req->admin_mtu = cpu_to_le16(mtu);

	req->num_rsscos_ctxs = cpu_to_le16(1);
	req->num_cmpl_rings = cpu_to_le16(vf_cp_rings);
	req->num_tx_rings = cpu_to_le16(vf_tx_rings);
	req->num_rx_rings = cpu_to_le16(vf_rx_rings);
	req->num_hw_ring_grps = cpu_to_le16(vf_ring_grps);
	req->num_l2_ctxs = cpu_to_le16(4);

	req->num_vnics = cpu_to_le16(vf_vnics);
	/* FIXME spec currently uses 1 bit for stats ctx */
	req->num_stat_ctxs = cpu_to_le16(vf_stat_ctx);

	hwrm_req_hold(bp, req);
	for (i = 0; i < num_vfs; i++) {
		struct bnxt_vf_info *vf = &pf->vf[i];
		int vf_tx_rsvd = vf_tx_rings;

		req->fid = cpu_to_le16(pf->first_vf_id + i);
		rc = hwrm_req_send(bp, req);
		if (rc)
			break;
		pf->active_vfs = i + 1;
		vf->fw_fid = le16_to_cpu(req->fid);
		rc = __bnxt_hwrm_get_tx_rings(bp, vf->fw_fid, &vf_tx_rsvd);
		if (rc)
			break;
		total_vf_tx_rings += vf_tx_rsvd;
		vf->min_tx_rings = vf_tx_rsvd;
		vf->max_tx_rings = vf_tx_rsvd;
		vf->min_rx_rings = vf_rx_rings;
		vf->max_rx_rings = vf_rx_rings;
	}
	hwrm_req_drop(bp, req);
	if (pf->active_vfs) {
		hw_resc->max_tx_rings -= total_vf_tx_rings;
		hw_resc->max_rx_rings -= vf_rx_rings * num_vfs;
		hw_resc->max_hw_ring_grps -= vf_ring_grps * num_vfs;
		hw_resc->max_cp_rings -= vf_cp_rings * num_vfs;
		hw_resc->max_rsscos_ctxs -= num_vfs;
		hw_resc->max_stat_ctxs -= vf_stat_ctx * num_vfs;
		hw_resc->max_vnics -= vf_vnics * num_vfs;
		rc = pf->active_vfs;
	}
	return rc;
}

static int bnxt_func_cfg(struct bnxt *bp, int num_vfs, bool reset)
{
	if (BNXT_NEW_RM(bp))
		return bnxt_hwrm_func_vf_resc_cfg(bp, num_vfs, reset);
	else
		return bnxt_hwrm_func_cfg(bp, num_vfs);
}

int bnxt_cfg_hw_sriov(struct bnxt *bp, int *num_vfs, bool reset)
{
	int rc;

	/* Register buffers for VFs */
	rc = bnxt_hwrm_func_buf_rgtr(bp);
	if (rc)
		return rc;

	/* Reserve resources for VFs */
	rc = bnxt_func_cfg(bp, *num_vfs, reset);
	if (rc != *num_vfs) {
		if (rc <= 0) {
			netdev_warn(bp->dev, "Unable to reserve resources for SRIOV.\n");
			*num_vfs = 0;
			return rc;
		}
		netdev_warn(bp->dev, "Only able to reserve resources for %d VFs.\n", rc);
		*num_vfs = rc;
	}

	if (BNXT_RDMA_SRIOV_EN(bp) && BNXT_ROCE_VF_RESC_CAP(bp) &&
	    bnxt_ulp_registered(bp->edev))
		bnxt_hwrm_roce_sriov_cfg(bp, *num_vfs);

	return 0;
}

static int bnxt_get_msix_vec_per_vf(struct bnxt *bp, u32 *msix_per_vf)
{
	u16 bits = sizeof(*msix_per_vf);
	union bnxt_nvm_data *data;
	dma_addr_t data_dma_addr;
	u16 dim = 1;
	int rc;

	/* On older FW, this will be 0, in which case fetch it from NVM */
	if (bp->pf.max_msix_vfs) {
		*msix_per_vf = bp->pf.max_msix_vfs;
		return 0;
	}

	data = dma_zalloc_coherent(&bp->pdev->dev, sizeof(*data),
				   &data_dma_addr, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	rc = bnxt_hwrm_nvm_get_var(bp, data_dma_addr, NVM_OFF_MSIX_VEC_PER_VF,
				   dim, bp->pf.fw_fid - 1, bits);
	if (rc)
		*msix_per_vf = 1; /* At least 1 MSI-X per VF */
	else
		*msix_per_vf = le32_to_cpu(data->val32);

	dma_free_coherent(&bp->pdev->dev, sizeof(*data), data, data_dma_addr);

	return rc;
}

static int bnxt_sriov_enable(struct bnxt *bp, int *num_vfs)
{
	int rc = 0, vfs_supported;
	int min_rx_rings, min_tx_rings, min_rss_ctxs;
	struct bnxt_hw_resc *hw_resc = &bp->hw_resc;
	int tx_ok = 0, rx_ok = 0, rss_ok = 0;
	u32 nvm_cfg_msix_per_vf = 1;
	int avail_cp, avail_stat;

	/* Check if we can enable requested num of vf's. At a mininum
	 * we require 1 RX 1 TX rings for each VF. In this minimum conf
	 * features like TPA will not be available.
	 */
	vfs_supported = *num_vfs;

	avail_cp = bnxt_get_avail_cp_rings_for_en(bp);
	avail_stat = bnxt_get_avail_stat_ctxs_for_en(bp);
	avail_cp = min_t(int, avail_cp, avail_stat);

	/* Workaround for Thor HW issue (fixed in B2, so check
	 * for metal version < 2).
	 * Create only those many VFs with which NQ's/VF >= N.
	 * where, N = MSI-X table size advertised in the VF's PCIe configuration space
	 * Also, it is expected to be rounded to a multiple of 8 as that is how the HW
	 * is programmed
	 * Starting with 2.28, FW has implemented workaround to productize Thor SRIOV
	 * with Small VFs only(VF# 128 and above), while discontinuing use of Big VFs
	 * as the above HW bug is hit only when using Big VFs(first 128 VFs).
	 * FW indicates this via VF_SCALE_SUPPORTED bit in FW QCAPs
	 */
	if (BNXT_CHIP_THOR(bp) && bp->chip_rev == 1 &&
	    bp->ver_resp.chip_metal < 2 &&
	    !(bp->fw_cap & BNXT_FW_CAP_VF_SCALE_SUPPORTED)) {
		u32 max_vf_msix, max_vfs_possible;

		max_vf_msix = hw_resc->max_nqs - bnxt_min_nq_rings_in_use(bp);
		bnxt_get_msix_vec_per_vf(bp, &nvm_cfg_msix_per_vf);
		max_vfs_possible = round_down(max_vf_msix / nvm_cfg_msix_per_vf, 8);
		vfs_supported = min_t(u32, max_vfs_possible, vfs_supported);
	}

	while (vfs_supported) {
		min_rx_rings = vfs_supported;
		min_tx_rings = vfs_supported;
		min_rss_ctxs = vfs_supported;

		if (bp->flags & BNXT_FLAG_AGG_RINGS) {
			if (hw_resc->max_rx_rings - bp->rx_nr_rings * 2 >=
			    min_rx_rings)
				rx_ok = 1;
		} else {
			if (hw_resc->max_rx_rings - bp->rx_nr_rings >=
			    min_rx_rings)
				rx_ok = 1;
		}
		if ((hw_resc->max_vnics - bp->nr_vnics < min_rx_rings) ||
		    (avail_cp < min_rx_rings))
			rx_ok = 0;

		if ((hw_resc->max_tx_rings - bnxt_total_tx_rings(bp) >=
		     min_tx_rings) && (avail_cp >= min_tx_rings))
			tx_ok = 1;

		if (hw_resc->max_rsscos_ctxs - bp->rsscos_nr_ctxs >=
		    min_rss_ctxs)
			rss_ok = 1;

		if (tx_ok && rx_ok && rss_ok)
			break;

		vfs_supported--;
	}

	if (!vfs_supported) {
		netdev_err(bp->dev, "Cannot enable VF's as all resources are used by PF\n");
		return -EINVAL;
	}

	if (vfs_supported != *num_vfs) {
		netdev_info(bp->dev, "Requested VFs %d, can enable %d\n",
			    *num_vfs, vfs_supported);
		*num_vfs = vfs_supported;
	}

	rtnl_lock();
	if (!bnxt_ulp_registered(bp->edev)) {
		u16 max_nqs = hw_resc->max_nqs;

		if (netif_running(bp->dev)) {
			bp->sriov_cfg = false;
			bnxt_close_nic(bp, true, false);
			bp->sriov_cfg = true;
		}

		/* Reduce max NQs so that reserve ring do not see NQs
		 * available for ulp.
		 */
		if (bp->flags & BNXT_FLAG_CHIP_P5_PLUS)
			hw_resc->max_nqs = bnxt_min_nq_rings_in_use(bp);

		/* Tell reserve rings to consider reservation again */
		bnxt_set_ulp_msix_num(bp, 0);

		if (netif_running(bp->dev))
			rc = bnxt_open_nic(bp, true, false);
		hw_resc->max_nqs = max_nqs;
		if (rc) {
			rtnl_unlock();
			return rc;
		}
	}
	rtnl_unlock();

	rc = bnxt_alloc_vf_resources(bp, *num_vfs);
	if (rc)
		goto err_out1;

	rc = bnxt_cfg_hw_sriov(bp, num_vfs, false);
	if (rc)
		goto err_out2;

	rc = pci_enable_sriov(bp->pdev, *num_vfs);
	if (rc) {
		netdev_err(bp->dev, "pci_enable_sriov failed : %d\n", rc);
		goto err_out2;
	}

	rc = bnxt_create_vfs_sysfs(bp);
	if (rc)
		netdev_err(bp->dev, "Could not create SRIOV sysfs entries %d\n", rc);

	rc = bnxt_alloc_vf_stats_mem(bp);
	if (rc)
		netdev_dbg(bp->dev, "Failed to allocate VF stats memory\n");

	if (bp->eswitch_mode != DEVLINK_ESWITCH_MODE_SWITCHDEV)
		return 0;

	/* Create representors for VFs in switchdev mode */
	mutex_lock(&bp->vf_rep_lock);
	rc = bnxt_vf_reps_create(bp);
	mutex_unlock(&bp->vf_rep_lock);
	if (rc) {
		netdev_info(bp->dev, "Cannot enable VFs as representors cannot be created\n");
		goto err_out3;
	}

	return 0;

err_out3:
	bnxt_destroy_vfs_sysfs(bp);

	bnxt_free_vf_stats_mem(bp);

	/* Disable SR-IOV */
	pci_disable_sriov(bp->pdev);

err_out2:
	/* Free the resources reserved for various VF's */
	bnxt_hwrm_func_vf_resource_free(bp, *num_vfs);

	/* Restore the max resources */
	bnxt_hwrm_func_qcaps(bp, false);

err_out1:
	bnxt_free_vf_resources(bp);

	return rc;
}

void bnxt_sriov_disable(struct bnxt *bp)
{
	u16 num_vfs = pci_num_vf(bp->pdev);

	if (!num_vfs)
		return;

	bnxt_destroy_vfs_sysfs(bp);

	/* synchronize VF and VF-rep create and destroy
	 * and to protect the array of VF structures
	 */
	mutex_lock(&bp->vf_rep_lock);
	bnxt_vf_reps_destroy(bp);
	mutex_unlock(&bp->vf_rep_lock);

	/* Free VF stats mem after destroying VF-reps */
	bnxt_free_vf_stats_mem(bp);

	if (bnxt_tc_flower_enabled(bp))
		bnxt_tc_flush_flows(bp);

	if (pci_vfs_assigned(bp->pdev)) {
		bnxt_hwrm_fwd_async_event_cmpl(
			bp, NULL, ASYNC_EVENT_CMPL_EVENT_ID_PF_DRVR_UNLOAD);
		netdev_warn(bp->dev, "Unable to free %d VFs because some are assigned to VMs.\n",
			    num_vfs);
	} else {
		pci_disable_sriov(bp->pdev);
		/* Free the HW resources reserved for various VF's */
		bnxt_hwrm_func_vf_resource_free(bp, num_vfs);
	}

	bnxt_free_vf_resources(bp);

	/* Reclaim all resources for the PF. */
	rtnl_lock();
	bnxt_set_dflt_ulp_stat_ctxs(bp);
	bnxt_restore_pf_fw_resources(bp);
	rtnl_unlock();
}

int bnxt_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnxt *bp = netdev_priv(dev);
	int rc = 0;

	rtnl_lock();
	if (!netif_running(dev)) {
		netdev_warn(dev, "Reject SRIOV config request since if is down!\n");
		rtnl_unlock();
		return 0;
	}
	if (test_bit(BNXT_STATE_IN_FW_RESET, &bp->state)) {
		netdev_warn(dev, "Reject SRIOV config request when FW reset is in progress\n");
		rtnl_unlock();
		return 0;
	}
	bp->sriov_cfg = true;
	rtnl_unlock();

	if (pci_vfs_assigned(bp->pdev)) {
		netdev_warn(dev, "Unable to configure SRIOV since some VFs are assigned to VMs.\n");
		num_vfs = 0;
		goto sriov_cfg_exit;
	}

	/* Check if enabled VFs is same as requested */
	if (num_vfs && num_vfs == bp->pf.active_vfs)
		goto sriov_cfg_exit;

	/* if there are previous existing VFs, clean them up */
	bnxt_sriov_disable(bp);
	if (!num_vfs)
		goto sriov_cfg_exit;

	rc = bnxt_sriov_enable(bp, &num_vfs);

sriov_cfg_exit:
	bp->sriov_cfg = false;
	wake_up(&bp->sriov_cfg_wait);

	return rc ? rc : num_vfs;
}

#ifndef PCIE_SRIOV_CONFIGURE

static struct workqueue_struct *bnxt_iov_wq;

void bnxt_sriov_init(unsigned int num_vfs)
{
	if (num_vfs)
		bnxt_iov_wq = create_singlethread_workqueue("bnxt_iov_wq");
}

void bnxt_sriov_exit(void)
{
	if (bnxt_iov_wq)
		destroy_workqueue(bnxt_iov_wq);
	bnxt_iov_wq = NULL;
}

static void bnxt_iov_task(struct work_struct *work)
{
	struct bnxt *bp;

	bp = container_of(work, struct bnxt, iov_task);
	bnxt_sriov_configure(bp->pdev, bp->req_vfs);
}

void bnxt_start_sriov(struct bnxt *bp, int num_vfs)
{
	int pos, req_vfs;

	if (!num_vfs || !BNXT_PF(bp))
		return;

	pos = pci_find_ext_capability(bp->pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos) {
		return;
	} else {
		u16 t_vf = 0;

		pci_read_config_word(bp->pdev, pos + PCI_SRIOV_TOTAL_VF, &t_vf);
		req_vfs = min_t(int, num_vfs, (int)t_vf);
	}

	if (!bnxt_iov_wq) {
		netdev_warn(bp->dev, "Work queue not available to start SRIOV\n");
		return;
	}
	bp->req_vfs = req_vfs;
	INIT_WORK(&bp->iov_task, bnxt_iov_task);
	queue_work(bnxt_iov_wq, &bp->iov_task);
}
#endif

static int bnxt_hwrm_fwd_resp(struct bnxt *bp, struct bnxt_vf_info *vf,
			      void *encap_resp, __le64 encap_resp_addr,
			      __le16 encap_resp_cpr, u32 msg_size)
{
	struct hwrm_fwd_resp_input *req;
	int rc;

	if (BNXT_FWD_RESP_SIZE_ERR(msg_size)) {
		netdev_warn_once(bp->dev, "HWRM fwd response too big (%d bytes)\n",
				 msg_size);
		return -EINVAL;
	}

	rc = hwrm_req_init(bp, req, HWRM_FWD_RESP);
	if (!rc) {
		/* Set the new target id */
		req->target_id = cpu_to_le16(vf->fw_fid);
		req->encap_resp_target_id = cpu_to_le16(vf->fw_fid);
		req->encap_resp_len = cpu_to_le16(msg_size);
		req->encap_resp_addr = encap_resp_addr;
		req->encap_resp_cmpl_ring = encap_resp_cpr;
		memcpy(req->encap_resp, encap_resp, msg_size);

		rc = hwrm_req_send(bp, req);
	}
	if (rc)
		netdev_err(bp->dev, "hwrm_fwd_resp failed. rc:%d\n", rc);
	return rc;
}

static int bnxt_hwrm_fwd_err_resp(struct bnxt *bp, struct bnxt_vf_info *vf,
				  u32 msg_size)
{
	struct hwrm_reject_fwd_resp_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_REJECT_FWD_RESP);
	if (!rc) {
		if (msg_size > sizeof(req->encap_request))
			msg_size = sizeof(req->encap_request);

		/* Set the new target id */
		req->target_id = cpu_to_le16(vf->fw_fid);
		req->encap_resp_target_id = cpu_to_le16(vf->fw_fid);
		memcpy(req->encap_request, vf->hwrm_cmd_req_addr, msg_size);

		rc = hwrm_req_send(bp, req);
	}
	if (rc)
		netdev_err(bp->dev, "hwrm_fwd_err_resp failed. rc:%d\n", rc);
	return rc;
}

static int bnxt_hwrm_exec_fwd_resp(struct bnxt *bp, struct bnxt_vf_info *vf,
				   u32 msg_size)
{
	struct hwrm_exec_fwd_resp_input *req;
	int rc;

	if (BNXT_EXEC_FWD_RESP_SIZE_ERR(msg_size))
		return bnxt_hwrm_fwd_err_resp(bp, vf, msg_size);

	rc = hwrm_req_init(bp, req, HWRM_EXEC_FWD_RESP);
	if (!rc) {
		/* Set the new target id */
		req->target_id = cpu_to_le16(vf->fw_fid);
		req->encap_resp_target_id = cpu_to_le16(vf->fw_fid);
		memcpy(req->encap_request, vf->hwrm_cmd_req_addr, msg_size);

		rc = hwrm_req_send(bp, req);
	}
	if (rc)
		netdev_err(bp->dev, "hwrm_exec_fw_resp failed. rc:%d\n", rc);
	return rc;
}

static int bnxt_vf_configure_mac(struct bnxt *bp, struct bnxt_vf_info *vf)
{
	u32 msg_size = sizeof(struct hwrm_func_vf_cfg_input);
	struct hwrm_func_vf_cfg_input *req =
		(struct hwrm_func_vf_cfg_input *)vf->hwrm_cmd_req_addr;

	/* Allow VF to set a valid MAC address, if trust is set to on or
	 * if the PF assigned MAC address is zero
	 */
	if (req->enables & cpu_to_le32(FUNC_VF_CFG_REQ_ENABLES_DFLT_MAC_ADDR)) {
		bool trust = bnxt_is_trusted_vf(bp, vf);

		if (is_valid_ether_addr(req->dflt_mac_addr) &&
		    (trust || !is_valid_ether_addr(vf->mac_addr) ||
		     ether_addr_equal(req->dflt_mac_addr, vf->mac_addr))) {
			ether_addr_copy(vf->vf_mac_addr, req->dflt_mac_addr);
			return bnxt_hwrm_exec_fwd_resp(bp, vf, msg_size);
		}
		return bnxt_hwrm_fwd_err_resp(bp, vf, msg_size);
	}
	return bnxt_hwrm_exec_fwd_resp(bp, vf, msg_size);
}

static int bnxt_vf_validate_set_mac(struct bnxt *bp, struct bnxt_vf_info *vf)
{
	u32 msg_size = sizeof(struct hwrm_cfa_l2_filter_alloc_input);
	struct hwrm_cfa_l2_filter_alloc_input *req =
		(struct hwrm_cfa_l2_filter_alloc_input *)vf->hwrm_cmd_req_addr;
	bool mac_ok = false;

	if (!is_valid_ether_addr((const u8 *)req->l2_addr))
		return bnxt_hwrm_fwd_err_resp(bp, vf, msg_size);

	/* Allow VF to set a valid MAC address, if trust is set to on.
	 * Or VF MAC address must first match MAC address in PF's context.
	 * Otherwise, it must match the VF MAC address if firmware spec >=
	 * 1.2.2
	 */
	if (bnxt_is_trusted_vf(bp, vf)) {
		mac_ok = true;
	} else if (is_valid_ether_addr(vf->mac_addr)) {
		if (ether_addr_equal((const u8 *)req->l2_addr, vf->mac_addr))
			mac_ok = true;
	} else if (is_valid_ether_addr(vf->vf_mac_addr)) {
		if (ether_addr_equal((const u8 *)req->l2_addr, vf->vf_mac_addr))
			mac_ok = true;
	} else {
		/* There are two cases:
		 * 1.If firmware spec < 0x10202,VF MAC address is not forwarded
		 *   to the PF and so it doesn't have to match
		 * 2.Allow VF to modify it's own MAC when PF has not assigned a
		 *   valid MAC address and firmware spec >= 0x10202
		 */
		mac_ok = true;
	}
	if (mac_ok)
		return bnxt_hwrm_exec_fwd_resp(bp, vf, msg_size);

	return bnxt_hwrm_fwd_err_resp(bp, vf, msg_size);
}

static int bnxt_vf_set_link(struct bnxt *bp, struct bnxt_vf_info *vf)
{
	int rc = 0;

	if (!(vf->flags & BNXT_VF_LINK_FORCED)) {
		/* real link */
		rc = bnxt_hwrm_exec_fwd_resp(
			bp, vf, sizeof(struct hwrm_port_phy_qcfg_input));
	} else {
		struct hwrm_port_phy_qcfg_output_compat phy_qcfg_resp;
		struct hwrm_port_phy_qcfg_input *phy_qcfg_req;

		phy_qcfg_req =
		(struct hwrm_port_phy_qcfg_input *)vf->hwrm_cmd_req_addr;
		mutex_lock(&bp->link_lock);
		memcpy(&phy_qcfg_resp, &bp->link_info.phy_qcfg_resp,
		       sizeof(phy_qcfg_resp));
		mutex_unlock(&bp->link_lock);
		phy_qcfg_resp.resp_len = cpu_to_le16(sizeof(phy_qcfg_resp));
		phy_qcfg_resp.seq_id = phy_qcfg_req->seq_id;
		phy_qcfg_resp.option_flags &=
			~PORT_PHY_QCAPS_RESP_FLAGS2_SPEEDS2_SUPPORTED;
		phy_qcfg_resp.valid = 1;

		if (vf->flags & BNXT_VF_LINK_UP) {
			/* if physical link is down, force link up on VF */
			if (phy_qcfg_resp.link !=
			    PORT_PHY_QCFG_RESP_LINK_LINK) {
				phy_qcfg_resp.link =
					PORT_PHY_QCFG_RESP_LINK_LINK;
				phy_qcfg_resp.link_speed = cpu_to_le16(
					PORT_PHY_QCFG_RESP_LINK_SPEED_10GB);
				phy_qcfg_resp.duplex_cfg =
					PORT_PHY_QCFG_RESP_DUPLEX_CFG_FULL;
				phy_qcfg_resp.duplex_state =
					PORT_PHY_QCFG_RESP_DUPLEX_STATE_FULL;
				phy_qcfg_resp.pause =
					(PORT_PHY_QCFG_RESP_PAUSE_TX |
					 PORT_PHY_QCFG_RESP_PAUSE_RX);
			}
		} else {
			/* force link down */
			phy_qcfg_resp.link = PORT_PHY_QCFG_RESP_LINK_NO_LINK;
			phy_qcfg_resp.link_speed = 0;
			phy_qcfg_resp.duplex_state =
				PORT_PHY_QCFG_RESP_DUPLEX_STATE_HALF;
			phy_qcfg_resp.pause = 0;
		}
		rc = bnxt_hwrm_fwd_resp(bp, vf, &phy_qcfg_resp,
					phy_qcfg_req->resp_addr,
					phy_qcfg_req->cmpl_ring,
					sizeof(phy_qcfg_resp));
	}
	return rc;
}

static int bnxt_hwrm_oem_cmd(struct bnxt *bp, struct bnxt_vf_info *vf)
{
	struct hwrm_oem_cmd_input *oem_cmd = vf->hwrm_cmd_req_addr;
	struct hwrm_oem_cmd_output oem_out = { 0 };
	struct tfc *tfcp = bp->tfp;
	int rc = 0;

	if (oem_cmd->oem_id == 0x14e4 &&
	    oem_cmd->naming_authority == OEM_CMD_REQ_NAMING_AUTHORITY_PCI_SIG &&
	    oem_cmd->message_family == OEM_CMD_REQ_MESSAGE_FAMILY_TRUFLOW) {
		uint16_t oem_data_len = sizeof(oem_out.oem_data);
		uint16_t resp_len = oem_data_len;
		uint32_t resp[18] = { 0 };

		rc = tfc_oem_cmd_process(tfcp, oem_cmd->oem_data, resp, &resp_len);
		if (rc) {
			netdev_dbg(bp->dev,
				   "OEM cmd process error id 0x%x, name 0x%x, family 0x%x rc %d\n",
				   oem_cmd->oem_id, oem_cmd->naming_authority,
				   oem_cmd->message_family, rc);
			return rc;
		}

		oem_out.error_code = 0;
		oem_out.req_type = oem_cmd->req_type;
		oem_out.seq_id = oem_cmd->seq_id;
		oem_out.resp_len = cpu_to_le16(sizeof(oem_out));
		oem_out.oem_id = oem_cmd->oem_id;
		oem_out.naming_authority = oem_cmd->naming_authority;
		oem_out.message_family = oem_cmd->message_family;
		memcpy(oem_out.oem_data, resp, resp_len);
		oem_out.valid = 1;

		rc = bnxt_hwrm_fwd_resp(bp, vf, &oem_out, oem_cmd->resp_addr,
					oem_cmd->cmpl_ring, oem_out.resp_len);
		if (rc)
			netdev_dbg(bp->dev, "Failed to send HWRM_FWD_RESP VF 0x%p rc %d\n", vf, rc);
	} else {
		netdev_dbg(bp->dev, "Unsupported OEM cmd id 0x%x, name 0x%x, family 0x%x\n",
			   oem_cmd->oem_id, oem_cmd->naming_authority, oem_cmd->message_family);
		rc = -EOPNOTSUPP;
	}

	return rc;
}

int bnxt_hwrm_tf_oem_cmd(struct bnxt *bp, u32 *in, u16 in_len, u32 *out, u16 out_len)
{
	struct hwrm_oem_cmd_output *resp;
	struct hwrm_oem_cmd_input *req;
	int rc = 0;

	if (!BNXT_VF(bp)) {
		netdev_dbg(bp->dev, "Not a VF. Command not supported\n");
		return -EOPNOTSUPP;
	}

	rc = hwrm_req_init(bp, req, HWRM_OEM_CMD);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	req->oem_id = cpu_to_le32(0x14e4);
	req->naming_authority = OEM_CMD_REQ_NAMING_AUTHORITY_PCI_SIG;
	req->message_family = OEM_CMD_REQ_MESSAGE_FAMILY_TRUFLOW;
	memcpy(req->oem_data, in, in_len);

	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	if (resp->oem_id == 0x14e4 &&
	    resp->naming_authority == OEM_CMD_REQ_NAMING_AUTHORITY_PCI_SIG &&
	    resp->message_family == OEM_CMD_REQ_MESSAGE_FAMILY_TRUFLOW)
		memcpy(out, resp->oem_data, out_len);

cleanup:
	hwrm_req_drop(bp, req);
	return rc;
}

static int bnxt_vf_req_validate_snd(struct bnxt *bp, struct bnxt_vf_info *vf)
{
	int rc = 0;
	struct input *encap_req = vf->hwrm_cmd_req_addr;
	u32 req_type = le16_to_cpu(encap_req->req_type);

	switch (req_type) {
	case HWRM_FUNC_VF_CFG:
		rc = bnxt_vf_configure_mac(bp, vf);
		break;
	case HWRM_CFA_L2_FILTER_ALLOC:
		rc = bnxt_vf_validate_set_mac(bp, vf);
		break;
	case HWRM_OEM_CMD:
		rc = bnxt_hwrm_oem_cmd(bp, vf);
		break;
	case HWRM_FUNC_CFG:
		/* TODO Validate if VF is allowed to change mac address,
		 * mtu, num of rings etc
		 */
		rc = bnxt_hwrm_exec_fwd_resp(
			bp, vf, sizeof(struct hwrm_func_cfg_input));
		break;
	case HWRM_PORT_PHY_QCFG:
		rc = bnxt_vf_set_link(bp, vf);
		break;
	default:
		rc = bnxt_hwrm_fwd_err_resp(bp, vf, bp->hwrm_max_req_len);
		break;
	}
	return rc;
}

void bnxt_hwrm_exec_fwd_req(struct bnxt *bp)
{
	u32 i = 0, active_vfs = bp->pf.active_vfs, vf_id;

	/* Scan through VF's and process commands */
	while (1) {
		vf_id = find_next_bit(bp->pf.vf_event_bmap, active_vfs, i);
		if (vf_id >= active_vfs)
			break;

		clear_bit(vf_id, bp->pf.vf_event_bmap);
		bnxt_vf_req_validate_snd(bp, &bp->pf.vf[vf_id]);
		i = vf_id + 1;
	}
}

int bnxt_approve_mac(struct bnxt *bp, const u8 *mac, bool strict)
{
	struct hwrm_func_vf_cfg_input *req;
	int rc = 0;

	if (!BNXT_VF(bp))
		return 0;

	if (bp->hwrm_spec_code < 0x10202) {
		if (is_valid_ether_addr(bp->vf.mac_addr))
			rc = -EADDRNOTAVAIL;
		goto mac_done;
	}

	rc = hwrm_req_init(bp, req, HWRM_FUNC_VF_CFG);
	if (rc)
		goto mac_done;

	req->enables = cpu_to_le32(FUNC_VF_CFG_REQ_ENABLES_DFLT_MAC_ADDR);
	memcpy(req->dflt_mac_addr, mac, ETH_ALEN);
	if (!strict)
		hwrm_req_flags(bp, req, BNXT_HWRM_CTX_SILENT);
	rc = hwrm_req_send(bp, req);
mac_done:
	if (rc && strict) {
		rc = -EADDRNOTAVAIL;
		netdev_warn(bp->dev, "VF MAC address %pM not approved by the PF\n",
			    mac);
		return rc;
	}
	return 0;
}

void bnxt_update_vf_mac(struct bnxt *bp)
{
	struct hwrm_func_qcaps_output *resp;
	struct hwrm_func_qcaps_input *req;
	bool inform_pf = false;

	if (hwrm_req_init(bp, req, HWRM_FUNC_QCAPS))
		return;

	req->fid = cpu_to_le16(0xffff);

	resp = hwrm_req_hold(bp, req);
	if (hwrm_req_send(bp, req))
		goto update_vf_mac_exit;

	/* Store MAC address from the firmware.  There are 2 cases:
	 * 1. MAC address is valid.  It is assigned from the PF and we
	 *    need to override the current VF MAC address with it.
	 * 2. MAC address is zero.  The VF will use a random MAC address by
	 *    default but the stored zero MAC will allow the VF user to change
	 *    the random MAC address using ndo_set_mac_address() if he wants.
	 */
	if (!ether_addr_equal(resp->mac_address, bp->vf.mac_addr)) {
		memcpy(bp->vf.mac_addr, resp->mac_address, ETH_ALEN);
		/* This means we are now using our own MAC address, let
		 * the PF know about this MAC address.
		 */
		if (!is_valid_ether_addr(bp->vf.mac_addr))
			inform_pf = true;
	}

	/* overwrite netdev dev_addr with admin VF MAC */
	if (is_valid_ether_addr(bp->vf.mac_addr))
		eth_hw_addr_set(bp->dev, bp->vf.mac_addr);
update_vf_mac_exit:
	hwrm_req_drop(bp, req);
	if (inform_pf)
		bnxt_approve_mac(bp, bp->dev->dev_addr, false);
}

void bnxt_update_vf_vnic(struct bnxt *bp, u32 vf_idx, u32 state)
{
	struct bnxt_pf_info *pf = &bp->pf;
	struct bnxt_vf_info *vf;

	rcu_read_lock();
	vf = rcu_dereference(pf->vf);
	if (vf) {
		vf = &vf[vf_idx];
		if (state == EVENT_DATA1_VNIC_CHNG_VNIC_STATE_ALLOC)
			vf->vnic_state_pending = 1;
		else if (state == EVENT_DATA1_VNIC_CHNG_VNIC_STATE_FREE)
			vf->vnic_state_pending = 0;
	}
	rcu_read_unlock();
}

void bnxt_commit_vf_vnic(struct bnxt *bp, u32 vf_idx)
{
	struct bnxt_pf_info *pf = &bp->pf;
	struct bnxt_vf_info *vf;

	rcu_read_lock();
	vf = rcu_dereference(pf->vf);
	if (vf) {
		vf = &vf[vf_idx];
		vf->vnic_state = vf->vnic_state_pending;
	}
	rcu_read_unlock();
}

bool bnxt_vf_vnic_state_is_up(struct bnxt *bp, u32 vf_idx)
{
	struct bnxt_pf_info *pf = &bp->pf;
	struct bnxt_vf_info *vf = vf;
	bool up = false;

	rcu_read_lock();
	vf = rcu_dereference(pf->vf);
	if (vf)
		up = !!vf[vf_idx].vnic_state;
	rcu_read_unlock();
	return up;
}

bool bnxt_vf_cfg_change(struct bnxt *bp, u16 vf_id, u32 data1)
{
	struct bnxt_pf_info *pf = &bp->pf;
	struct bnxt_vf_info *vf;
	bool rc = false;
	u16 vf_idx;

	if (!(data1 &
	      ASYNC_EVENT_CMPL_VF_CFG_CHANGE_EVENT_DATA1_TRUSTED_VF_CFG_CHANGE))
		return false;

	rcu_read_lock();
	vf_idx = vf_id - pf->first_vf_id;
	vf = rcu_dereference(pf->vf);
	if (vf && vf_idx < pf->active_vfs) {
		vf[vf_idx].cfg_change = 1;
		rc = true;
	}
	rcu_read_unlock();
	return rc;
}

void bnxt_update_vf_cfg(struct bnxt *bp)
{
	struct bnxt_pf_info *pf = &bp->pf;
	struct bnxt_vf_info *vf;
	int i, num_vfs;

	mutex_lock(&bp->sriov_lock);
	num_vfs = pf->active_vfs;
	if (!num_vfs)
		goto vf_cfg_done;

	vf = rcu_dereference_protected(bp->pf.vf,
				       lockdep_is_held(&bp->sriov_lock));
	for (i = 0; i < num_vfs; i++) {
		if (vf[i].cfg_change) {
			vf[i].cfg_change = 0;
			bnxt_hwrm_func_qcfg_flags(bp, &vf[i]);
		}
	}
vf_cfg_done:
	mutex_unlock(&bp->sriov_lock);
}

void bnxt_reset_vf_stats(struct bnxt *bp)
{
	struct bnxt_vf_info *vfp;
	struct bnxt_vf_info *vf;
	int num_vfs;
	int vf_idx;
	int len;
	u64 *sw;

	mutex_lock(&bp->sriov_lock);

	vf = rcu_dereference_protected(bp->pf.vf,
				       lockdep_is_held(&bp->sriov_lock));
	if (!vf) {
		mutex_unlock(&bp->sriov_lock);
		return;
	}

	num_vfs = bp->pf.active_vfs;
	len = vf[0].stats.len;

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vfp = &vf[vf_idx];
		if (vfp->vnic_state)	/* !free */
			continue;

		sw = vfp->stats.sw_stats;
		if (!sw)
			continue;

		memset(sw, 0, len);
	}
	mutex_unlock(&bp->sriov_lock);
}

#else

int bnxt_cfg_hw_sriov(struct bnxt *bp, int *num_vfs, bool reset)
{
	if (*num_vfs)
		return -EOPNOTSUPP;
	return 0;
}

void bnxt_sriov_disable(struct bnxt *bp)
{
}

void bnxt_hwrm_exec_fwd_req(struct bnxt *bp)
{
	netdev_err(bp->dev, "Invalid VF message received when SRIOV is not enable\n");
}

void bnxt_update_vf_mac(struct bnxt *bp)
{
}

int bnxt_approve_mac(struct bnxt *bp, const u8 *mac, bool strict)
{
	return 0;
}

void bnxt_update_vf_vnic(struct bnxt *bp, u32 vf_idx, u32 state)
{
}

void bnxt_commit_vf_vnic(struct bnxt *bp, u32 vf_idx)
{
}

bool bnxt_vf_vnic_state_is_up(struct bnxt *bp, u32 vf_idx)
{
	return false;
}

bool bnxt_vf_cfg_change(struct bnxt *bp, u16 vf_id, u32 data1)
{
	return false;
}

static void bnxt_update_vf_cfg(struct bnxt *bp)
{
}

void bnxt_reset_vf_stats(struct bnxt *bp)
{
}
#endif
