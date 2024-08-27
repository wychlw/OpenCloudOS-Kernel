/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2022-2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "bnxt_compat.h"
#include "bnxt_hsi.h"
#include "bnxt.h"
#include "bnxt_mpc.h"
#include "bnxt_ktls.h"
#include "bnxt_tfc.h"

void bnxt_alloc_mpc_info(struct bnxt *bp, u8 mpc_chnls_cap)
{
	if (mpc_chnls_cap) {
		if (!bp->mpc_info)
			bp->mpc_info = kzalloc(sizeof(*bp->mpc_info),
					       GFP_KERNEL);
	} else {
		bnxt_free_mpc_info(bp);
	}
	if (bp->mpc_info)
		bp->mpc_info->mpc_chnls_cap = mpc_chnls_cap;
}

void bnxt_free_mpc_info(struct bnxt *bp)
{
	kfree(bp->mpc_info);
	bp->mpc_info = NULL;
}

int bnxt_mpc_tx_rings_in_use(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i, mpc_tx = 0;

	if (!mpc)
		return 0;
	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++)
		mpc_tx += mpc->mpc_ring_count[i];
	return mpc_tx;
}

int bnxt_mpc_cp_rings_in_use(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;

	if (!mpc)
		return 0;
	return mpc->mpc_cp_rings;
}

bool bnxt_napi_has_mpc(struct bnxt *bp, int i)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	struct bnxt_napi *bnapi = bp->bnapi[i];
	struct bnxt_tx_ring_info *txr;

	if (!mpc)
		return false;

	txr = bnapi->tx_ring[0];
	if (txr && !(bnapi->flags & BNXT_NAPI_FLAG_XDP))
		return txr->txq_index < mpc->mpc_cp_rings;
	return false;
}

void bnxt_set_mpc_cp_ring(struct bnxt *bp, int bnapi_idx,
			  struct bnxt_cp_ring_info *cpr)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	struct bnxt_napi *bnapi;
	int i, j;

	bnapi = bp->bnapi[bnapi_idx];
	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		int num = mpc->mpc_ring_count[i];

		for (j = 0; j < num; j++) {
			struct bnxt_tx_ring_info *txr = &mpc->mpc_rings[i][j];

			if (txr->bnapi == bnapi) {
				txr->tx_cpr = cpr;
				txr->tx_napi_idx = i;
				bnapi->tx_mpc_ring[i] = txr;
				break;
			}
		}
	}
	cpr->cp_ring_type = BNXT_NQ_HDL_TYPE_MP;
}

void bnxt_trim_mpc_rings(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int max = bp->tx_nr_rings_per_tc;
	u8 max_cp = 0;
	int i;

	if (!mpc)
		return;

	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		mpc->mpc_ring_count[i] = min_t(u8, mpc->mpc_ring_count[i], max);
		max_cp = max(max_cp, mpc->mpc_ring_count[i]);
	}
	mpc->mpc_cp_rings = max_cp;
}

enum bnxt_mpc_type {
	BNXT_MPC_CRYPTO,
	BNXT_MPC_CFA,
};

static void __bnxt_set_dflt_mpc_rings(struct bnxt *bp, enum bnxt_mpc_type type,
				      int *avail, int avail_cp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int dflt1, dflt2;
	int idx1, idx2;
	int min1, min2;
	int val1, val2;

	if (type == BNXT_MPC_CRYPTO) {
		min1 = BNXT_MIN_MPC_TCE;
		min2 = BNXT_MIN_MPC_RCE;
		dflt1 = BNXT_DFLT_MPC_TCE;
		dflt2 = BNXT_DFLT_MPC_RCE;
		idx1 = BNXT_MPC_TCE_TYPE;
		idx2 = BNXT_MPC_RCE_TYPE;
	} else {
		min1 = BNXT_MIN_MPC_TE_CFA;
		min2 = BNXT_MIN_MPC_RE_CFA;
		dflt1 = BNXT_DFLT_MPC_TE_CFA;
		dflt2 = BNXT_DFLT_MPC_RE_CFA;
		idx1 = BNXT_MPC_TE_CFA_TYPE;
		idx2 = BNXT_MPC_RE_CFA_TYPE;
	}
	if (*avail < (min1 + min2))
		return;

	val1 = min_t(int, *avail / 2, bp->tx_nr_rings_per_tc);
	val2 = val1;

	val1 = min_t(int, val1, dflt1);
	val2 = min_t(int, val2, dflt2);

	if (avail_cp < min1 || avail_cp < min2)
		return;

	val1 = min(val1, avail_cp);
	val2 = min(val2, avail_cp);

	mpc->mpc_ring_count[idx1] = val1;
	mpc->mpc_ring_count[idx2] = val2;

	*avail = *avail - val1 - val2;
}

void bnxt_set_dflt_mpc_rings(struct bnxt *bp)
{
	struct bnxt_hw_resc *hw_resc = &bp->hw_resc;
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int avail, mpc_cp, i;
	int avail_cp;

	if (!mpc)
		return;

	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++)
		mpc->mpc_ring_count[i] = 0;
	mpc->mpc_cp_rings = 0;

	avail = hw_resc->max_tx_rings - bp->tx_nr_rings;

	avail_cp = hw_resc->max_cp_rings - bp->tx_nr_rings -
		   bp->rx_nr_rings;

	if (BNXT_MPC_CRYPTO_CAPABLE(bp))
		__bnxt_set_dflt_mpc_rings(bp, BNXT_MPC_CRYPTO, &avail, avail_cp);

	if (BNXT_MPC_CFA_CAPABLE(bp))
		__bnxt_set_dflt_mpc_rings(bp, BNXT_MPC_CFA, &avail, avail_cp);

	for (i = 0, mpc_cp = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		if (mpc_cp < mpc->mpc_ring_count[i])
			mpc_cp = mpc->mpc_ring_count[i];
	}
	mpc->mpc_cp_rings = mpc_cp;
}

void bnxt_init_mpc_ring_struct(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i, j;

	if (!BNXT_MPC_CRYPTO_CAPABLE(bp) && !BNXT_MPC_CFA_CAPABLE(bp))
		return;

	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		int num = mpc->mpc_ring_count[i];
		struct bnxt_tx_ring_info *txr;

		txr = mpc->mpc_rings[i];
		if (!txr)
			continue;
		for (j = 0; j < num; j++) {
			struct bnxt_ring_mem_info *rmem;
			struct bnxt_ring_struct *ring;

			txr = &mpc->mpc_rings[i][j];

			txr->tx_ring_struct.ring_mem.flags =
				BNXT_RMEM_RING_PTE_FLAG;
			txr->bnapi = bp->tx_ring[bp->tx_ring_map[j]].bnapi;

			ring = &txr->tx_ring_struct;
			rmem = &ring->ring_mem;
			rmem->nr_pages = bp->tx_nr_pages;
			rmem->page_size = HW_TXBD_RING_SIZE;
			rmem->pg_arr = (void **)txr->tx_desc_ring;
			rmem->dma_arr = txr->tx_desc_mapping;
			rmem->vmem_size = SW_MPC_TXBD_RING_SIZE *
					  bp->tx_nr_pages;
			rmem->vmem = (void **)&txr->tx_buf_ring;
		}
	}
}

int bnxt_alloc_mpcs(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i;

	if (!BNXT_MPC_CRYPTO_CAPABLE(bp) && !BNXT_MPC_CFA_CAPABLE(bp))
		return 0;

	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		int num = mpc->mpc_ring_count[i];
		struct bnxt_tx_ring_info *txr;

		if (!num)
			continue;
		txr = kcalloc(num, sizeof(*txr), GFP_KERNEL);
		if (!txr)
			return -ENOMEM;
		mpc->mpc_rings[i] = txr;
	}

	for (i = 0; i < bp->cp_nr_rings; i++) {
		struct bnxt_napi *bnapi = bp->bnapi[i];

		if (!bnxt_napi_has_mpc(bp, i))
			continue;
		bnapi->tx_mpc_ring = kcalloc(BNXT_MPC_TYPE_MAX,
					     sizeof(*bnapi->tx_mpc_ring),
					     GFP_KERNEL);
		if (!bnapi->tx_mpc_ring)
			return -ENOMEM;
	}
	return 0;
}

void bnxt_free_mpcs(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i;

	if (!mpc)
		return;

	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		kfree(mpc->mpc_rings[i]);
		mpc->mpc_rings[i] = NULL;
	}
	if (!bp->bnapi)
		return;
	for (i = 0; i < bp->cp_nr_rings; i++) {
		struct bnxt_napi *bnapi = bp->bnapi[i];

		kfree(bnapi->tx_mpc_ring);
		bnapi->tx_mpc_ring = NULL;
	}
}

int bnxt_alloc_mpc_rings(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i, j;

	if (!mpc)
		return 0;

	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		int num = mpc->mpc_ring_count[i], rc;

		for (j = 0; j < num; j++) {
			struct bnxt_tx_ring_info *txr = &mpc->mpc_rings[i][j];
			struct bnxt_ring_struct *ring;

			ring = &txr->tx_ring_struct;
			rc = bnxt_alloc_ring(bp, &ring->ring_mem);
			if (rc)
				return rc;
			ring->queue_id = BNXT_MPC_QUEUE_ID;
			ring->mpc_chnl_type = i;
			/* for stats context */
			ring->grp_idx = txr->bnapi->index;
			spin_lock_init(&txr->tx_lock);
		}
	}
	return 0;
}

void bnxt_free_mpc_rings(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i, j;

	if (!mpc)
		return;

	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		int num = mpc->mpc_ring_count[i];

		if (!mpc->mpc_rings[i])
			continue;
		for (j = 0; j < num; j++) {
			struct bnxt_tx_ring_info *txr = &mpc->mpc_rings[i][j];
			struct bnxt_ring_struct *ring = &txr->tx_ring_struct;

			bnxt_free_ring(bp, &ring->ring_mem);
		}
	}
}

void bnxt_init_mpc_rings(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i, j;

	if (!mpc)
		return;

	mpc->mpc_tx_start_idx = bp->tx_nr_rings;
	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		int num = mpc->mpc_ring_count[i];

		for (j = 0; j < num; j++) {
			struct bnxt_tx_ring_info *txr = &mpc->mpc_rings[i][j];
			struct bnxt_ring_struct *ring = &txr->tx_ring_struct;

			txr->tx_prod = 0;
			txr->tx_cons = 0;
			txr->tx_hw_cons = 0;
			ring->fw_ring_id = INVALID_HW_RING_ID;
		}
	}
}

int bnxt_hwrm_mpc_ring_alloc(struct bnxt *bp)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i, j, rc;
	u32 tx_idx;

	if (!mpc)
		return 0;

	tx_idx = mpc->mpc_tx_start_idx;
	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		int num = mpc->mpc_ring_count[i];

		for (j = 0; j < num; j++) {
			struct bnxt_tx_ring_info *txr = &mpc->mpc_rings[i][j];
			struct bnxt_cp_ring_info *cpr = txr->tx_cpr;
			struct bnxt_ring_struct *ring;

			ring = &cpr->cp_ring_struct;
			if (ring->fw_ring_id == INVALID_HW_RING_ID) {
				rc = bnxt_hwrm_cp_ring_alloc_p5(bp, cpr);
				if (rc)
					return rc;
			}
			rc = bnxt_hwrm_tx_ring_alloc(bp, txr, tx_idx++);
			if (rc)
				return rc;
		}
	}
	return 0;
}

void bnxt_hwrm_mpc_ring_free(struct bnxt *bp, bool close_path)
{
	struct bnxt_mpc_info *mpc = bp->mpc_info;
	int i, j;

	if (!mpc)
		return;

	for (i = 0; i < BNXT_MPC_TYPE_MAX; i++) {
		int num = mpc->mpc_ring_count[i];

		if (!mpc->mpc_rings[i])
			continue;
		for (j = 0; j < num; j++)
			bnxt_hwrm_tx_ring_free(bp, &mpc->mpc_rings[i][j],
					       close_path);
	}
}

int bnxt_start_xmit_mpc(struct bnxt *bp, struct bnxt_tx_ring_info *txr,
			void *data, uint len, unsigned long handle)
{
	u32 bds, total_bds, bd_space, free_size;
	struct bnxt_sw_mpc_tx_bd *tx_buf;
	struct tx_bd *txbd;
	u16 prod;

	bds = DIV_ROUND_UP(len, sizeof(*txbd));
	total_bds = bds + 1;
	free_size = bnxt_tx_avail(bp, txr);
	if (free_size < total_bds)
		return -EBUSY;

	prod = txr->tx_prod;
	txbd = &txr->tx_desc_ring[TX_RING(bp, prod)][TX_IDX(prod)];
	tx_buf = &txr->tx_mpc_buf_ring[RING_TX(bp, prod)];
	tx_buf->handle = handle;
	tx_buf->inline_bds = total_bds;

	txbd->tx_bd_len_flags_type =
		cpu_to_le32((len << TX_BD_LEN_SHIFT) | TX_BD_TYPE_MPC_TX_BD |
			    (total_bds << TX_BD_FLAGS_BD_CNT_SHIFT));
	txbd->tx_bd_opaque = SET_TX_OPAQUE(bp, txr, prod, total_bds);

	prod = NEXT_TX(prod);
	txbd = &txr->tx_desc_ring[TX_RING(bp, prod)][TX_IDX(prod)];
	bd_space = TX_DESC_CNT - TX_IDX(prod);
	if (bd_space < bds) {
		uint len0 = bd_space * sizeof(*txbd);

		memcpy(txbd, data, len0);
		prod += bd_space;
		txbd = &txr->tx_desc_ring[TX_RING(bp, prod)][TX_IDX(prod)];
		bds -= bd_space;
		len -= len0;
		data += len0;
	}
	memcpy(txbd, data, len);
	prod += bds;
	txr->tx_prod = prod;

	/* Sync BD data before updating doorbell */
	wmb();
	bnxt_db_write(bp, &txr->tx_db, prod);

	return 0;
}

static bool bnxt_mpc_unsolicit(struct mpc_cmp *mpcmp)
{
	u32 client = MPC_CMP_CLIENT_TYPE(mpcmp);

	if (client != MPC_CMP_CLIENT_TCE && client != MPC_CMP_CLIENT_RCE &&
	    client != MPC_CMP_CLIENT_TE_CFA && client != MPC_CMP_CLIENT_RE_CFA)
		return false;
	return MPC_CMP_UNSOLICIT_SUBTYPE(mpcmp);
}

int bnxt_mpc_cmp(struct bnxt *bp, struct bnxt_cp_ring_info *cpr, u32 *raw_cons)
{
	struct bnxt_cmpl_entry cmpl_entry_arr[2];
	struct bnxt_napi *bnapi = cpr->bnapi;
	u16 cons = RING_CMP(*raw_cons);
	struct mpc_cmp *mpcmp, *mpcmp1;
	u32 tmp_raw_cons = *raw_cons;
	unsigned long handle = 0;
	u32 client, cmpl_num;
	u8 type;

	mpcmp = (struct mpc_cmp *)
		&cpr->cp_desc_ring[CP_RING(cons)][CP_IDX(cons)];
	type = MPC_CMP_CMP_TYPE(mpcmp);
	cmpl_entry_arr[0].cmpl = mpcmp;
	cmpl_entry_arr[0].len = sizeof(*mpcmp);
	cmpl_num = 1;
	if (type == MPC_CMP_TYPE_MID_PATH_LONG) {
		tmp_raw_cons = NEXT_RAW_CMP(tmp_raw_cons);
		cons = RING_CMP(tmp_raw_cons);
		mpcmp1 = (struct mpc_cmp *)
			 &cpr->cp_desc_ring[CP_RING(cons)][CP_IDX(cons)];

		if (!MPC_CMP_VALID(bp, mpcmp1, tmp_raw_cons))
			return -EBUSY;
		/* The valid test of the entry must be done first before
		 * reading any further.
		 */
		dma_rmb();
		if (mpcmp1 == mpcmp + 1) {
			cmpl_entry_arr[cmpl_num - 1].len += sizeof(*mpcmp1);
		} else {
			cmpl_entry_arr[cmpl_num].cmpl = mpcmp1;
			cmpl_entry_arr[cmpl_num].len = sizeof(*mpcmp1);
			cmpl_num++;
		}
	}
	client = MPC_CMP_CLIENT_TYPE(mpcmp) >> MPC_CMP_CLIENT_SFT;

	if (!bnxt_mpc_unsolicit(mpcmp)) {
		struct bnxt_sw_mpc_tx_bd *mpc_buf;
		struct bnxt_tx_ring_info *txr;
		u16 tx_cons;
		u32 opaque;

		opaque = mpcmp->mpc_cmp_opaque;
		txr = bnapi->tx_mpc_ring[client];
		tx_cons = txr->tx_cons;
		if (TX_OPAQUE_RING(opaque) != txr->tx_napi_idx)
			netdev_warn(bp->dev, "Wrong opaque %x, expected ring %x, idx %x\n",
				    opaque, txr->tx_napi_idx, txr->tx_cons);
		mpc_buf = &txr->tx_mpc_buf_ring[RING_TX(bp, tx_cons)];
		handle = mpc_buf->handle;
		tx_cons += mpc_buf->inline_bds;
		txr->tx_cons = tx_cons;
		txr->tx_hw_cons = RING_TX(bp, tx_cons);
	}
	if (client == BNXT_MPC_TCE_TYPE || client == BNXT_MPC_RCE_TYPE)
		bnxt_ktls_mpc_cmp(bp, client, handle, cmpl_entry_arr, cmpl_num);
	else if (client == BNXT_MPC_TE_CFA_TYPE || client == BNXT_MPC_RE_CFA_TYPE)
		bnxt_tfc_mpc_cmp(bp, client, handle, cmpl_entry_arr, cmpl_num);
	*raw_cons = tmp_raw_cons;
	return 0;
}
