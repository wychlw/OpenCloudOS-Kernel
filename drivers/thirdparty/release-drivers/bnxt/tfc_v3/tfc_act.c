// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2019-2023 Broadcom
 * All rights reserved.
 */

#include <linux/types.h>
#include <linux/netdevice.h>

#include "tfc.h"
#include "cfa_bld_mpc_field_ids.h"
#include "cfa_bld_mpcops.h"
#include "tfo.h"
#include "tfc_em.h"
#include "tfc_cpm.h"
#include "tfc_msg.h"
#include "tfc_priv.h"
#include "cfa_types.h"
#include "cfa_mm.h"
#include "tfc_action_handle.h"
#include "bnxt_compat.h"
#include "bnxt.h"
#include "bnxt_mpc.h"
#include "bnxt_tfc.h"
#include "sys_util.h"

/* The read/write  granularity is 32B
 */
#define TFC_ACT_RW_GRANULARITY 32

#define TFC_ACT_CACHE_OPT_EN 0

int tfc_act_alloc(struct tfc *tfcp, u8 tsid, struct tfc_cmm_info *cmm_info, u16 num_contig_rec)
{
	struct cfa_mm_alloc_parms aparms;
	struct tfc_cpm *cpm_lkup = NULL;
	struct tfc_cpm *cpm_act = NULL;
	struct tfc_ts_mem_cfg mem_cfg;
	bool is_bs_owner, is_shared;
	struct bnxt *bp = tfcp->bp;
	struct tfc_ts_pool_info pi;
	struct tfc_cmm *cmm;
	u32 entry_offset;
	u16 max_pools;
	u16 pool_id;
	bool valid;
	int rc;

	rc = tfo_ts_get(tfcp->tfo, tsid, &is_shared, NULL, &valid, &max_pools);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get tsid: %d\n", __func__, rc);
		return -EINVAL;
	}

	if (!valid) {
		netdev_dbg(bp->dev, "%s: tsid(%d) not allocated\n", __func__, tsid);
		return -EINVAL;
	}

	if (!max_pools) {
		netdev_dbg(bp->dev, "%s: tsid(%d) Max pools must be greater than 0 %d\n",
			   __func__, tsid, max_pools);
		return -EINVAL;
	}

	rc = tfo_ts_get_pool_info(tfcp->tfo, tsid, cmm_info->dir, &pi);
	if (rc) {
		netdev_dbg(bp->dev,
			   "%s: Failed to get pool info for tsid:%d\n",
			   __func__, tsid);
		return -EINVAL;
	}

	/* Get CPM instances */
	rc = tfo_ts_get_cpm_inst(tfcp->tfo, tsid, cmm_info->dir, &cpm_lkup, &cpm_act);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get CPM instances: %d\n",
			   __func__, rc);
		return -EINVAL;
	}

	rc = tfo_ts_get_mem_cfg(tfcp->tfo, tsid,
				cmm_info->dir,
				CFA_REGION_TYPE_ACT,
				&is_bs_owner,
				&mem_cfg);
	if (rc) {
		netdev_dbg(bp->dev, "%s: tfo_ts_get_mem_cfg() failed: %d\n",
			   __func__, rc);
		return -EINVAL;
	}

	/* if no pool available locally or all pools full */
	rc = tfc_cpm_get_avail_pool(cpm_act, &pool_id);
	if (rc) {
		/* Allocate a pool */
		struct cfa_mm_query_parms qparms;
		struct cfa_mm_open_parms oparms;
		u16 fid;

		/* There is only 1 pool for a non-shared table scope
		 * and it is full.
		 */
		if (!is_shared) {
			netdev_dbg(bp->dev, "%s: no records remain\n", __func__);
			return -ENOMEM;
		}
		rc = tfc_get_fid(tfcp, &fid);
		if (rc)
			return rc;

		rc = tfc_tbl_scope_pool_alloc(tfcp,
					      fid,
					      tsid,
					      CFA_REGION_TYPE_ACT,
					      cmm_info->dir,
					      NULL,
					      &pool_id);
		if (rc) {
			netdev_dbg(bp->dev, "%s: table scope alloc HWRM failed: %d\n",
				   __func__, rc);
			return -EINVAL;
		}

		/* Create pool CMM instance */
		qparms.max_records = mem_cfg.rec_cnt;
		qparms.max_contig_records = roundup_pow_of_two(pi.act_max_contig_rec);
		rc = cfa_mm_query(&qparms);
		if (rc) {
			netdev_dbg(bp->dev, "%s: cfa_mm_query() failed: %d\n",
				   __func__, rc);
			return -EINVAL;
		}

		cmm = kzalloc(qparms.db_size, GFP_KERNEL);
		if (!cmm)
			return -ENOMEM;

		oparms.db_mem_size = qparms.db_size;
		oparms.max_contig_records = roundup_pow_of_two(qparms.max_contig_records);
		oparms.max_records = qparms.max_records / max_pools;
		rc = cfa_mm_open(cmm, &oparms);
		if (rc) {
			netdev_dbg(bp->dev, "%s: cfa_mm_open() failed: %d\n",
				   __func__, rc);
			kfree(cmm);
			return -EINVAL;
		}

		/* Store CMM instance in the CPM */
		rc = tfc_cpm_set_cmm_inst(cpm_act, pool_id, cmm);
		if (rc) {
			netdev_dbg(bp->dev, "%s: tfc_cpm_set_cmm_inst() failed: %d\n",
				   __func__, rc);
			kfree(cmm);
			return -EINVAL;
		}

		/* store updated pool info */
		tfo_ts_set_pool_info(tfcp->tfo, tsid, cmm_info->dir, &pi);
	} else {
		/* Get the pool instance and allocate an act rec index from the pool */
		rc = tfc_cpm_get_cmm_inst(cpm_act, pool_id, &cmm);
		if (rc) {
			netdev_dbg(bp->dev, "%s: tfc_cpm_get_cmm_inst() failed: %d\n",
				   __func__, rc);
			kfree(cmm);
			return -EINVAL;
		}
	}

	aparms.num_contig_records = roundup_pow_of_two(num_contig_rec);
	rc = cfa_mm_alloc(cmm, &aparms);
	if (rc) {
		netdev_dbg(bp->dev, "%s: cfa_mm_alloc() failed: %d\n",
			   __func__, rc);
		kfree(cmm);
		return -EINVAL;
	}

	/* Update CPM info so it will determine best pool to use next alloc */
	rc = tfc_cpm_set_usage(pi.act_cpm, pool_id, aparms.used_count, aparms.all_used);
	if (rc) {
		netdev_dbg(bp->dev, "%s: EM insert tfc_cpm_set_usage() failed: %d\n",
			   __func__, rc);
	}

	CREATE_OFFSET(&entry_offset, pi.act_pool_sz_exp, pool_id, aparms.record_offset);

	/* Create Action handle */
	cmm_info->act_handle = tfc_create_action_handle(tsid, num_contig_rec, entry_offset);
	return rc;
}

int tfc_act_set(struct tfc *tfcp, const struct tfc_cmm_info *cmm_info, const u8 *data,
		u16 data_sz_words)
{
	struct cfa_mpc_data_obj fields_cmd[CFA_BLD_MPC_WRITE_CMD_MAX_FLD];
	struct cfa_mpc_data_obj fields_cmp[CFA_BLD_MPC_WRITE_CMP_MAX_FLD];
	u8 tx_msg[TFC_MPC_MAX_TX_BYTES], rx_msg[TFC_MPC_MAX_RX_BYTES];
	u32 i, buff_len, entry_offset, record_size;
	u32 mpc_opaque = TFC_MPC_OPAQUE_VAL;
	struct bnxt_mpc_mbuf mpc_msg_in;
	struct bnxt_mpc_mbuf mpc_msg_out;
	struct cfa_bld_mpcinfo *mpc_info;
	struct bnxt *bp = tfcp->bp;
	bool is_shared, valid;
	int rc;
	u8 tsid;

	tfo_mpcinfo_get(tfcp->tfo, &mpc_info);

	/* Check that MPC APIs are bound */
	if (!mpc_info->mpcops) {
		netdev_dbg(bp->dev, "%s: MPC not initialized\n",
			   __func__);
		return -EINVAL;
	}

	tfc_get_fields_from_action_handle(&cmm_info->act_handle,
					  &tsid,
					  &record_size,
					  &entry_offset);

	rc = tfo_ts_get(tfcp->tfo, tsid, &is_shared, NULL, &valid, NULL);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get tsid: rc:%d\n", __func__, rc);
		return -EINVAL;
	}
	if (!valid) {
		netdev_dbg(bp->dev, "%s: tsid not allocated %d\n", __func__, tsid);
		return -EINVAL;
	}

	/* Create MPC EM insert command using builder */
	for (i = 0; i < CFA_BLD_MPC_WRITE_CMD_MAX_FLD; i++)
		fields_cmd[i].field_id = INVALID_U16;

	fields_cmd[CFA_BLD_MPC_WRITE_CMD_OPAQUE_FLD].field_id =
		CFA_BLD_MPC_WRITE_CMD_OPAQUE_FLD;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_OPAQUE_FLD].val = 0xAA;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_TABLE_TYPE_FLD].field_id =
		CFA_BLD_MPC_WRITE_CMD_TABLE_TYPE_FLD;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_TABLE_TYPE_FLD].val = CFA_BLD_MPC_HW_TABLE_TYPE_ACTION;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_TABLE_SCOPE_FLD].field_id =
		CFA_BLD_MPC_WRITE_CMD_TABLE_SCOPE_FLD;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_TABLE_SCOPE_FLD].val = tsid;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_DATA_SIZE_FLD].field_id =
		CFA_BLD_MPC_WRITE_CMD_DATA_SIZE_FLD;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_DATA_SIZE_FLD].val = data_sz_words;
#if TFC_ACT_CACHE_OPT_EN
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_CACHE_OPTION_FLD].field_id =
		CFA_BLD_MPC_WRITE_CMD_CACHE_OPTION_FLD;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_CACHE_OPTION_FLD].val = 0x01;
#endif
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_TABLE_INDEX_FLD].field_id =
		CFA_BLD_MPC_WRITE_CMD_TABLE_INDEX_FLD;
	fields_cmd[CFA_BLD_MPC_WRITE_CMD_TABLE_INDEX_FLD].val = entry_offset;

	buff_len = TFC_MPC_MAX_TX_BYTES;

	rc = mpc_info->mpcops->cfa_bld_mpc_build_cache_write(tx_msg,
							     &buff_len,
							     data,
							     fields_cmd);
	if (rc) {
		netdev_dbg(bp->dev, "%s: write build failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

#ifdef TFC_ACT_MSG_DEBUG
	netdev_dbg(bp->dev, "Tx Msg: size:%d\n", buff_len);
	bnxt_tfc_buf_dump(bp, NULL, (uint8_t *)tx_msg, buff_len, 4, 4);
#endif

	/* Send MPC */
	mpc_msg_in.chnl_id = (cmm_info->dir == CFA_DIR_TX ?
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_TE_CFA :
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_RE_CFA);
	mpc_msg_in.msg_data = &tx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_in.msg_size = buff_len - TFC_MPC_HEADER_SIZE_BYTES;
	mpc_msg_out.cmp_type = MPC_CMP_TYPE_MID_PATH_SHORT;
	mpc_msg_out.msg_data = &rx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_out.msg_size = TFC_MPC_MAX_RX_BYTES;

	rc = bnxt_mpc_send(tfcp->bp,
			   &mpc_msg_in,
			   &mpc_msg_out,
			   &mpc_opaque);
	if (rc) {
		netdev_dbg(bp->dev, "%s: write MPC send failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

#ifdef TFC_ACT_MSG_DEBUG
	netdev_dbg(bp->dev, "Rx Msg: size:%d\n", mpc_msg_out.msg_size);
	bnxt_tfc_buf_dump(bp, NULL, (uint8_t *)rx_msg, buff_len, 4, 4);
#endif

	/* Process response */
	for (i = 0; i < CFA_BLD_MPC_WRITE_CMP_MAX_FLD; i++)
		fields_cmp[i].field_id = INVALID_U16;

	fields_cmp[CFA_BLD_MPC_WRITE_CMP_STATUS_FLD].field_id =
		CFA_BLD_MPC_WRITE_CMP_STATUS_FLD;

	rc = mpc_info->mpcops->cfa_bld_mpc_parse_cache_write(rx_msg,
							     mpc_msg_out.msg_size,
							     fields_cmp);
	if (rc) {
		netdev_dbg(bp->dev, "%s: write parse failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	if (fields_cmp[CFA_BLD_MPC_WRITE_CMP_STATUS_FLD].val != CFA_BLD_MPC_OK) {
		netdev_dbg(bp->dev, "%s: failed with status code:%d\n",
			   __func__,
			   (u32)fields_cmp[CFA_BLD_MPC_WRITE_CMP_STATUS_FLD].val);
		netdev_dbg(bp->dev, "Hash MSB:0x%0x\n",
			   (u32)fields_cmp[CFA_BLD_MPC_WRITE_CMP_HASH_MSB_FLD].val);
		rc = ((int)fields_cmp[CFA_BLD_MPC_WRITE_CMP_STATUS_FLD].val) * -1;
		goto cleanup;
	}
	return 0;

 cleanup:
	return rc;
}

static int tfc_act_get_only(struct tfc *tfcp, const struct tfc_cmm_info *cmm_info, u8 *data,
			    u16 *data_sz_words)
{
	struct cfa_mpc_data_obj fields_cmd[CFA_BLD_MPC_READ_CMD_MAX_FLD] = { {0} };
	struct cfa_mpc_data_obj fields_cmp[CFA_BLD_MPC_READ_CMP_MAX_FLD] = { {0} };
	u8 tx_msg[TFC_MPC_MAX_TX_BYTES] = { 0 };
	u8 rx_msg[TFC_MPC_MAX_RX_BYTES] = { 0 };
	u32 entry_offset, record_size, buff_len;
	u32 mpc_opaque = TFC_MPC_OPAQUE_VAL;
	struct cfa_bld_mpcinfo *mpc_info;
	struct bnxt_mpc_mbuf mpc_msg_out;
	struct bnxt_mpc_mbuf mpc_msg_in;
	struct bnxt *bp = tfcp->bp;
	u8 discard_data[128], tsid;
	bool is_shared, valid;
	u64 host_address;
	int i, rc;

	tfo_mpcinfo_get(tfcp->tfo, &mpc_info);

	tfc_get_fields_from_action_handle(&cmm_info->act_handle, &tsid,
					  &record_size, &entry_offset);

	rc = tfo_ts_get(tfcp->tfo, tsid, &is_shared, NULL, &valid, NULL);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get tsid: rc:%d\n", __func__, rc);
		return -EINVAL;
	}

	if (!valid) {
		netdev_dbg(bp->dev, "%s: tsid not allocated %d\n", __func__, tsid);
		return -EINVAL;
	}

	/* Check that data pointer is word aligned */
	if (((u64)data)  & 0x3ULL) {
		netdev_dbg(bp->dev, "%s: data pointer not word aligned\n",
			   __func__);
		return -EINVAL;
	}

	host_address = (phys_addr_t)virt_to_phys(data);

	/* Check that MPC APIs are bound */
	if (!mpc_info->mpcops) {
		netdev_dbg(bp->dev, "%s: MPC not initialized\n",
			   __func__);
		return -EINVAL;
	}

	/* Create MPC EM insert command using builder */
	for (i = 0; i < CFA_BLD_MPC_READ_CMD_MAX_FLD; i++)
		fields_cmd[i].field_id = INVALID_U16;

	fields_cmd[CFA_BLD_MPC_READ_CMD_OPAQUE_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_OPAQUE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_OPAQUE_FLD].val = 0xAA;

	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD].val =
		CFA_BLD_MPC_HW_TABLE_TYPE_ACTION;

	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_SCOPE_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_TABLE_SCOPE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_SCOPE_FLD].val = tsid;

	fields_cmd[CFA_BLD_MPC_READ_CMD_DATA_SIZE_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_DATA_SIZE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_DATA_SIZE_FLD].val = *data_sz_words;

#if TFC_ACT_CACHE_OPT_EN
	fields_cmd[CFA_BLD_MPC_READ_CMD_CACHE_OPTION_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_CACHE_OPTION_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_CACHE_OPTION_FLD].val = 0x0;
#endif
	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_INDEX_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_TABLE_INDEX_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_INDEX_FLD].val = entry_offset;

	fields_cmd[CFA_BLD_MPC_READ_CMD_HOST_ADDRESS_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_HOST_ADDRESS_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_HOST_ADDRESS_FLD].val = host_address;

	buff_len = TFC_MPC_MAX_TX_BYTES;

	rc = mpc_info->mpcops->cfa_bld_mpc_build_cache_read(tx_msg,
							    &buff_len,
							    fields_cmd);
	if (rc) {
		netdev_dbg(bp->dev, "%s: read build failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	/* Send MPC */
	mpc_msg_in.chnl_id = (cmm_info->dir == CFA_DIR_TX ?
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_TE_CFA :
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_RE_CFA);
	mpc_msg_in.msg_data = &tx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_in.msg_size = buff_len - TFC_MPC_HEADER_SIZE_BYTES;
	mpc_msg_out.cmp_type = MPC_CMP_TYPE_MID_PATH_SHORT;
	mpc_msg_out.msg_data = &rx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_out.msg_size = TFC_MPC_MAX_RX_BYTES;

	rc = bnxt_mpc_send(tfcp->bp,
			   &mpc_msg_in,
			   &mpc_msg_out,
			   &mpc_opaque);
	if (rc) {
		netdev_dbg(bp->dev, "%s: read MPC send failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	/* Process response */
	for (i = 0; i < CFA_BLD_MPC_READ_CMP_MAX_FLD; i++)
		fields_cmp[i].field_id = INVALID_U16;

	fields_cmp[CFA_BLD_MPC_READ_CMP_STATUS_FLD].field_id =
		CFA_BLD_MPC_READ_CMP_STATUS_FLD;

	rc = mpc_info->mpcops->cfa_bld_mpc_parse_cache_read(rx_msg,
							    mpc_msg_out.msg_size,
							    discard_data,
							    *data_sz_words * TFC_MPC_BYTES_PER_WORD,
							    fields_cmp);
	if (rc) {
		netdev_dbg(bp->dev, "%s: Action read parse failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	if (fields_cmp[CFA_BLD_MPC_READ_CMP_STATUS_FLD].val != CFA_BLD_MPC_OK) {
		netdev_dbg(bp->dev, "%s: Action read failed with status code:%d\n",
			   __func__,
			   (u32)fields_cmp[CFA_BLD_MPC_READ_CMP_STATUS_FLD].val);
		rc = ((int)fields_cmp[CFA_BLD_MPC_READ_CMP_STATUS_FLD].val) * -1;
		goto cleanup;
	}
	return 0;

cleanup:
	return rc;
}

static int tfc_act_get_clear(struct tfc *tfcp,
			     const struct tfc_cmm_info *cmm_info,
			     u8 *data,
			     u16 *data_sz_words,
			     u8 clr_offset,
			     u8 clr_size)
{
	int rc = 0;
	u8 tx_msg[TFC_MPC_MAX_TX_BYTES] = { 0 };
	u8 rx_msg[TFC_MPC_MAX_RX_BYTES] = { 0 };
	u32 msg_count = BNXT_MPC_COMP_MSG_COUNT;
	int i;
	u32 buff_len;
	struct cfa_mpc_data_obj fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_MAX_FLD] = { {0} };
	struct cfa_mpc_data_obj fields_cmp[CFA_BLD_MPC_READ_CLR_CMP_MAX_FLD] = { {0} };
	u32 entry_offset;
	u64 host_address;
	struct bnxt_mpc_mbuf mpc_msg_in;
	struct bnxt_mpc_mbuf mpc_msg_out;
	u32 record_size;
	u8 tsid;
	bool is_shared;
	struct cfa_bld_mpcinfo *mpc_info;
	u8 discard_data[128];
	bool valid;
	u16 mask = 0;
	struct bnxt *bp = tfcp->bp;

	tfo_mpcinfo_get(tfcp->tfo, &mpc_info);

	tfc_get_fields_from_action_handle(&cmm_info->act_handle,
					  &tsid,
					  &record_size,
					  &entry_offset);

	rc = tfo_ts_get(tfcp->tfo, tsid, &is_shared, NULL, &valid, NULL);
	if (rc != 0) {
		netdev_dbg(bp->dev, "%s: failed to get tsid: %d\n",
			   __func__, rc);
		return -EINVAL;
	}
	if (!valid) {
		netdev_dbg(bp->dev, "%s: tsid not allocated %d\n",
			   __func__, tsid);
		return -EINVAL;
	}

	/* Check that data pointer is word aligned */
	if (((uint64_t)data)  & 0x3ULL) {
		netdev_dbg(bp->dev, "%s: data pointer not word aligned\n",
			   __func__);
		return -EINVAL;
	}

	host_address = (phys_addr_t)virt_to_phys(data);

	/* Check that MPC APIs are bound */
	if (!mpc_info->mpcops) {
		netdev_dbg(bp->dev, "%s: MPC not initialized\n",
			   __func__);
		return -EINVAL;
	}

	/* Create MPC EM insert command using builder */
	for (i = 0; i < CFA_BLD_MPC_READ_CLR_CMD_MAX_FLD; i++)
		fields_cmd[i].field_id = INVALID_U16;

	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_OPAQUE_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMD_OPAQUE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_OPAQUE_FLD].val = 0xAA;

	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_TABLE_TYPE_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMD_TABLE_TYPE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_TABLE_TYPE_FLD].val =
		CFA_BLD_MPC_HW_TABLE_TYPE_ACTION;

	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_TABLE_SCOPE_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMD_TABLE_SCOPE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_TABLE_SCOPE_FLD].val = tsid;

	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_DATA_SIZE_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMD_DATA_SIZE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_DATA_SIZE_FLD].val = *data_sz_words;

#if TFC_ACT_CACHE_OPT_EN
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_CACHE_OPTION_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMD_CACHE_OPTION_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_CACHE_OPTION_FLD].val = 0x0;
#endif
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_TABLE_INDEX_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMD_TABLE_INDEX_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_TABLE_INDEX_FLD].val = entry_offset;

	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_HOST_ADDRESS_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMD_HOST_ADDRESS_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_HOST_ADDRESS_FLD].val = host_address;

	for (i = clr_offset; i < clr_size; i++)
		mask |= (1 << i);

	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_CLEAR_MASK_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMD_CLEAR_MASK_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CLR_CMD_CLEAR_MASK_FLD].val = mask;

	buff_len = TFC_MPC_MAX_TX_BYTES;

	rc = mpc_info->mpcops->cfa_bld_mpc_build_cache_read_clr(tx_msg,
								&buff_len,
								fields_cmd);

	if (rc) {
		netdev_dbg(bp->dev, "%s: read clear build failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	/* Send MPC */
	mpc_msg_in.chnl_id = (cmm_info->dir == CFA_DIR_TX ?
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_TE_CFA :
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_RE_CFA);
	mpc_msg_in.msg_data = &tx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_in.msg_size = buff_len - TFC_MPC_HEADER_SIZE_BYTES;
	mpc_msg_out.cmp_type = MPC_CMP_TYPE_MID_PATH_SHORT;
	mpc_msg_out.msg_data = &rx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_out.msg_size = TFC_MPC_MAX_RX_BYTES;

	rc = bnxt_mpc_send(tfcp->bp,
			   &mpc_msg_in,
			   &mpc_msg_out,
			   &msg_count);

	if (rc) {
		netdev_dbg(bp->dev, "%s: read clear MPC send failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

		/* Process response */
	for (i = 0; i < CFA_BLD_MPC_READ_CLR_CMP_MAX_FLD; i++)
		fields_cmp[i].field_id = INVALID_U16;

	fields_cmp[CFA_BLD_MPC_READ_CLR_CMP_STATUS_FLD].field_id =
		CFA_BLD_MPC_READ_CLR_CMP_STATUS_FLD;

	rc = mpc_info->mpcops->cfa_bld_mpc_parse_cache_read_clr(rx_msg,
								mpc_msg_out.msg_size,
								discard_data,
								*data_sz_words *
								TFC_MPC_BYTES_PER_WORD,
								fields_cmp);

	if (rc) {
		netdev_dbg(bp->dev, "%s: Action read clear parse failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	if (fields_cmp[CFA_BLD_MPC_READ_CLR_CMP_STATUS_FLD].val != CFA_BLD_MPC_OK) {
		netdev_dbg(bp->dev, "%s: Action read clear failed with status code:%d\n",
			   __func__,
			   (uint32_t)fields_cmp[CFA_BLD_MPC_READ_CLR_CMP_STATUS_FLD].val);
		rc = ((int)fields_cmp[CFA_BLD_MPC_READ_CLR_CMP_STATUS_FLD].val) * -1;
		goto cleanup;
	}

	return 0;

cleanup:

	return rc;
}

int tfc_act_get(struct tfc *tfcp,
		const struct tfc_cmm_info *cmm_info,
		struct tfc_cmm_clr *clr,
		u8 *data, u16 *data_sz_words)
{
	struct bnxt *bp = tfcp->bp;
	/* It's not an error to pass clr as a Null pointer, just means that read
	 * and clear is not being requested.  Also allow the user to manage
	 * clear via the clr flag.
	 */
	if (clr && clr->clr) {
		/* Clear offset and size have to be two bytes aligned */
		if (clr->offset_in_byte % 2 || clr->sz_in_byte % 2) {
			netdev_dbg(bp->dev, "%s: clr offset(%d) or size(%d) is not two bytes aligned.\n",
				   __func__, clr->offset_in_byte, clr->sz_in_byte);
			return -EINVAL;
		}

		return tfc_act_get_clear(tfcp, cmm_info,
					 data, data_sz_words,
					 clr->offset_in_byte / 2,
					 clr->sz_in_byte / 2);
	} else {
		return tfc_act_get_only(tfcp, cmm_info,
					data, data_sz_words);
	}
}

int tfc_act_free(struct tfc *tfcp,
		 const struct tfc_cmm_info *cmm_info)
{
	u32 pool_id = 0, record_size, record_offset;
	struct cfa_mm_free_parms fparms;
	struct tfc_cpm *cpm_lkup = NULL;
	struct tfc_cpm *cpm_act = NULL;
	struct tfc_ts_mem_cfg mem_cfg;
	struct tfc_ts_pool_info pi;
	struct bnxt *bp = tfcp->bp;
	bool is_shared, valid;
	struct tfc_cmm *cmm;
	bool is_bs_owner;
	u8 tsid;
	int rc;

	/* Get fields from MPC Action handle */
	tfc_get_fields_from_action_handle(&cmm_info->act_handle, &tsid,
					  &record_size, &record_offset);

	rc = tfo_ts_get(tfcp->tfo, tsid, &is_shared, NULL, &valid, NULL);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get tsid: rc:%d\n", __func__, rc);
		return -EINVAL;
	}

	if (!valid) {
		netdev_dbg(bp->dev, "%s: tsid not allocated %d\n", __func__, tsid);
		return -EINVAL;
	}

	rc = tfo_ts_get_pool_info(tfcp->tfo, tsid, cmm_info->dir, &pi);
	if (rc) {
		netdev_dbg(bp->dev,
			   "%s: Failed to get pool info for tsid:%d\n",
			   __func__, tsid);
		return -EINVAL;
	}

	pool_id = TFC_ACTION_GET_POOL_ID(record_offset, pi.act_pool_sz_exp);

	rc = tfo_ts_get_mem_cfg(tfcp->tfo, tsid,
				cmm_info->dir,
				CFA_REGION_TYPE_ACT,
				&is_bs_owner,
				&mem_cfg);
	if (rc) {
		netdev_dbg(bp->dev, "%s: tfo_ts_get_mem_cfg() failed: %d\n",
			   __func__, rc);
		return -EINVAL;
	}
	/* Get CPM instance for this table scope */
	rc = tfo_ts_get_cpm_inst(tfcp->tfo, tsid, cmm_info->dir, &cpm_lkup, &cpm_act);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get CPM instance: %d\n",
			   __func__, rc);
		return -EINVAL;
	}

	rc = tfc_cpm_get_cmm_inst(cpm_act, pool_id, &cmm);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get record: %d\n", __func__, rc);
		return -EINVAL;
	}

	fparms.record_offset = record_offset;
	fparms.num_contig_records = roundup_pow_of_two(record_size);
	rc = cfa_mm_free(cmm, &fparms);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to free CMM instance: %d\n", __func__, rc);
		return -EINVAL;
	}

	rc = tfc_cpm_set_usage(cpm_act, pool_id, 0, false);
	if (rc)
		netdev_dbg(bp->dev, "%s: failed to set usage: %d\n", __func__, rc);

	return rc;
}
