// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2019-2023 Broadcom
 * All rights reserved.
 */

#include <linux/types.h>
#include "bnxt_compat.h"
#include "bnxt.h"
#include "bnxt_mpc.h"
#include "bnxt_tfc.h"

#include "tfc.h"
#include "tfo.h"
#include "tfc_em.h"
#include "tfc_cpm.h"
#include "tfc_msg.h"
#include "tfc_priv.h"
#include "cfa_types.h"
#include "cfa_mm.h"
#include "cfa_bld_mpc_field_ids.h"
#include "cfa_bld_mpcops.h"
#include "tfc_flow_handle.h"
#include "tfc_util.h"
#include "sys_util.h"

#include "tfc_debug.h"

#define TFC_EM_DYNAMIC_BUCKET_RECORD_SIZE 1

int tfc_em_insert(struct tfc *tfcp, u8 tsid, struct tfc_em_insert_parms *parms)
{
	struct cfa_mpc_data_obj fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_MAX_FLD];
	struct cfa_mpc_data_obj fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_MAX_FLD];
	u32 entry_offset, i, num_contig_records, buff_len;
	u32 mpc_opaque = TFC_MPC_OPAQUE_VAL;
	struct cfa_mm_alloc_parms aparms;
	struct cfa_bld_mpcinfo *mpc_info;
	struct bnxt_mpc_mbuf mpc_msg_out;
	struct bnxt_mpc_mbuf mpc_msg_in;
	struct cfa_mm_free_parms fparms;
	struct tfc_cpm *cpm_lkup = NULL;
	struct tfc_cpm *cpm_act = NULL;
	struct tfc_ts_mem_cfg mem_cfg;
	bool is_bs_owner, is_shared;
	struct tfc_ts_pool_info pi;
	struct bnxt *bp = tfcp->bp;
	u16 pool_id, max_pools;
	u8 *tx_msg, *rx_msg;
	struct tfc_cmm *cmm;
	int cleanup_rc;
	bool valid;
	int rc;

	tfo_mpcinfo_get(tfcp->tfo, &mpc_info);

	rc = tfo_ts_get(tfcp->tfo, tsid, &is_shared, NULL, &valid, &max_pools);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get tsid: %d\n",
			   __func__, rc);
		return -EINVAL;
	}

	if (!valid) {
		netdev_dbg(bp->dev, "%s: tsid not allocated %d\n", __func__, tsid);
		return -EINVAL;
	}

	if (max_pools == 0) {
		netdev_dbg(bp->dev, "%s: tsid(%d) Max pools must be greater than 0 %d\n",
			   __func__, tsid, max_pools);
		return -EINVAL;
	}

	/* Check that MPC APIs are bound */
	if (!mpc_info->mpcops) {
		netdev_dbg(bp->dev, "%s: MPC not initialized\n",
			   __func__);
		return -EINVAL;
	}

	rc = tfo_ts_get_mem_cfg(tfcp->tfo, tsid,
				parms->dir,
				CFA_REGION_TYPE_LKUP,
				&is_bs_owner,
				&mem_cfg);
	if (rc) {
		netdev_dbg(bp->dev, "%s: tfo_ts_get_mem_cfg() failed: %d\n",
			   __func__, rc);
		return -EINVAL;
	}

	/* Get CPM instances */
	rc = tfo_ts_get_cpm_inst(tfcp->tfo, tsid, parms->dir, &cpm_lkup, &cpm_act);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get CPM instances: %d\n",
			   __func__, rc);
		return -EINVAL;
	}

	num_contig_records = roundup_pow_of_two(parms->lkup_key_sz_words);

	rc = tfo_ts_get_pool_info(tfcp->tfo, tsid, parms->dir, &pi);
	if (rc) {
		netdev_dbg(bp->dev,
			   "%s: Failed to get pool info for tsid:%d\n",
			   __func__, tsid);
		return -EINVAL;
	}

	/* if no pool available locally or all pools full */
	rc = tfc_cpm_get_avail_pool(cpm_lkup, &pool_id);
	if (rc) {
		/* Allocate a pool */
		struct cfa_mm_query_parms qparms;
		struct cfa_mm_open_parms oparms;
		u16 fid;

		/* There is only 1 pool for a non-shared table scope and it is full. */
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
					      CFA_REGION_TYPE_LKUP,
					      parms->dir,
					      NULL,
					      &pool_id);

		if (rc) {
			netdev_dbg(bp->dev, "%s: table scope alloc pool failed: %d\n",
				   __func__, rc);
			return -EINVAL;
		}

		/* Create pool CMM instance.
		 * rec_cnt is the total number of records including static buckets
		 */
		qparms.max_records = (mem_cfg.rec_cnt - mem_cfg.lkup_rec_start_offset) / max_pools;
		qparms.max_contig_records = roundup_pow_of_two(pi.lkup_max_contig_rec);
		rc = cfa_mm_query(&qparms);
		if (rc) {
			netdev_dbg(bp->dev, "%s: cfa_mm_query() failed: %d\n",
				   __func__, rc);
			kfree(cmm);
			return -EINVAL;
		}

		cmm = kzalloc(qparms.db_size, GFP_KERNEL);
		if (!cmm)
			return -ENOMEM;

		oparms.db_mem_size = qparms.db_size;
		oparms.max_contig_records = roundup_pow_of_two(qparms.max_contig_records);
		oparms.max_records = qparms.max_records;
		rc = cfa_mm_open(cmm, &oparms);
		if (rc) {
			netdev_dbg(bp->dev, "%s: cfa_mm_open() failed: %d\n",
				   __func__, rc);
			kfree(cmm);
			return -EINVAL;
		}

		/* Store CMM instance in the CPM */
		rc = tfc_cpm_set_cmm_inst(cpm_lkup, pool_id, cmm);
		if (rc) {
			netdev_dbg(bp->dev, "%s: tfc_cpm_set_cmm_inst() failed: %d\n",
				   __func__, rc);
			kfree(cmm);
			return -EINVAL;
		}

		/* Store the updated pool information */
		tfo_ts_set_pool_info(tfcp->tfo, tsid, parms->dir, &pi);
	} else {
		/* Get the pool instance and allocate an lkup rec index from the pool */
		rc = tfc_cpm_get_cmm_inst(cpm_lkup, pool_id, &cmm);
		if (rc) {
			netdev_dbg(bp->dev, "%s: tfc_cpm_get_cmm_inst() failed: %d\n",
				   __func__, rc);
			return -EINVAL;
		}
	}

	aparms.num_contig_records = num_contig_records;
	rc = cfa_mm_alloc(cmm, &aparms);
	if (rc) {
		netdev_dbg(bp->dev, "%s: cfa_mm_alloc() failed: %d\n",
			   __func__, rc);
		return -EINVAL;
	}

	CREATE_OFFSET(&entry_offset, pi.lkup_pool_sz_exp, pool_id, aparms.record_offset);

	/* Create MPC EM insert command using builder */
	for (i = 0; i < CFA_BLD_MPC_EM_INSERT_CMD_MAX_FLD; i++)
		fields_cmd[i].field_id = INVALID_U16;

	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_OPAQUE_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMD_OPAQUE_FLD;
	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_OPAQUE_FLD].val = 0xAA;

	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_TABLE_SCOPE_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMD_TABLE_SCOPE_FLD;
	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_TABLE_SCOPE_FLD].val = tsid;

	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_DATA_SIZE_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMD_DATA_SIZE_FLD;
	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_DATA_SIZE_FLD].val = parms->lkup_key_sz_words;

	/* LREC address */
	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_TABLE_INDEX_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMD_TABLE_INDEX_FLD;
	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_TABLE_INDEX_FLD].val = entry_offset +
		mem_cfg.lkup_rec_start_offset;

	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_REPLACE_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMD_REPLACE_FLD;
	fields_cmd[CFA_BLD_MPC_EM_INSERT_CMD_REPLACE_FLD].val = 0x0;

	buff_len = TFC_MPC_MAX_TX_BYTES;

	netdev_dbg(bp->dev, "Lkup key data: size;%d entry_offset:%d\n",
		   (parms->lkup_key_sz_words * 32),
		   entry_offset + mem_cfg.lkup_rec_start_offset);
	bnxt_tfc_buf_dump(bp, "lkup key", (uint8_t *)parms->lkup_key_data,
			  (parms->lkup_key_sz_words * 32), 4, 4);

	tx_msg = kzalloc(TFC_MPC_MAX_TX_BYTES, GFP_KERNEL);
	rx_msg = kzalloc(TFC_MPC_MAX_RX_BYTES, GFP_KERNEL);

	if (!tx_msg || !rx_msg) {
		netdev_err(bp->dev, "%s: tx_msg[%p], rx_msg[%p]\n",
			   __func__, tx_msg, rx_msg);
		rc = -ENOMEM;
		goto cleanup;
	}

	rc = mpc_info->mpcops->cfa_bld_mpc_build_em_insert(tx_msg,
							   &buff_len,
							   parms->lkup_key_data,
							   fields_cmd);
	if (rc) {
		netdev_dbg(bp->dev, "%s: EM insert build failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	netdev_dbg(bp->dev, "Tx Msg: size:%d\n", buff_len);
	bnxt_tfc_buf_dump(bp, "EM insert", (uint8_t *)tx_msg, buff_len, 4, 4);

	/* Send MPC */
	mpc_msg_in.chnl_id = (parms->dir == CFA_DIR_TX ?
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_TE_CFA :
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_RE_CFA);
	mpc_msg_in.msg_data = &tx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_in.msg_size = buff_len - TFC_MPC_HEADER_SIZE_BYTES;
	mpc_msg_out.cmp_type = MPC_CMP_TYPE_MID_PATH_LONG;
	mpc_msg_out.msg_data = &rx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_out.msg_size = TFC_MPC_MAX_RX_BYTES - TFC_MPC_HEADER_SIZE_BYTES;

	rc = bnxt_mpc_send(tfcp->bp,
			   &mpc_msg_in,
			   &mpc_msg_out,
			   &mpc_opaque);
	if (rc) {
		netdev_dbg(bp->dev, "%s: EM insert send failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	netdev_dbg(bp->dev, "Rx Msg: size:%d\n", mpc_msg_out.msg_size);
	bnxt_tfc_buf_dump(bp, "EM insert", (uint8_t *)rx_msg, buff_len, 4, 4);

	/* Process response */
	for (i = 0; i < CFA_BLD_MPC_EM_INSERT_CMP_MAX_FLD; i++)
		fields_cmp[i].field_id = INVALID_U16;

	fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_STATUS_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMP_STATUS_FLD;
	fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_BKT_NUM_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMP_BKT_NUM_FLD;
	fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_NUM_ENTRIES_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMP_NUM_ENTRIES_FLD;
	fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_TABLE_INDEX3_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMP_TABLE_INDEX3_FLD;
	fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_CHAIN_UPD_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMP_CHAIN_UPD_FLD;
	fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_HASH_MSB_FLD].field_id =
		CFA_BLD_MPC_EM_INSERT_CMP_HASH_MSB_FLD;

	rc = mpc_info->mpcops->cfa_bld_mpc_parse_em_insert(rx_msg,
							   mpc_msg_out.msg_size,
							   fields_cmp);
	if (rc) {
		netdev_dbg(bp->dev, "%s: EM insert parse failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	netdev_dbg(bp->dev, "Hash MSB:0x%0x\n",
		   (u32)fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_HASH_MSB_FLD].val);

	if (fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_STATUS_FLD].val != CFA_BLD_MPC_OK) {
		netdev_dbg(bp->dev, "%s: MPC failed with status code:%d\n",
			   __func__,
			   (u32)fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_STATUS_FLD].val);
		rc = ((int)fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_STATUS_FLD].val) * -1;
		goto cleanup;
	}

	/* Update CPM info so it will determine best pool to use next alloc */
	rc = tfc_cpm_set_usage(cpm_lkup, pool_id, aparms.used_count, aparms.all_used);
	if (rc) {
		netdev_dbg(bp->dev, "%s: EM insert tfc_cpm_set_usage() failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	*parms->flow_handle = tfc_create_flow_handle(tsid,
						     num_contig_records, /* Based on key size */
						     entry_offset,
					fields_cmp[CFA_BLD_MPC_EM_INSERT_CMP_TABLE_INDEX3_FLD].val);

	kfree(tx_msg);
	kfree(rx_msg);
	return 0;

cleanup:
	/* Preserve the rc from the actual error rather than
	 * an error during cleanup.
	 */
	/* Free allocated resources */
	fparms.record_offset = aparms.record_offset;
	fparms.num_contig_records = num_contig_records;
	cleanup_rc = cfa_mm_free(cmm, &fparms);
	if (cleanup_rc)
		netdev_dbg(bp->dev, "%s: failed to free entry: %d\n",
			   __func__, rc);

	cleanup_rc = tfc_cpm_set_usage(cpm_lkup, pool_id, fparms.used_count, false);
	if (cleanup_rc)
		netdev_dbg(bp->dev, "%s: failed to set usage: %d\n",
			   __func__, rc);

	kfree(tx_msg);
	kfree(rx_msg);
	return rc;
}

int tfc_em_delete_raw(struct tfc *tfcp, u8 tsid, enum cfa_dir dir, u32 offset, u32 static_bucket)
{
	struct cfa_mpc_data_obj fields_cmp[CFA_BLD_MPC_EM_DELETE_CMP_MAX_FLD];
	struct cfa_mpc_data_obj fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_MAX_FLD];
	u32 mpc_opaque = TFC_MPC_OPAQUE_VAL;
	struct cfa_bld_mpcinfo *mpc_info;
	struct bnxt_mpc_mbuf mpc_msg_out;
	struct bnxt_mpc_mbuf mpc_msg_in;
	u8 tx_msg[TFC_MPC_MAX_TX_BYTES];
	u8 rx_msg[TFC_MPC_MAX_RX_BYTES];
	struct bnxt *bp = tfcp->bp;
	u32 buff_len;
	int i, rc;

	tfo_mpcinfo_get(tfcp->tfo, &mpc_info);
	if (!mpc_info->mpcops) {
		netdev_dbg(bp->dev, "%s: MPC not initialized\n", __func__);
		return -EINVAL;
	}

	/* Create MPC EM delete command using builder */
	for (i = 0; i < CFA_BLD_MPC_EM_DELETE_CMD_MAX_FLD; i++)
		fields_cmd[i].field_id = INVALID_U16;

	fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_OPAQUE_FLD].field_id =
		CFA_BLD_MPC_EM_DELETE_CMD_OPAQUE_FLD;
	fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_OPAQUE_FLD].val = 0xAA;
	fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_TABLE_SCOPE_FLD].field_id =
		CFA_BLD_MPC_EM_DELETE_CMD_TABLE_SCOPE_FLD;
	fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_TABLE_SCOPE_FLD].val = tsid;

	/* LREC address to delete */
	fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_TABLE_INDEX_FLD].field_id =
		CFA_BLD_MPC_EM_DELETE_CMD_TABLE_INDEX_FLD;
	fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_TABLE_INDEX_FLD].val = offset;

	fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_TABLE_INDEX2_FLD].field_id =
		CFA_BLD_MPC_EM_DELETE_CMD_TABLE_INDEX2_FLD;
	fields_cmd[CFA_BLD_MPC_EM_DELETE_CMD_TABLE_INDEX2_FLD].val = static_bucket;

	/* Create MPC EM delete command using builder */
	buff_len = TFC_MPC_MAX_TX_BYTES;

	rc = mpc_info->mpcops->cfa_bld_mpc_build_em_delete(tx_msg,
							   &buff_len,
							   fields_cmd);
	if (rc) {
		netdev_dbg(bp->dev, "%s: delete mpc build failed: %d\n", __func__, -rc);
		return -EINVAL;
	}

	netdev_dbg(bp->dev, "Tx Msg: size:%d\n", buff_len);
	bnxt_tfc_buf_dump(bp, "EM delete", (uint8_t *)tx_msg, buff_len, 4, 4);

	/* Send MPC */
	mpc_msg_in.chnl_id = (dir == CFA_DIR_TX ?
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_TE_CFA :
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_RE_CFA);
	mpc_msg_in.msg_data = &tx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_in.msg_size = 16;
	mpc_msg_out.cmp_type = MPC_CMP_TYPE_MID_PATH_LONG;
	mpc_msg_out.msg_data = &rx_msg[TFC_MPC_HEADER_SIZE_BYTES];
	mpc_msg_out.msg_size = TFC_MPC_MAX_RX_BYTES;

	netdev_dbg(bp->dev, "Tx Msg: size:%d\n", mpc_msg_out.msg_size);
	bnxt_tfc_buf_dump(bp, "EM Delete", (uint8_t *)tx_msg, buff_len, 4, 4);

	rc = bnxt_mpc_send(tfcp->bp,
			   &mpc_msg_in,
			   &mpc_msg_out,
			   &mpc_opaque);
	if (rc) {
		netdev_dbg(bp->dev, "%s: delete MPC send failed: %d\n", __func__, rc);
		return -EINVAL;
	}

	netdev_dbg(bp->dev, "Rx Msg: size:%d\n", mpc_msg_out.msg_size);
	bnxt_tfc_buf_dump(bp, "EM delete", (uint8_t *)rx_msg, buff_len, 4, 4);

	/* Process response */
	for (i = 0; i < CFA_BLD_MPC_EM_DELETE_CMP_MAX_FLD; i++)
		fields_cmp[i].field_id = INVALID_U16;

	fields_cmp[CFA_BLD_MPC_EM_DELETE_CMP_STATUS_FLD].field_id =
		CFA_BLD_MPC_EM_DELETE_CMP_STATUS_FLD;

	rc = mpc_info->mpcops->cfa_bld_mpc_parse_em_delete(rx_msg,
							   mpc_msg_out.msg_size,
							   fields_cmp);
	if (rc) {
		netdev_dbg(bp->dev, "%s: delete parse failed: %d\n", __func__, rc);
		return -EINVAL;
	}

	if (fields_cmp[CFA_BLD_MPC_EM_DELETE_CMP_STATUS_FLD].val != CFA_BLD_MPC_OK) {
		netdev_dbg(bp->dev, "%s: MPC failed with status code:%d\n", __func__,
			   (u32)fields_cmp[CFA_BLD_MPC_EM_DELETE_CMP_STATUS_FLD].val);
		rc = ((int)fields_cmp[CFA_BLD_MPC_EM_DELETE_CMP_STATUS_FLD].val) * -1;
		return rc;
	}

	return rc;
}

int tfc_em_delete(struct tfc *tfcp, struct tfc_em_delete_parms *parms)
{
	u32 static_bucket, record_offset, record_size, pool_id;
	bool is_bs_owner, is_shared, valid;
	struct cfa_mm_free_parms fparms;
	struct tfc_cpm *cpm_lkup = NULL;
	struct tfc_cpm *cpm_act = NULL;
	struct tfc_ts_mem_cfg mem_cfg;
	struct tfc_ts_pool_info pi;
	struct bnxt *bp = tfcp->bp;
	struct tfc_cmm *cmm;
	u8 tsid;
	int rc;

	/* Get fields from MPC Flow handle */
	tfc_get_fields_from_flow_handle(&parms->flow_handle,
					&tsid,
					&record_size,
					&record_offset,
					&static_bucket);

	rc = tfo_ts_get(tfcp->tfo, tsid, &is_shared, NULL, &valid, NULL);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get tsid: %d\n", __func__, rc);
		return -EINVAL;
	}
	if (!valid) {
		netdev_dbg(bp->dev, "%s: tsid not allocated %d\n", __func__, tsid);
		return -EINVAL;
	}

	rc = tfo_ts_get_pool_info(tfcp->tfo, tsid, parms->dir, &pi);
	if (rc) {
		netdev_dbg(bp->dev,
			   "%s: Failed to get pool info for tsid:%d\n",
			   __func__, tsid);
		return -EINVAL;
	}

	pool_id = TFC_FLOW_GET_POOL_ID(record_offset, pi.lkup_pool_sz_exp);

	rc = tfo_ts_get_mem_cfg(tfcp->tfo, tsid,
				parms->dir,
				CFA_REGION_TYPE_LKUP,
				&is_bs_owner,
				&mem_cfg);
	if (rc) {
		netdev_dbg(bp->dev, "%s: tfo_ts_get_mem_cfg() failed: %d\n", __func__, rc);
		return -EINVAL;
	}

	/* Get CPM instance for this table scope */
	rc = tfo_ts_get_cpm_inst(tfcp->tfo, tsid, parms->dir, &cpm_lkup, &cpm_act);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get CMM instance: %d\n", __func__, rc);
		return -EINVAL;
	}

	rc = tfc_em_delete_raw(tfcp,
			       tsid,
			       parms->dir,
			       record_offset +
			       mem_cfg.lkup_rec_start_offset,
			       static_bucket);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to delete em raw record, offset %u: %d\n",
			   __func__, record_offset + mem_cfg.lkup_rec_start_offset, rc);
		return -EINVAL;
	}

	rc = tfc_cpm_get_cmm_inst(cpm_lkup, pool_id, &cmm);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get CMM instance: %d\n", __func__, rc);
		return -EINVAL;
	}

	fparms.record_offset = record_offset;
	fparms.num_contig_records = roundup_pow_of_two(record_size);

	rc = cfa_mm_free(cmm, &fparms);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to free CMM instance: %d\n", __func__, rc);
		return -EINVAL;
	}

	rc = tfc_cpm_set_usage(cpm_lkup, pool_id, fparms.used_count, false);
	if (rc)
		netdev_dbg(bp->dev, "%s: failed to set usage: %d\n", __func__, rc);

	return rc;
}

static void bucket_decode(u32 *bucket_ptr,
			  struct bucket_info_t *bucket_info)
{
	int offset = 0;
	int i;

	bucket_info->valid = false;
	bucket_info->chain = tfc_getbits(bucket_ptr, 254, 1);
	bucket_info->chain_ptr = tfc_getbits(bucket_ptr, 228, 26);

	if  (bucket_info->chain ||
	     bucket_info->chain_ptr)
		bucket_info->valid = true;

	for (i = 0; i < TFC_BUCKET_ENTRIES; i++) {
		bucket_info->entries[i].entry_ptr = tfc_getbits(bucket_ptr, offset, 26);
		offset += 26;
		bucket_info->entries[i].hash_msb = tfc_getbits(bucket_ptr, offset, 12);
		offset += 12;
		if  (bucket_info->entries[i].hash_msb ||
		     bucket_info->entries[i].entry_ptr) {
			bucket_info->valid = true;
		}
	}
}

static int tfc_mpc_table_read(struct tfc *tfcp,
			      u8 tsid,
			      enum cfa_dir dir,
			      u32 type,
			      u32 offset,
			      u8 words,
			      u8 *data,
			      u8 debug)
{
	struct cfa_mpc_data_obj fields_cmd[CFA_BLD_MPC_READ_CMD_MAX_FLD];
	struct cfa_mpc_data_obj fields_cmp[CFA_BLD_MPC_READ_CMP_MAX_FLD];
	u32 mpc_opaque = TFC_MPC_OPAQUE_VAL;
	struct bnxt_mpc_mbuf mpc_msg_out;
	struct cfa_bld_mpcinfo *mpc_info;
	struct bnxt_mpc_mbuf mpc_msg_in;
	u8 tx_msg[TFC_MPC_MAX_TX_BYTES];
	u8 rx_msg[TFC_MPC_MAX_RX_BYTES];
	struct bnxt *bp = tfcp->bp;
	phys_addr_t host_address;
	bool is_shared, valid;
	u8 discard_data[128];
	u32 buff_len;
	u32 set, way;
	int i, rc;

	tfo_mpcinfo_get(tfcp->tfo, &mpc_info);

	rc = tfo_ts_get(tfcp->tfo, tsid, &is_shared, NULL, &valid, NULL);
	if (rc) {
		netdev_dbg(bp->dev, "%s: failed to get tsid: %d\n",
			   __func__, -rc);
		return -EINVAL;
	}
	if (!valid) {
		netdev_dbg(bp->dev, "%s: tsid not allocated %d\n",
			   __func__, tsid);
		return -EINVAL;
	}

	/* Check that data pointer is word aligned */
	if (((u64)data) & 0x1fULL) {
		netdev_dbg(bp->dev, "%s: Table read data pointer not word aligned\n",
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

	set = offset & 0x7ff;
	way = (offset >> 12)  & 0xf;

	if (debug)
		netdev_dbg(bp->dev,
			   "%s: Debug read table type:%s %d words32B at way:%d set:%d debug:%d words32B\n",
			   __func__,
			   (type == 0 ? "Lookup" : "Action"),
			   words,
			   way,
			   set,
			   debug);
	else
		netdev_dbg(bp->dev,
			   "%s: Reading table type:%s %d words32B at offset %d words32B\n",
			   __func__,
			   (type == 0 ? "Lookup" : "Action"),
			   words,
			   offset);

	/* Create MPC EM cache read  */
	for (i = 0; i < CFA_BLD_MPC_READ_CMD_MAX_FLD; i++)
		fields_cmd[i].field_id = INVALID_U16;

	fields_cmd[CFA_BLD_MPC_READ_CMD_OPAQUE_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_OPAQUE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_OPAQUE_FLD].val = 0xAA;

	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD].val = (type == 0 ?
	       CFA_BLD_MPC_HW_TABLE_TYPE_LOOKUP : CFA_BLD_MPC_HW_TABLE_TYPE_ACTION);

	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_SCOPE_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_TABLE_SCOPE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_SCOPE_FLD].val =
		(debug ? way : tsid);

	fields_cmd[CFA_BLD_MPC_READ_CMD_DATA_SIZE_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_DATA_SIZE_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_DATA_SIZE_FLD].val = words;

	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_INDEX_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_TABLE_INDEX_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_TABLE_INDEX_FLD].val =
		(debug ? set : offset);

	fields_cmd[CFA_BLD_MPC_READ_CMD_HOST_ADDRESS_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_HOST_ADDRESS_FLD;
	fields_cmd[CFA_BLD_MPC_READ_CMD_HOST_ADDRESS_FLD].val = (u64)host_address;

	if (debug) {
		fields_cmd[CFA_BLD_MPC_READ_CMD_CACHE_OPTION_FLD].field_id =
		CFA_BLD_MPC_READ_CMD_CACHE_OPTION_FLD;
		fields_cmd[CFA_BLD_MPC_READ_CMD_CACHE_OPTION_FLD].val = debug;
	}

	buff_len = TFC_MPC_MAX_TX_BYTES;

	rc = mpc_info->mpcops->cfa_bld_mpc_build_cache_read(tx_msg,
							    &buff_len,
							    fields_cmd);
	if (rc) {
		netdev_dbg(bp->dev, "%s: Action read build failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	/* Send MPC */
	mpc_msg_in.chnl_id = (dir == CFA_DIR_TX ?
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_TE_CFA :
			      RING_ALLOC_REQ_MPC_CHNLS_TYPE_RE_CFA);
	mpc_msg_in.msg_data = &tx_msg[16];
	mpc_msg_in.msg_size = 16;
	mpc_msg_out.cmp_type = MPC_CMP_TYPE_MID_PATH_SHORT;
	mpc_msg_out.msg_data = &rx_msg[16];
	mpc_msg_out.msg_size = TFC_MPC_MAX_RX_BYTES;

	rc = bnxt_mpc_send(tfcp->bp,
			   &mpc_msg_in,
			   &mpc_msg_out,
			   &mpc_opaque);
	if (rc) {
		netdev_dbg(bp->dev, "%s: Table read MPC send failed: %d\n",
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
							    words * TFC_MPC_BYTES_PER_WORD,
							    fields_cmp);
	if (rc) {
		netdev_dbg(bp->dev, "%s: Table read parse failed: %d\n",
			   __func__, rc);
		goto cleanup;
	}

	if (fields_cmp[CFA_BLD_MPC_READ_CMP_STATUS_FLD].val != CFA_BLD_MPC_OK) {
		netdev_dbg(bp->dev, "%s: Table read failed with status code:%d\n",
			   __func__,
			   (u32)fields_cmp[CFA_BLD_MPC_READ_CMP_STATUS_FLD].val);
		rc = -1;
		goto cleanup;
	}

	return 0;

 cleanup:

	return rc;
}

int tfc_em_delete_entries_by_pool_id(struct tfc *tfcp,
				     u8 tsid,
				     enum cfa_dir dir,
				     u16 pool_id,
				     u8 debug,
				     u8 *data)
{
	struct tfc_ts_mem_cfg mem_cfg;
	struct bucket_info_t *bucket;
	struct tfc_ts_pool_info pi;
	struct bnxt *bp = tfcp->bp;
	bool is_bs_owner;
	u32 offset;
	int rc;
	int i;
	int j;

	/* Get memory info */
	rc = tfo_ts_get_pool_info(tfcp->tfo, tsid, dir, &pi);
	if (rc) {
		netdev_dbg(bp->dev,
			   "%s: Failed to get pool info for tsid:%d\n",
			   __func__, tsid);
		return -EINVAL;
	}

	rc = tfo_ts_get_mem_cfg(tfcp->tfo,
				tsid,
				dir,
				CFA_REGION_TYPE_LKUP,
				&is_bs_owner,
				&mem_cfg);
	if (rc) {
		netdev_dbg(bp->dev, "%s: tfo_ts_get_mem_cfg() failed: %d\n",
			   __func__, rc);
		return -EINVAL;
	}

	bucket = kmalloc(sizeof(*bucket), GFP_KERNEL);
	if (!bucket)
		return -EINVAL;

	/* Read static bucket entries */
	for (offset = 0; offset < mem_cfg.lkup_rec_start_offset; ) {
		/* Read static bucket region of lookup table.
		 * A static bucket is 32B in size and must be 32B aligned.
		 * A table read can read up to 4 * 32B so in the interest
		 * of efficiency the max read size will be used.
		 */
		rc = tfc_mpc_table_read(tfcp,
					tsid,
					dir,
					CFA_REGION_TYPE_LKUP,
					offset,
					TFC_MPC_MAX_TABLE_READ_WORDS,
					data,
					debug);
		if (rc) {
			netdev_dbg(bp->dev,
				   "%s: tfc_mpc_table_read() failed for offset:%d: %d\n",
				   __func__, offset, rc);
			kfree(bucket);
			return -EINVAL;
		}

		for (i = 0; (i < TFC_MPC_MAX_TABLE_READ_WORDS) &&
		     (offset < mem_cfg.lkup_rec_start_offset); i++) {
			/* Walk static bucket entry pointers */
			bucket_decode((u32 *)&data[i * TFC_MPC_BYTES_PER_WORD],
				      bucket);

			for (j = 0; j < TFC_BUCKET_ENTRIES; j++) {
				if (bucket->entries[j].entry_ptr != 0 &&
				    pool_id == (bucket->entries[j].entry_ptr >>
						pi.lkup_pool_sz_exp)) {
					/* Delete EM entry */
					rc = tfc_em_delete_raw(tfcp,
							       tsid,
							       dir,
							       bucket->entries[j].entry_ptr,
							       offset);
					if (rc) {
						netdev_dbg(bp->dev,
							   "%s: EM delete failed offset:0x%08x %d\n",
							   __func__,
							   offset,
							   rc);
						kfree(bucket);
						return -1;
					}
				}
			}

			offset++;
		}
	}

	kfree(bucket);
	return rc;
}
