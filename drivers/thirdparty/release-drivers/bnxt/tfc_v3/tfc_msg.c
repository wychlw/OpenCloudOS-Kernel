// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2023 Broadcom
 * All rights reserved.
 */

#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include "tfc_msg.h"
#include "bnxt_hsi.h"
#include "bnxt_compat.h"
#include "bnxt.h"
#include "bnxt_hwrm.h"
#include "tfo.h"

/* Logging defines */
#define TFC_RM_MSG_DEBUG  0

#define CFA_INVALID_FID 0xFFFF

/* This is the MAX data we can transport across regular HWRM */
#define TFC_PCI_BUF_SIZE_MAX 80

struct tfc_msg_dma_buf {
	void *va_addr;
	dma_addr_t pa_addr;
};

static int tfc_msg_set_fid(struct bnxt *bp, u16 req_fid, u16 *msg_fid)
{
	/* Set request FID to 0xffff in case the request FID is the same as the
	 * target FID (bp->fw_fid). If we're on a TVF or if this is a PF, then
	 * set the FID to the requested FID.
	 *
	 * The firmware validates the FID and accepts/rejects the request based
	 * on these rules:
	 *
	 *   1. (request_fid == 0xffff), final_fid = target_fid, accept
	 *   2. IS_PF(request_fid):
	 *      reject, Only (1) above is allowed
	 *   3. IS_PF(target_fid) && IS_VF(request_fid):
	 *      if(target_fid == parent_of(request_fid)) accept, else reject
	 *   4. IS_VF(target_fid) && IS_VF(request_fid):
	 *      if(parent_of(target_fid) == parent_of(request_fid)) accept, else reject
	 *
	 *   Note: for cases 2..4, final_fid = request_fid
	 */
	if (bp->pf.fw_fid == req_fid)
		*msg_fid = CFA_INVALID_FID;
	else if (BNXT_VF_IS_TRUSTED(bp) || BNXT_PF(bp))
		*msg_fid = cpu_to_le16(req_fid);
	else
		return -EINVAL;
	return 0;
}

/* If data bigger than TFC_PCI_BUF_SIZE_MAX then use DMA method */
int
tfc_msg_tbl_scope_qcaps(struct tfc *tfcp, bool *tbl_scope_capable, u32 *max_lkup_rec_cnt,
			u32 *max_act_rec_cnt, u8 *max_lkup_static_buckets_exp)
{
	struct hwrm_tfc_tbl_scope_qcaps_output *resp;
	struct hwrm_tfc_tbl_scope_qcaps_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	if (!tbl_scope_capable) {
		netdev_dbg(bp->dev, "%s: Invalid tbl_scope_capable pointer\n", __func__);
		return -EINVAL;
	}

	*tbl_scope_capable = false;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TBL_SCOPE_QCAPS);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	if (resp->tbl_scope_capable) {
		*tbl_scope_capable = true;
		if (max_lkup_rec_cnt)
			*max_lkup_rec_cnt =
				le32_to_cpu(resp->max_lkup_rec_cnt);
		if (max_act_rec_cnt)
			*max_act_rec_cnt =
				le32_to_cpu(resp->max_act_rec_cnt);
		if (max_lkup_static_buckets_exp)
			*max_lkup_static_buckets_exp =
				resp->max_lkup_static_buckets_exp;
	}

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: Success\n", __func__);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tbl_scope_id_alloc(struct tfc *tfcp, u16 fid, bool shared, enum cfa_app_type app_type,
			   u8 *tsid, bool *first)
{
	struct hwrm_tfc_tbl_scope_id_alloc_output *resp;
	struct hwrm_tfc_tbl_scope_id_alloc_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	if (!tsid) {
		netdev_dbg(bp->dev, "%s: Invalid tsid pointer\n", __func__);
		return -EINVAL;
	}

	rc = hwrm_req_init(bp, req, HWRM_TFC_TBL_SCOPE_ID_ALLOC);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	req->app_type = app_type;
	req->shared = shared;

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	*tsid = resp->tsid;
	if (first) {
		if (resp->first)
			*first = true;
		else
			*first = false;
	}

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: tsid %d first %d Success\n", __func__,
			   *tsid, *first);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

#define RE_LKUP 0
#define RE_ACT  1
#define TE_LKUP 2
#define TE_ACT  3

/*  Given the direction and the region return the backing store cfg instance */
static int tfc_tbl_scope_region_dir_to_inst(struct bnxt *bp,
					    enum cfa_region_type region,
					    enum cfa_dir dir, u16 *instance)
{
	if (!instance) {
		netdev_dbg(bp->dev, "%s: Invalid tfcp pointer\n", __func__);
		return -EINVAL;
	}
	switch (region) {
	case CFA_REGION_TYPE_LKUP:
		if (dir == CFA_DIR_RX)
			*instance = RE_LKUP;
		else
			*instance = TE_LKUP;
		break;
	case CFA_REGION_TYPE_ACT:
		if (dir == CFA_DIR_RX)
			*instance = RE_ACT;
		else
			*instance = TE_ACT;
		break;
	default:
		netdev_dbg(bp->dev, "%s: Invalid region\n", __func__);
		return -EINVAL;
	}
	return 0;
}

/* Given the page_sz_bytes and pbl_level, encode the pg_sz_pbl_level */
static int tfc_tbl_scope_pg_sz_pbl_level_encode(struct bnxt *bp,
						u32 page_sz_in_bytes,
						u8 pbl_level,
						u8 *page_sz_pbl_level)
{
	u8 page_sz;

	switch (page_sz_in_bytes) {
	case 0x1000:		/* 4K */
		page_sz = FUNC_BACKING_STORE_CFG_V2_REQ_PAGE_SIZE_PG_4K;
		break;
	case 0x2000:		/* 8K */
		page_sz = FUNC_BACKING_STORE_CFG_V2_REQ_PAGE_SIZE_PG_8K;
		break;
	case 0x10000:		/* 64K */
		page_sz = FUNC_BACKING_STORE_CFG_V2_REQ_PAGE_SIZE_PG_64K;
		break;
	case 0x200000:		/* 2M */
		page_sz = FUNC_BACKING_STORE_CFG_V2_REQ_PAGE_SIZE_PG_2M;
		break;
	case 0x40000000:	/* 1G */
		page_sz = FUNC_BACKING_STORE_CFG_V2_REQ_PAGE_SIZE_PG_1G;
		break;
	default:
		netdev_dbg(bp->dev, "%s: Unsupported page size (0x%x)\n", __func__,
			   page_sz_in_bytes);
		return -EINVAL;
	}
	/* Page size value is already shifted */
	*page_sz_pbl_level = page_sz;
	if (pbl_level > 2) {
		netdev_dbg(bp->dev, "%s: Invalid pbl_level(%d)\n", __func__, pbl_level);
		return -EINVAL;
	}
	*page_sz_pbl_level |= pbl_level;
	return 0;
}

int
tfc_msg_backing_store_cfg_v2(struct tfc *tfcp, u8 tsid, enum cfa_dir dir,
			     enum cfa_region_type region, u64 base_addr,
			     u8 pbl_level, u32 pbl_page_sz_in_bytes,
			     u32 rec_cnt, u8 static_bkt_cnt_exp,
			     bool cfg_done)
{
	struct hwrm_func_backing_store_cfg_v2_input *req;
	struct ts_split_entries *ts_sp;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_FUNC_BACKING_STORE_CFG_V2);
	if (rc)
		return rc;

	ts_sp = (struct ts_split_entries *)&req->split_entry_0;
	ts_sp->tsid = tsid;
	ts_sp->lkup_static_bkt_cnt_exp[dir] = static_bkt_cnt_exp;
	ts_sp->region_num_entries = rec_cnt;
	if (cfg_done)
		req->flags |= FUNC_BACKING_STORE_CFG_V2_REQ_FLAGS_BS_CFG_ALL_DONE;

	rc = tfc_tbl_scope_region_dir_to_inst(bp, region, dir, &req->instance);
	if (rc)
		return rc;

	req->page_dir = cpu_to_le64(base_addr);
	req->num_entries = cpu_to_le32(rec_cnt);

	req->type = FUNC_BACKING_STORE_CFG_V2_REQ_TYPE_TBL_SCOPE;

	rc = tfc_tbl_scope_pg_sz_pbl_level_encode(bp, pbl_page_sz_in_bytes,
						  pbl_level, &req->page_size_pbl_level);
	if (rc)
		return rc;

	/* send the request */
	rc = hwrm_req_send(bp, req);

	if (rc)
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tbl_scope_deconfig(struct tfc *tfcp, u8 tsid)
{
	struct hwrm_tfc_tbl_scope_deconfig_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TBL_SCOPE_DECONFIG);
	if (rc)
		return rc;

	req->tsid = tsid;
	rc = hwrm_req_send(bp, req);

	if (rc)
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tbl_scope_fid_add(struct tfc *tfcp, u16 fid, u8 tsid, u16 *fid_cnt)
{
	struct hwrm_tfc_tbl_scope_fid_add_output *resp;
	struct hwrm_tfc_tbl_scope_fid_add_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TBL_SCOPE_FID_ADD);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->tsid = tsid;
	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	if (fid_cnt)
		*fid_cnt = le16_to_cpu(resp->fid_cnt);

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: Success\n", __func__);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tbl_scope_fid_rem(struct tfc *tfcp, u16 fid, u8 tsid, u16 *fid_cnt)
{
	struct hwrm_tfc_tbl_scope_fid_rem_output *resp;
	struct hwrm_tfc_tbl_scope_fid_rem_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TBL_SCOPE_FID_REM);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->tsid = tsid;
	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	if (fid_cnt)
		*fid_cnt = le16_to_cpu(resp->fid_cnt);

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: Success\n", __func__);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_idx_tbl_alloc(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_track_type tt, enum cfa_dir dir,
		      enum cfa_resource_subtype_idx_tbl subtype, u16 *id)

{
	struct hwrm_tfc_idx_tbl_alloc_output *resp;
	struct hwrm_tfc_idx_tbl_alloc_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IDX_TBL_ALLOC);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	if (dir == CFA_DIR_RX)
		req->flags |= TFC_IDX_TBL_ALLOC_REQ_FLAGS_DIR_RX &
			      TFC_IDX_TBL_ALLOC_REQ_FLAGS_DIR;
	else
		req->flags |= TFC_IDX_TBL_ALLOC_REQ_FLAGS_DIR_TX &
			      TFC_IDX_TBL_ALLOC_REQ_FLAGS_DIR;

	if (tt == CFA_TRACK_TYPE_FID)
		req->track_type = TFC_IDX_TBL_ALLOC_REQ_TRACK_TYPE_TRACK_TYPE_FID;
	else
		req->track_type = TFC_IDX_TBL_ALLOC_REQ_TRACK_TYPE_TRACK_TYPE_SID;

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->subtype = cpu_to_le16(subtype);

	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	*id = le16_to_cpu(resp->idx_tbl_id);

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: idx_tbl_id %d Success\n", __func__, *id);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_idx_tbl_alloc_set(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_track_type tt,
			  enum cfa_dir dir, enum cfa_resource_subtype_idx_tbl subtype,
			  const u32 *dev_data, u8 data_size, u16 *id)

{
	struct hwrm_tfc_idx_tbl_alloc_set_output *resp;
	struct hwrm_tfc_idx_tbl_alloc_set_input *req;
	struct tfc_msg_dma_buf buf = { 0 };
	struct bnxt *bp = tfcp->bp;
	u8 *data = NULL;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IDX_TBL_ALLOC_SET);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	if (dir == CFA_DIR_RX)
		req->flags |= TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR_RX &
			      TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR;
	else
		req->flags |= TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR_TX &
			      TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR;

	if (tt == CFA_TRACK_TYPE_FID)
		req->track_type = TFC_IDX_TBL_ALLOC_SET_REQ_TRACK_TYPE_TRACK_TYPE_FID;
	else
		req->track_type = TFC_IDX_TBL_ALLOC_SET_REQ_TRACK_TYPE_TRACK_TYPE_SID;

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->subtype = cpu_to_le16(subtype);
	req->data_size = cpu_to_le16(data_size);

	if (req->data_size >= sizeof(req->dev_data)) {
		/* Prepare DMA buffer */
		req->flags |= TFC_IDX_TBL_SET_REQ_FLAGS_DMA;
		hwrm_req_alloc_flags(bp, req, GFP_KERNEL | __GFP_ZERO);
		buf.va_addr = dma_alloc_coherent(&bp->pdev->dev, req->data_size,
						 &buf.pa_addr, GFP_KERNEL);

		if (!buf.va_addr) {
			rc = -ENOMEM;
			goto cleanup;
		}

		data = buf.va_addr;
		req->dma_addr = cpu_to_le64(buf.pa_addr);
	} else {
		data = &req->dev_data[0];
	}

	memcpy(&data[0], &dev_data[0], req->data_size);

	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	*id = le16_to_cpu(resp->idx_tbl_id);

cleanup:
	if (buf.va_addr)
		dma_free_coherent(&bp->pdev->dev, req->data_size, buf.va_addr, buf.pa_addr);

	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: idx_tbl_id %d Success\n", __func__, *id);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_idx_tbl_set(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_dir dir,
		    enum cfa_resource_subtype_idx_tbl subtype, u16 id,
		    const u32 *dev_data, u8 data_size)
{
	struct hwrm_tfc_idx_tbl_set_input *req;
	struct tfc_msg_dma_buf buf = { 0 };
	struct bnxt *bp = tfcp->bp;
	int dma_size = 0, rc;
	u8 *data = NULL;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IDX_TBL_SET);
	if (rc)
		return rc;

	if (dir == CFA_DIR_RX)
		req->flags |= TFC_IDX_TBL_SET_REQ_FLAGS_DIR_RX &
			      TFC_IDX_TBL_SET_REQ_FLAGS_DIR;
	else
		req->flags |= TFC_IDX_TBL_SET_REQ_FLAGS_DIR_TX &
			      TFC_IDX_TBL_SET_REQ_FLAGS_DIR;

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->idx_tbl_id = cpu_to_le16(id);
	req->subtype = cpu_to_le16(subtype);
	req->data_size = cpu_to_le16(data_size);

	if (req->data_size >= sizeof(req->dev_data)) {
		/* Prepare DMA buffer */
		req->flags |= TFC_IDX_TBL_SET_REQ_FLAGS_DMA;
		hwrm_req_alloc_flags(bp, req, GFP_KERNEL | __GFP_ZERO);
		buf.va_addr = dma_alloc_coherent(&bp->pdev->dev, req->data_size,
						 &buf.pa_addr, GFP_KERNEL);

		if (!buf.va_addr) {
			rc = -ENOMEM;
			goto cleanup;
		}

		data = buf.va_addr;
		req->dma_addr = cpu_to_le64(buf.pa_addr);
	} else {
		data = &req->dev_data[0];
	}

	memcpy(&data[0], &dev_data[0], req->data_size);
	rc = hwrm_req_send(bp, req);

cleanup:
	if (buf.va_addr)
		dma_free_coherent(&bp->pdev->dev, dma_size, buf.va_addr, buf.pa_addr);

	if (!rc)
		netdev_dbg(bp->dev, "%s: Success\n", __func__);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_idx_tbl_get(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_dir dir,
		    enum cfa_resource_subtype_idx_tbl subtype, u16 id,
		    u32 *dev_data, u8 *data_size)
{
	struct hwrm_tfc_idx_tbl_get_output *resp;
	struct hwrm_tfc_idx_tbl_get_input *req;
	struct tfc_msg_dma_buf buf = { 0 };
	struct bnxt *bp = tfcp->bp;
	int dma_size, rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IDX_TBL_GET);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	/* Prepare DMA buffer */
	hwrm_req_alloc_flags(bp, req, GFP_KERNEL | __GFP_ZERO);
	dma_size = sizeof(*data_size);
	buf.va_addr = dma_alloc_coherent(&bp->pdev->dev, dma_size,
					 &buf.pa_addr, GFP_KERNEL);

	if (!buf.va_addr) {
		rc = -ENOMEM;
		goto cleanup;
	}

	if (dir == CFA_DIR_RX)
		req->flags |= TFC_IDX_TBL_GET_REQ_FLAGS_DIR_RX &
			      TFC_IDX_TBL_GET_REQ_FLAGS_DIR;
	else
		req->flags |= TFC_IDX_TBL_GET_REQ_FLAGS_DIR_TX &
			      TFC_IDX_TBL_GET_REQ_FLAGS_DIR;

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->idx_tbl_id = cpu_to_le16(id);
	req->subtype = cpu_to_le16(subtype);
	req->buffer_size = cpu_to_le16(*data_size);
	req->dma_addr = cpu_to_le64(buf.pa_addr);

	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	memcpy(dev_data, buf.va_addr, resp->data_size);
	*data_size = le16_to_cpu(resp->data_size);

cleanup:
	if (buf.va_addr)
		dma_free_coherent(&bp->pdev->dev, dma_size,
				  buf.va_addr, buf.pa_addr);

	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: data_size %d Success\n", __func__, *data_size);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_idx_tbl_free(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_dir dir,
		     enum cfa_resource_subtype_idx_tbl subtype, u16 id)
{
	struct hwrm_tfc_idx_tbl_free_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IDX_TBL_FREE);
	if (rc)
		return rc;

	if (dir == CFA_DIR_RX)
		req->flags |= TFC_IDX_TBL_FREE_REQ_FLAGS_DIR_RX &
			      TFC_IDX_TBL_FREE_REQ_FLAGS_DIR;
	else
		req->flags |= TFC_IDX_TBL_FREE_REQ_FLAGS_DIR_TX &
			      TFC_IDX_TBL_FREE_REQ_FLAGS_DIR;

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		return rc;

	req->sid = cpu_to_le16(sid);
	req->idx_tbl_id = cpu_to_le16(id);
	req->subtype = cpu_to_le16(subtype);

	rc = hwrm_req_send(bp, req);

	if (rc)
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int tfc_msg_global_id_alloc(struct tfc *tfcp, u16 fid, u16 sid,
			    enum tfc_domain_id domain_id, u16 req_cnt,
			    const struct tfc_global_id_req *glb_id_req,
			    struct tfc_global_id *rsp, u16 *rsp_cnt,
			    bool *first)
{
	struct hwrm_tfc_global_id_alloc_output *resp;
	struct hwrm_tfc_global_id_alloc_input *req;
	struct tfc_global_id_hwrm_req *req_data;
	struct tfc_global_id_hwrm_rsp *rsp_data;
	struct tfc_msg_dma_buf req_buf = { 0 };
	struct tfc_msg_dma_buf rsp_buf = { 0 };
	int i = 0, rc, resp_cnt = 0;
	struct bnxt *bp = tfcp->bp;
	int dma_size_req = 0;
	int dma_size_rsp = 0;

	rc = hwrm_req_init(bp, req, HWRM_TFC_GLOBAL_ID_ALLOC);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	/* Prepare DMA buffers */
	dma_size_req = req_cnt * sizeof(struct tfc_global_id_req);
	hwrm_req_alloc_flags(bp, req, GFP_KERNEL | __GFP_ZERO);
	req_buf.va_addr = dma_alloc_coherent(&bp->pdev->dev, dma_size_req,
					     &req_buf.pa_addr, GFP_KERNEL);

	if (!req_buf.va_addr) {
		rc = -ENOMEM;
		goto cleanup;
	}

	for (i = 0; i < req_cnt; i++)
		resp_cnt += glb_id_req->cnt;

	dma_size_rsp = resp_cnt * sizeof(struct tfc_global_id);
	rsp_buf.va_addr = dma_alloc_coherent(&bp->pdev->dev, dma_size_rsp,
					     &rsp_buf.pa_addr, GFP_KERNEL);

	if (!rsp_buf.va_addr) {
		rc = -ENOMEM;
		goto cleanup;
	}

	/* Populate the request */
	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->global_id = cpu_to_le16(domain_id);
	req->req_cnt = req_cnt;
	req->req_addr = cpu_to_le64(req_buf.pa_addr);
	req->resc_addr = cpu_to_le64(rsp_buf.pa_addr);
	req_data = (struct tfc_global_id_hwrm_req *)req_buf.va_addr;
	for (i = 0; i < req_cnt; i++) {
		req_data[i].rtype = cpu_to_le16(glb_id_req[i].rtype);
		req_data[i].dir = cpu_to_le16(glb_id_req[i].dir);
		req_data[i].subtype = cpu_to_le16(glb_id_req[i].rsubtype);
		req_data[i].cnt = cpu_to_le16(glb_id_req[i].cnt);
	}

	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	if (first) {
		if (resp->first)
			*first = true;
		else
			*first = false;
	}

	/* Process the response
	 * Should always get expected number of entries
	 */
	if (le32_to_cpu(resp->rsp_cnt) != *rsp_cnt) {
		rc = -EINVAL;
		netdev_dbg(bp->dev, "Alloc message size error, rc:%d\n", rc);
		goto cleanup;
	}

	rsp_data = (struct tfc_global_id_hwrm_rsp *)rsp_buf.va_addr;
	for (i = 0; i < resp->rsp_cnt; i++) {
		rsp[i].rtype = le32_to_cpu(rsp_data[i].rtype);
		rsp[i].dir = le32_to_cpu(rsp_data[i].dir);
		rsp[i].rsubtype = le32_to_cpu(rsp_data[i].subtype);
		rsp[i].id = le32_to_cpu(rsp_data[i].id);
	}

cleanup:
	if (req_buf.va_addr)
		dma_free_coherent(&bp->pdev->dev, dma_size_req,
				  req_buf.va_addr, req_buf.pa_addr);

	if (rsp_buf.va_addr)
		dma_free_coherent(&bp->pdev->dev, dma_size_rsp,
				  rsp_buf.va_addr, rsp_buf.pa_addr);

	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: first %d Success\n", __func__, *first);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tbl_scope_config_get(struct tfc *tfcp, u8 tsid, bool *configured)
{
	struct hwrm_tfc_tbl_scope_config_get_output *resp;
	struct hwrm_tfc_tbl_scope_config_get_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TBL_SCOPE_CONFIG_GET);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	req->tsid = tsid;
	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	*configured = le16_to_cpu(resp->configured) ? true : false;

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: configured %d Success\n", __func__, *configured);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_session_id_alloc(struct tfc *tfcp, u16 fid, u16 *sid)
{
	struct hwrm_tfc_session_id_alloc_output *resp;
	struct hwrm_tfc_session_id_alloc_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_SESSION_ID_ALLOC);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	*sid = le16_to_cpu(resp->sid);

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: sid %d Success\n", __func__, *sid);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_session_fid_add(struct tfc *tfcp, u16 fid, u16 sid, u16 *fid_cnt)
{
	struct hwrm_tfc_session_fid_add_output *resp;
	struct hwrm_tfc_session_fid_add_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_SESSION_FID_ADD);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);

	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	if (fid_cnt)
		*fid_cnt = le16_to_cpu(resp->fid_cnt);

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: Success\n", __func__);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_session_fid_rem(struct tfc *tfcp, u16 fid, u16 sid, u16 *fid_cnt)
{
	struct hwrm_tfc_session_fid_rem_output *resp;
	struct hwrm_tfc_session_fid_rem_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_SESSION_FID_REM);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);

	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	if (fid_cnt)
		*fid_cnt = le16_to_cpu(resp->fid_cnt);

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: Success\n", __func__);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

static int tfc_msg_set_tt(struct bnxt *bp, enum cfa_track_type tt, u8 *ptt)
{
	switch (tt) {
	case CFA_TRACK_TYPE_SID:
		*ptt = TFC_IDENT_ALLOC_REQ_TRACK_TYPE_TRACK_TYPE_SID;
		break;
	case CFA_TRACK_TYPE_FID:
		*ptt = TFC_IDENT_ALLOC_REQ_TRACK_TYPE_TRACK_TYPE_FID;
		break;
	default:
		netdev_dbg(bp->dev, "%s: Invalid tt[%u]\n", __func__, tt);
		return -EINVAL;
	}

	return 0;
}

int tfc_msg_identifier_alloc(struct tfc *tfcp, enum cfa_dir dir,
			     enum cfa_resource_subtype_ident subtype,
			     enum cfa_track_type tt, u16 fid, u16 sid, u16 *ident_id)
{
	struct hwrm_tfc_ident_alloc_output *resp;
	struct hwrm_tfc_ident_alloc_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IDENT_ALLOC);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	req->flags = (dir == CFA_DIR_TX ?
		     TFC_IDENT_ALLOC_REQ_FLAGS_DIR_TX :
		     TFC_IDENT_ALLOC_REQ_FLAGS_DIR_RX);

	rc = tfc_msg_set_tt(bp, tt, &req->track_type);
	if (rc)
		goto cleanup;

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->subtype = subtype;

	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	*ident_id = le16_to_cpu(resp->ident_id);

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: ident_id %d Success\n", __func__, *ident_id);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int tfc_msg_identifier_free(struct tfc *tfcp, enum cfa_dir dir,
			    enum cfa_resource_subtype_ident subtype,
			    u16 fid, u16 sid, u16 ident_id)
{
	struct hwrm_tfc_ident_free_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IDENT_FREE);
	if (rc)
		return rc;

	req->flags = (dir == CFA_DIR_TX ?
		     TFC_IDENT_FREE_REQ_FLAGS_DIR_TX :
		     TFC_IDENT_FREE_REQ_FLAGS_DIR_RX);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		return rc;

	req->sid = cpu_to_le16(sid);
	req->subtype = subtype;
	req->ident_id = ident_id;

	/* send the request */
	rc = hwrm_req_send(bp, req);

	if (rc)
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);
	return rc;
}

int
tfc_msg_tcam_alloc(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_dir dir,
		   enum cfa_resource_subtype_tcam subtype,
		   enum cfa_track_type tt, u16 pri, u16 key_sz_bytes,
		   u16 *tcam_id)
{
	struct hwrm_tfc_tcam_alloc_output *resp;
	struct hwrm_tfc_tcam_alloc_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TCAM_ALLOC);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	req->flags = (dir == CFA_DIR_TX ?
		     TFC_TCAM_ALLOC_REQ_FLAGS_DIR_TX :
		     TFC_TCAM_ALLOC_REQ_FLAGS_DIR_RX);

	req->track_type = (tt == CFA_TRACK_TYPE_FID ?
			  TFC_TCAM_ALLOC_REQ_TRACK_TYPE_TRACK_TYPE_FID :
			  TFC_TCAM_ALLOC_REQ_TRACK_TYPE_TRACK_TYPE_SID);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->subtype = cpu_to_le16(subtype);
	req->priority = cpu_to_le16(pri);
	req->key_size = cpu_to_le16(key_sz_bytes);

	/* send the request */
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	*tcam_id = resp->idx;

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: tcam_id %d Success\n", __func__, *tcam_id);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tcam_alloc_set(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_dir dir,
		       enum cfa_resource_subtype_tcam subtype,
		       enum cfa_track_type tt, u16 *tcam_id, u16 pri,
		       const u8 *key, u8 key_size, const u8 *mask,
		       const u8 *remap, u8 remap_size)
{
	struct hwrm_tfc_tcam_alloc_set_output *resp;
	struct hwrm_tfc_tcam_alloc_set_input *req;
	struct tfc_msg_dma_buf buf = { 0 };
	struct bnxt *bp = tfcp->bp;
	int data_size = 0, rc;
	u8 *data = NULL;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TCAM_ALLOC_SET);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	if (dir == CFA_DIR_RX)
		req->flags |= TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR_RX &
			      TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR;
	else
		req->flags |= TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR_TX &
			      TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR;

	req->track_type = (tt == CFA_TRACK_TYPE_FID ?
			  TFC_TCAM_ALLOC_SET_REQ_TRACK_TYPE_TRACK_TYPE_FID :
			  TFC_TCAM_ALLOC_SET_REQ_TRACK_TYPE_TRACK_TYPE_SID);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->subtype = cpu_to_le16(subtype);
	req->key_size = cpu_to_le16(key_size);
	req->priority = cpu_to_le16(pri);
	req->result_size = cpu_to_le16(remap_size);
	data_size = 2 * req->key_size + req->result_size;

	if (data_size > TFC_PCI_BUF_SIZE_MAX) {
		/* Prepare DMA buffer */
		req->flags |= TFC_TCAM_ALLOC_SET_REQ_FLAGS_DMA;
		hwrm_req_alloc_flags(bp, req, GFP_KERNEL | __GFP_ZERO);
		buf.va_addr = dma_alloc_coherent(&bp->pdev->dev, data_size,
						 &buf.pa_addr, GFP_KERNEL);

		if (!buf.va_addr) {
			rc = -ENOMEM;
			goto cleanup;
		}

		data = buf.va_addr;
		req->dma_addr = cpu_to_le64(buf.pa_addr);
	} else {
		data = &req->dev_data[0];
	}

	memcpy(&data[0], &key, key_size * sizeof(u32));
	memcpy(&data[key_size], &mask, key_size * sizeof(u32));
	memcpy(&data[key_size * 2], &remap, remap_size * sizeof(u32));

	rc = hwrm_req_send(bp, req);
	if (rc)
		goto cleanup;

	*tcam_id = resp->tcam_id;

cleanup:
	if (buf.va_addr)
		dma_free_coherent(&bp->pdev->dev, data_size,
				  buf.va_addr, buf.pa_addr);

	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: tcam_id %d Success\n", __func__, *tcam_id);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tcam_set(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_dir dir,
		 enum cfa_resource_subtype_tcam subtype,
		 u16 tcam_id, const u8 *key, u8 key_size,
		 const u8 *mask, const u8 *remap,
		 u8 remap_size)
{
	struct hwrm_tfc_tcam_set_input *req;
	struct tfc_msg_dma_buf buf = { 0 };
	struct bnxt *bp = tfcp->bp;
	int data_size = 0, rc;
	u8 *data = NULL;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TCAM_SET);
	if (rc)
		return rc;

	if (dir == CFA_DIR_RX)
		req->flags |= TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR_RX &
			      TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR;
	else
		req->flags |= TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR_TX &
			      TFC_IDX_TBL_ALLOC_SET_REQ_FLAGS_DIR;

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->tcam_id = cpu_to_le16(tcam_id);
	req->subtype = cpu_to_le16(subtype);
	req->key_size = cpu_to_le16(key_size);
	req->result_size = cpu_to_le16(remap_size);
	data_size = 2 * req->key_size + req->result_size;

	if (data_size > TFC_PCI_BUF_SIZE_MAX) {
		req->flags |= TF_TCAM_SET_REQ_FLAGS_DMA;
		hwrm_req_alloc_flags(bp, req, GFP_KERNEL | __GFP_ZERO);
		buf.va_addr = dma_alloc_coherent(&bp->pdev->dev, data_size,
						 &buf.pa_addr, GFP_KERNEL);

		if (!buf.va_addr) {
			rc = -ENOMEM;
			goto cleanup;
		}

		data = buf.va_addr;
		req->dma_addr = cpu_to_le64(buf.pa_addr);
	} else {
		data = &req->dev_data[0];
	}

	memcpy(&data[0], key, key_size);
	memcpy(&data[key_size], mask, key_size);
	memcpy(&data[key_size * 2], remap, remap_size);

	rc = hwrm_req_send(bp, req);

cleanup:
	if (buf.va_addr)
		dma_free_coherent(&bp->pdev->dev, data_size,
				  buf.va_addr, buf.pa_addr);

	if (!rc)
		netdev_dbg(bp->dev, "%s: Success\n", __func__);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tcam_get(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_dir dir,
		 enum cfa_resource_subtype_tcam subtype,
		 u16 tcam_id, u8 *key, u8 *key_size,
		 u8 *mask, u8 *remap, u8 *remap_size)
{
	struct hwrm_tfc_tcam_get_output *resp;
	struct hwrm_tfc_tcam_get_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TCAM_GET);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	req->flags = (dir == CFA_DIR_TX ?
		     TFC_TCAM_GET_REQ_FLAGS_DIR_TX :
		     TFC_TCAM_GET_REQ_FLAGS_DIR_RX);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		goto cleanup;

	req->sid = cpu_to_le16(sid);
	req->tcam_id = cpu_to_le16(tcam_id);
	req->subtype = cpu_to_le16(subtype);

	rc = hwrm_req_send(bp, req);
	if (rc ||
	    *key_size < le16_to_cpu(resp->key_size) ||
	    *remap_size < le16_to_cpu(resp->result_size)) {
		netdev_dbg(bp->dev, "Key buffer is too small, rc:%d\n", -EINVAL);
		goto cleanup;
	}

	*key_size = resp->key_size;
	*remap_size = resp->result_size;
	memcpy(key, &resp->dev_data[0], resp->key_size);
	memcpy(mask, &resp->dev_data[resp->key_size], resp->key_size);
	memcpy(remap, &resp->dev_data[resp->key_size * 2], resp->result_size);

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: key_size %d remap_size %d Success\n",
			   __func__, *key_size, *remap_size);
	else
		rc = -EINVAL;

	if (rc)
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}

int
tfc_msg_tcam_free(struct tfc *tfcp, u16 fid, u16 sid, enum cfa_dir dir,
		  enum cfa_resource_subtype_tcam subtype, u16 tcam_id)
{
	struct hwrm_tfc_tcam_free_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_TCAM_FREE);
	if (rc)
		return rc;

	req->flags = (dir == CFA_DIR_TX ?
		     TFC_TCAM_FREE_REQ_FLAGS_DIR_TX :
		     TFC_TCAM_FREE_REQ_FLAGS_DIR_RX);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		return rc;

	req->sid = cpu_to_le16(sid);
	req->tcam_id = cpu_to_le16(tcam_id);
	req->subtype = cpu_to_le16(subtype);

	rc = hwrm_req_send(bp, req);
	if (rc)
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);
	return rc;
}

int
tfc_msg_if_tbl_set(struct tfc *tfcp, u16 fid, u16 sid,
		   enum cfa_dir dir, enum cfa_resource_subtype_if_tbl subtype,
		   u16 index, u8 data_size, const u8 *data)
{
	struct hwrm_tfc_if_tbl_set_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IF_TBL_SET);
	if (rc)
		return rc;

	req->flags = (dir == CFA_DIR_TX ?
		    TFC_IF_TBL_SET_REQ_FLAGS_DIR_TX :
		    TFC_IF_TBL_SET_REQ_FLAGS_DIR_RX);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc)
		return rc;
	req->sid = cpu_to_le16(sid);

	req->index = cpu_to_le16(index);
	req->subtype = cpu_to_le16(subtype);
	req->data_size = data_size;
	memcpy(req->data, data, data_size);

	rc = hwrm_req_send(bp, req);
	if (rc)
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);
	return rc;
}

int
tfc_msg_if_tbl_get(struct tfc *tfcp, u16 fid, u16 sid,
		   enum cfa_dir dir, enum cfa_resource_subtype_if_tbl subtype,
		   u16 index, u8 *data_size, u8 *data)
{
	struct hwrm_tfc_if_tbl_get_output *resp;
	struct hwrm_tfc_if_tbl_get_input *req;
	struct bnxt *bp = tfcp->bp;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_TFC_IF_TBL_GET);
	if (rc)
		return rc;

	resp = hwrm_req_hold(bp, req);

	req->flags = (dir == CFA_DIR_TX ?
		    TFC_IF_TBL_GET_REQ_FLAGS_DIR_TX :
		    TFC_IF_TBL_GET_REQ_FLAGS_DIR_RX);

	rc = tfc_msg_set_fid(bp, fid, &req->fid);
	if (rc) {
		netdev_dbg(bp->dev, "%s: set fid Failed: %d\n", __func__, rc);
		goto cleanup;
	}

	req->sid = cpu_to_le16(sid);

	req->index = cpu_to_le16(index);
	req->subtype = cpu_to_le16(subtype);
	req->data_size = cpu_to_le16(*data_size);

	rc = hwrm_req_send(bp, req);
	if (rc) {
		netdev_dbg(bp->dev, "%s: hwrm req send Failed: %d\n", __func__, rc);
		goto cleanup;
	}

	if (*data_size < le16_to_cpu(resp->data_size)) {
		netdev_dbg(bp->dev,
			   "Table buffer is too small %d limit %d\n",
			   *data_size, resp->data_size);
		rc = -EINVAL;
		goto cleanup;
	}

	memcpy(data, resp->data, *data_size);
	*data_size = resp->data_size;

cleanup:
	hwrm_req_drop(bp, req);

	if (!rc)
		netdev_dbg(bp->dev, "%s: data_size %d Success\n", __func__, *data_size);
	else
		netdev_dbg(bp->dev, "%s: Failed: %d\n", __func__, rc);

	return rc;
}
