/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2021-2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include "bnxt_compat.h"
#include "bnxt_hsi.h"
#include "bnxt.h"
#include "bnxt_hwrm.h"
#include "bnxt_coredump.h"
#include "bnxt_log.h"

static int bnxt_dbg_hwrm_log_buffer_flush(struct bnxt *bp, u16 type, u32 flags, u32 *offset)
{
	struct hwrm_dbg_log_buffer_flush_output *resp;
	struct hwrm_dbg_log_buffer_flush_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_DBG_LOG_BUFFER_FLUSH);
	if (rc)
		return rc;

	req->flags = cpu_to_le32(flags);
	req->type = cpu_to_le16(type);
	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (!rc)
		*offset = le32_to_cpu(resp->current_buffer_offset);
	hwrm_req_drop(bp, req);
	return rc;
}

static void bnxt_fill_driver_segment_record(struct bnxt *bp,
					    struct bnxt_driver_segment_record *driver_seg_record,
					    struct bnxt_ctx_mem_type *ctxm, u16 type)
{
	struct bnxt_bs_trace_info *bs_trace = &bp->bs_trace[type];
	u32 offset = 0;
	int rc = 0;

	rc = bnxt_dbg_hwrm_log_buffer_flush(bp, type, 0, &offset);
	if (rc)
		return;

	bnxt_bs_trace_check_wrapping(bs_trace, offset);
	driver_seg_record->max_entries = cpu_to_le32(ctxm->max_entries);
	driver_seg_record->entry_size = cpu_to_le32(ctxm->entry_size);
	driver_seg_record->offset = cpu_to_le32(bs_trace->last_offset);
	driver_seg_record->wrapped = bs_trace->wrapped;
}

static void bnxt_retrieve_driver_coredump(struct bnxt *bp, u16 type, u32 *seg_len,
					  void *buf, u32 offset)
{
	struct bnxt_driver_segment_record driver_seg_record = {0};
	u32 dump_len, data_offset, record_len, record_offset;
	struct bnxt_ctx_mem_info *ctx = bp->ctx;
	struct bnxt_ctx_pg_info *ctx_pg;
	struct bnxt_ring_mem_info *rmem;
	struct bnxt_ctx_mem_type *ctxm;
	int k, n = 1;

	ctxm = &ctx->ctx_arr[type];

	dump_len = 0;
	record_len = sizeof(struct bnxt_driver_segment_record);
	record_offset = offset;
	data_offset = record_offset + sizeof(struct bnxt_driver_segment_record);
	bnxt_fill_driver_segment_record(bp, &driver_seg_record, ctxm, type - BNXT_CTX_SRT_TRACE);

	ctx_pg = ctxm->pg_info;
	if (ctxm->instance_bmap)
		n = hweight32(ctxm->instance_bmap);

	for (k = 0; k < n ; k++) {
		struct bnxt_ctx_pg_info *ctx_pg_block = &ctx_pg[k];
		int nr_tbls, i, j;

		rmem = &ctx_pg_block->ring_mem;
		if (rmem->depth > 1) {
			nr_tbls = DIV_ROUND_UP(ctx_pg_block->nr_pages, MAX_CTX_PAGES);
			for (i = 0; i < nr_tbls; i++) {
				struct bnxt_ctx_pg_info *pg_tbl;
				struct bnxt_ring_mem_info *rmem_pde;

				pg_tbl =  ctx_pg_block->ctx_pg_tbl[i];
				rmem_pde = &pg_tbl->ring_mem;
				if (i == (nr_tbls - 1)) {
					int rem = ctx_pg_block->nr_pages % MAX_CTX_PAGES;

					if (rem)
						rmem_pde->nr_pages = rem;
				}
				for (j = 0; j < rmem_pde->nr_pages; j++) {
					memcpy(buf + data_offset, rmem_pde->pg_arr[j],
					       BNXT_PAGE_SIZE);
					dump_len += BNXT_PAGE_SIZE;
					data_offset += BNXT_PAGE_SIZE;
				}
			}
		} else {
			for (i = 0; i < ctx_pg_block->nr_pages; i++) {
				memcpy(buf + data_offset, rmem->pg_arr[i], BNXT_PAGE_SIZE);
				dump_len += BNXT_PAGE_SIZE;
				data_offset += BNXT_PAGE_SIZE;
			}
		}
		memcpy(buf + record_offset, &driver_seg_record, record_len);
		*seg_len = dump_len + record_len;
	}
}

static int bnxt_hwrm_dbg_dma_data(struct bnxt *bp, void *msg,
				  struct bnxt_hwrm_dbg_dma_info *info)
{
	struct hwrm_dbg_cmn_input *cmn_req = msg;
	__le16 *seq_ptr = msg + info->seq_off;
	struct hwrm_dbg_cmn_output *cmn_resp;
	u16 seq = 0, len, segs_off;
	dma_addr_t dma_handle;
	void *dma_buf, *resp;
	int rc, off = 0;

	dma_buf = hwrm_req_dma_slice(bp, msg, info->dma_len, &dma_handle);
	if (!dma_buf) {
		hwrm_req_drop(bp, msg);
		return -ENOMEM;
	}

	hwrm_req_timeout(bp, msg, HWRM_COREDUMP_TIMEOUT);
	cmn_resp = hwrm_req_hold(bp, msg);
	resp = cmn_resp;

	segs_off = offsetof(struct hwrm_dbg_coredump_list_output, total_segments);
	cmn_req->host_dest_addr = cpu_to_le64(dma_handle);
	cmn_req->host_buf_len = cpu_to_le32(info->dma_len);
	while (1) {
		*seq_ptr = cpu_to_le16(seq);
		rc = hwrm_req_send(bp, msg);
		if (rc)
			break;

		len = le16_to_cpu(*((__le16 *)(resp + info->data_len_off)));
		if (!seq &&
		    cmn_req->req_type == cpu_to_le16(HWRM_DBG_COREDUMP_LIST)) {
			info->segs = le16_to_cpu(*((__le16 *)(resp + segs_off)));
			if (!info->segs) {
				rc = -EIO;
				break;
			}

			info->dest_buf_size = info->segs *
				sizeof(struct coredump_segment_record);
			info->dest_buf = kmalloc(info->dest_buf_size, GFP_KERNEL);
			if (!info->dest_buf) {
				rc = -ENOMEM;
				break;
			}
		}

		if (info->dest_buf) {
			if ((info->seg_start + off + len) <=
			    BNXT_COREDUMP_BUF_LEN(info->buf_len)) {
				memcpy(info->dest_buf + off, dma_buf, len);
			} else {
				rc = -ENOBUFS;
				break;
			}
		}

		if (cmn_req->req_type == cpu_to_le16(HWRM_DBG_COREDUMP_RETRIEVE))
			info->dest_buf_size += len;

		if (!(cmn_resp->flags & HWRM_DBG_CMN_FLAGS_MORE))
			break;

		seq++;
		off += len;
	}
	hwrm_req_drop(bp, msg);
	return rc;
}

static int bnxt_hwrm_dbg_coredump_list(struct bnxt *bp,
				       struct bnxt_coredump *coredump)
{
	struct bnxt_hwrm_dbg_dma_info info = {NULL};
	struct hwrm_dbg_coredump_list_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_DBG_COREDUMP_LIST);
	if (rc)
		return rc;

	info.dma_len = COREDUMP_LIST_BUF_LEN;
	info.seq_off = offsetof(struct hwrm_dbg_coredump_list_input, seq_no);
	info.data_len_off = offsetof(struct hwrm_dbg_coredump_list_output,
				     data_len);

	rc = bnxt_hwrm_dbg_dma_data(bp, req, &info);
	if (!rc) {
		coredump->data = info.dest_buf;
		coredump->data_size = info.dest_buf_size;
		coredump->total_segs = info.segs;
	}
	return rc;
}

static int bnxt_hwrm_dbg_coredump_initiate(struct bnxt *bp, u16 component_id,
					   u16 segment_id)
{
	struct hwrm_dbg_coredump_initiate_input *req;
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_DBG_COREDUMP_INITIATE);
	if (rc)
		return rc;

	hwrm_req_timeout(bp, req, HWRM_COREDUMP_TIMEOUT);
	req->component_id = cpu_to_le16(component_id);
	req->segment_id = cpu_to_le16(segment_id);

	return hwrm_req_send(bp, req);
}

static int bnxt_hwrm_dbg_coredump_retrieve(struct bnxt *bp, u16 component_id,
					   u16 segment_id, u32 *seg_len,
					   void *buf, u32 buf_len, u32 offset)
{
	struct hwrm_dbg_coredump_retrieve_input *req;
	struct bnxt_hwrm_dbg_dma_info info = {NULL};
	int rc;

	rc = hwrm_req_init(bp, req, HWRM_DBG_COREDUMP_RETRIEVE);
	if (rc)
		return rc;

	req->component_id = cpu_to_le16(component_id);
	req->segment_id = cpu_to_le16(segment_id);

	info.dma_len = COREDUMP_RETRIEVE_BUF_LEN;
	info.seq_off = offsetof(struct hwrm_dbg_coredump_retrieve_input,
				seq_no);
	info.data_len_off = offsetof(struct hwrm_dbg_coredump_retrieve_output,
				     data_len);
	if (buf) {
		info.dest_buf = buf + offset;
		info.buf_len = buf_len;
		info.seg_start = offset;
	}

	rc = bnxt_hwrm_dbg_dma_data(bp, req, &info);
	if (!rc)
		*seg_len = info.dest_buf_size;

	return rc;
}

void
bnxt_fill_coredump_seg_hdr(struct bnxt *bp,
			   struct bnxt_coredump_segment_hdr *seg_hdr,
			   struct coredump_segment_record *seg_rec, u32 seg_len,
			   int status, u32 duration, u32 instance, u32 comp_id,
			   u32 seg_id)
{
	memset(seg_hdr, 0, sizeof(*seg_hdr));
	memcpy(seg_hdr->signature, "sEgM", 4);
	if (seg_rec) {
		seg_hdr->component_id = (__force __le32)seg_rec->component_id;
		seg_hdr->segment_id = (__force __le32)seg_rec->segment_id;
		seg_hdr->low_version = seg_rec->version_low;
		seg_hdr->high_version = seg_rec->version_hi;
		seg_hdr->flags = seg_rec->compress_flags;
	} else {
		seg_hdr->component_id = cpu_to_le32(comp_id);
		seg_hdr->segment_id = cpu_to_le32(seg_id);
	}
	seg_hdr->function_id = cpu_to_le16(bp->pdev->devfn);
	seg_hdr->length = cpu_to_le32(seg_len);
	seg_hdr->status = cpu_to_le32(status);
	seg_hdr->duration = cpu_to_le32(duration);
	seg_hdr->data_offset = cpu_to_le32(sizeof(*seg_hdr));
	seg_hdr->instance = cpu_to_le32(instance);
}

struct bnxt_time bnxt_get_current_time(struct bnxt *bp)
{
	struct bnxt_time time;
#if defined(HAVE_TIME64)
	time64_to_tm(ktime_get_real_seconds(), -sys_tz.tz_minuteswest * 60, &time.tm);
#else
	struct timeval tv;

	do_gettimeofday(&tv);
	time_to_tm(tv.tv_sec, -sys_tz.tz_minuteswest * 60, &time.tm);
#endif
	time.tm.tm_mon += 1;
	time.tm.tm_year += 1900;

	return time;
}

static void bnxt_fill_cmdline(struct bnxt_coredump_record *record)
{
	struct mm_struct *mm = current->mm;

	if (mm) {
		unsigned long len = mm->arg_end - mm->arg_start;
		int i, last = 0;

		len = min(len, sizeof(record->commandline) - 1);
		if (len && !copy_from_user(record->commandline,
		    (char __user *) mm->arg_start, len)) {
			for (i = 0; i < len; i++) {
				if (record->commandline[i])
					last = i;
				else
					record->commandline[i] = ' ';
			}
			record->commandline[last + 1] = 0;
			return;
		}
	}

	strscpy(record->commandline, current->comm, TASK_COMM_LEN);
}

void bnxt_fill_empty_seg(struct bnxt *bp, void *buf, u32 len)
{
	struct bnxt_coredump_segment_hdr seg_hdr;

	bnxt_fill_coredump_seg_hdr(bp, &seg_hdr, NULL, len, 0, 0, 0, 0, 0);
	memcpy(buf, &seg_hdr, sizeof(seg_hdr));
}

void
bnxt_fill_coredump_record(struct bnxt *bp, struct bnxt_coredump_record *record,
			  struct bnxt_time start, s16 start_utc, u16 total_segs,
			  int status)
{
	struct bnxt_time end = bnxt_get_current_time(bp);
	u32 os_ver_major = 0, os_ver_minor = 0;

	memset(record, 0, sizeof(*record));
	memcpy(record->signature, "cOrE", 4);
	record->flags = 0;
	record->low_version = 0;
	record->high_version = 1;
	record->asic_state = 0;
	strscpy(record->system_name, utsname()->nodename,
		sizeof(record->system_name));
	record->year = cpu_to_le16(start.tm.tm_year);
	record->month = cpu_to_le16(start.tm.tm_mon);
	record->day = cpu_to_le16(start.tm.tm_mday);
	record->hour = cpu_to_le16(start.tm.tm_hour);
	record->minute = cpu_to_le16(start.tm.tm_min);
	record->second = cpu_to_le16(start.tm.tm_sec);
	record->utc_bias = cpu_to_le16(start_utc);
	bnxt_fill_cmdline(record);
	record->total_segments = cpu_to_le32(total_segs);

	if (sscanf(utsname()->release, "%u.%u", &os_ver_major, &os_ver_minor) != 2)
		netdev_warn(bp->dev, "Unknown OS release in coredump\n");
	record->os_ver_major = cpu_to_le32(os_ver_major);
	record->os_ver_minor = cpu_to_le32(os_ver_minor);

	strscpy(record->os_name, utsname()->sysname, sizeof(record->os_name));
	record->end_year = cpu_to_le16(end.tm.tm_year);
	record->end_month = cpu_to_le16(end.tm.tm_mon);
	record->end_day = cpu_to_le16(end.tm.tm_mday);
	record->end_hour = cpu_to_le16(end.tm.tm_hour);
	record->end_minute = cpu_to_le16(end.tm.tm_min);
	record->end_second = cpu_to_le16(end.tm.tm_sec);
	record->end_utc_bias = cpu_to_le16(sys_tz.tz_minuteswest);
	record->asic_id1 = cpu_to_le32(bp->chip_num << 16 |
	bp->ver_resp.chip_rev << 8 |
	bp->ver_resp.chip_metal);
	record->asic_id2 = 0;
	record->coredump_status = cpu_to_le32(status);
	record->ioctl_low_version = 0;
	record->ioctl_high_version = 0;
}

static int __bnxt_get_coredump(struct bnxt *bp, void *buf, u32 *dump_len)
{
	u32 offset = 0, seg_hdr_len, seg_record_len = 0, buf_len = 0;
	u32 ver_get_resp_len = sizeof(struct hwrm_ver_get_output);
	struct coredump_segment_record *seg_record = NULL;
	u32 driver_comp_id = DRV_COREDUMP_COMP_ID;
	struct bnxt_coredump_segment_hdr seg_hdr;
	struct bnxt_ctx_mem_info *ctx = bp->ctx;
	struct bnxt_coredump coredump = {NULL};
	int rc = 0, i, type, drv_seg_count = 0;
	u32 driver_seg_id = DRV_SEG_SRT_TRACE;
	struct bnxt_ctx_mem_type *ctxm;
	struct bnxt_time start_time;
	u32 null_seg_len;
	s16 start_utc;

	if (buf)
		buf_len = *dump_len;

	start_time = bnxt_get_current_time(bp);
	start_utc = sys_tz.tz_minuteswest;
	seg_hdr_len = sizeof(seg_hdr);

	/* First segment should be hwrm_ver_get response.
	 * For hwrm_ver_get response Component id = 2 and Segment id = 0
	 */
	*dump_len = seg_hdr_len + ver_get_resp_len;
	if (buf) {
		bnxt_fill_coredump_seg_hdr(bp, &seg_hdr, NULL, ver_get_resp_len,
					   0, 0, 0, 2, 0);
		memcpy(buf + offset, &seg_hdr, seg_hdr_len);
		offset += seg_hdr_len;
		memcpy(buf + offset, &bp->ver_resp, ver_get_resp_len);
		offset += ver_get_resp_len;
	}

	rc = bnxt_hwrm_dbg_coredump_list(bp, &coredump);
	if (rc) {
		netdev_err(bp->dev, "Failed to get coredump segment list\n");
		goto fw_coredump_err;
	}

	*dump_len += seg_hdr_len * coredump.total_segs;

	seg_record = (struct coredump_segment_record *)coredump.data;
	seg_record_len = sizeof(*seg_record);

	for (i = 0; i < coredump.total_segs; i++) {
		u16 comp_id = le16_to_cpu(seg_record->component_id);
		u16 seg_id = le16_to_cpu(seg_record->segment_id);
		u32 duration = 0, seg_len = 0;
		unsigned long start, end;

		if (buf && ((offset + seg_hdr_len) > BNXT_COREDUMP_BUF_LEN(buf_len))) {
			rc = -ENOBUFS;
			goto fw_coredump_err;
		}

		start = jiffies;

		rc = bnxt_hwrm_dbg_coredump_initiate(bp, comp_id, seg_id);
		if (rc) {
			netdev_err(bp->dev,
				   "Failed to initiate coredump for seg = %d\n",
				   seg_record->segment_id);
			goto next_seg;
		}

		/* Write segment data into the buffer */
		rc = bnxt_hwrm_dbg_coredump_retrieve(bp, comp_id, seg_id,
						     &seg_len, buf, buf_len,
						     offset + seg_hdr_len);
		if (rc && rc == -ENOBUFS)
			goto fw_coredump_err;
		else if (rc)
			netdev_err(bp->dev,
				   "Failed to retrieve coredump for seg = %d\n",
				   seg_record->segment_id);
next_seg:
		end = jiffies;
		duration = jiffies_to_msecs(end - start);
		bnxt_fill_coredump_seg_hdr(bp, &seg_hdr, seg_record, seg_len,
					   rc, duration, 0, 0, 0);

		if (buf) {
			/* Write segment header into the buffer */
			memcpy(buf + offset, &seg_hdr, seg_hdr_len);
			offset += seg_hdr_len + seg_len;
		}

		*dump_len += seg_len;
		seg_record =
		(struct coredump_segment_record *)((u8 *)seg_record +
		seg_record_len);
	}

fw_coredump_err:
	if (!ctx)
		goto skip_drv_coredump;

	for (type = BNXT_CTX_SRT_TRACE; type <= BNXT_CTX_ROCE_HWRM_TRACE;
	     type++, driver_seg_id++) {
		u32 duration = 0, seg_len = 0;
		unsigned long start, end;
		ctxm = &ctx->ctx_arr[type];

		if (!buf || !(ctxm->flags & BNXT_CTX_MEM_TYPE_VALID))
			continue;
		*dump_len += seg_hdr_len;
		start = jiffies;
		bnxt_retrieve_driver_coredump(bp, type, &seg_len, buf, offset + seg_hdr_len);
		end = jiffies;
		duration = jiffies_to_msecs(end - start);
		bnxt_fill_coredump_seg_hdr(bp, &seg_hdr, NULL, seg_len,
					   rc, duration, 0, driver_comp_id, driver_seg_id);

		/* Write segment header into the buffer */
		memcpy(buf + offset, &seg_hdr, seg_hdr_len);
		offset += seg_hdr_len + seg_len;

		*dump_len += seg_len;
		seg_record = (struct coredump_segment_record *)((u8 *)seg_record + seg_record_len);
		drv_seg_count++;
	}
skip_drv_coredump:
	null_seg_len = BNXT_COREDUMP_BUF_LEN(buf_len) - *dump_len;
	if (buf) {
		bnxt_fill_empty_seg(bp, buf + offset, null_seg_len);
		/* Fix the coredump record at last 1024 bytes */
		offset = buf_len - sizeof(struct bnxt_coredump_record);
		bnxt_fill_coredump_record(bp, buf + offset, start_time, start_utc,
					  coredump.total_segs + drv_seg_count + 2, rc);
	}

	kfree(coredump.data);
	*dump_len += sizeof(struct bnxt_coredump_record) + seg_hdr_len + null_seg_len;
	if (rc == -ENOBUFS)
		netdev_err(bp->dev, "Firmware returned large coredump buffer\n");
	return rc;
}

static u32 bnxt_copy_crash_data(struct bnxt_ring_mem_info *rmem, void *buf,
				u32 dump_len)
{
	u32 data_copied = 0;
	u32 data_len;
	int i;

	for (i = 0; i < rmem->nr_pages; i++) {
		data_len = rmem->page_size;
		if (data_copied + data_len > dump_len)
			data_len = dump_len - data_copied;
		memcpy(buf + data_copied, rmem->pg_arr[i], data_len);
		data_copied += data_len;
		if (data_copied >= dump_len)
			break;
	}
	return data_copied;
}

static int bnxt_copy_crash_dump(struct bnxt *bp, void *buf, u32 dump_len)
{
	struct bnxt_ring_mem_info *rmem;
	u32 offset = 0;

	if (!bp->fw_crash_mem)
		return -EEXIST;

	rmem = &bp->fw_crash_mem->ring_mem;

	if (rmem->depth > 1) {
		int i;

		for (i = 0; i < rmem->nr_pages; i++) {
			struct bnxt_ctx_pg_info *pg_tbl;

			pg_tbl = bp->fw_crash_mem->ctx_pg_tbl[i];
			offset += bnxt_copy_crash_data(&pg_tbl->ring_mem,
						       buf + offset, dump_len - offset);
			if (offset >= dump_len)
				break;
		}
	} else {
		bnxt_copy_crash_data(rmem, buf, dump_len);
	}

	return 0;
}

static bool bnxt_crash_dump_avail(struct bnxt *bp)
{
	u32 sig = 0;

	/* First 4 bytes(signature) of crash dump is always non-zero */
	bnxt_copy_crash_dump(bp, &sig, sizeof(u32));
	if (!sig)
		return false;

	return true;
}

int bnxt_get_coredump(struct bnxt *bp, u16 dump_type, void *buf, u32 *dump_len)
{
	if (dump_type >= BNXT_DUMP_DRIVER) {
		bnxt_start_logging_coredump(bp, buf, dump_len, dump_type);
		return 0;
	}

	if (dump_type == BNXT_DUMP_CRASH) {
		if (bp->fw_dbg_cap & BNXT_FW_DBG_CAP_CRASHDUMP_HOST)
			return bnxt_copy_crash_dump(bp, buf, *dump_len);
#ifdef CONFIG_TEE_BNXT_FW
		else if (bp->fw_dbg_cap & BNXT_FW_DBG_CAP_CRASHDUMP_SOC)
			return tee_bnxt_copy_coredump(buf, 0, *dump_len);
#endif
		else
			return -EOPNOTSUPP;
	} else {
		return  __bnxt_get_coredump(bp, buf, dump_len);
	}
}

static void bnxt_get_bs_trace_size(struct bnxt *bp, u8 *segments, u32 *seg_len)
{
	struct bnxt_ctx_mem_info *ctx = bp->ctx;
	struct bnxt_ctx_pg_info *ctx_pg;
	struct bnxt_ctx_mem_type *ctxm;
	int k, n = 1;
	u16 type;

	if (!ctx)
		return;

	for (type = BNXT_CTX_SRT_TRACE; type <= BNXT_CTX_ROCE_HWRM_TRACE; type++) {
		ctxm = &ctx->ctx_arr[type];
		if (!(ctxm->flags & BNXT_CTX_MEM_TYPE_VALID))
			continue;

		ctx_pg = ctxm->pg_info;
		if (ctxm->instance_bmap)
			n = hweight32(ctxm->instance_bmap);
		for (k = 0; k < n ; k++)
			*seg_len += ctx_pg[k].nr_pages * BNXT_PAGE_SIZE;
		*segments = *segments + 1;
	}
}

static void bnxt_append_driver_coredump_len(struct bnxt *bp, u32 *len)
{
	u8 segments = 0;
	u32 size = 0;
	int hdr_len;

	bnxt_get_bs_trace_size(bp, &segments, &size);
	if (size) {
		hdr_len = segments * sizeof(struct bnxt_driver_segment_record);
		*len += size + hdr_len;
	}
}

int bnxt_hwrm_get_dump_len(struct bnxt *bp, u16 dump_type, u32 *dump_len)
{
	struct hwrm_dbg_qcfg_output *resp;
	struct hwrm_dbg_qcfg_input *req;
	int rc, hdr_len = 0;

	if (dump_type >= BNXT_DUMP_DRIVER) {
		hdr_len = 2 * sizeof(struct bnxt_coredump_segment_hdr) +
				sizeof(struct hwrm_ver_get_output) +
				sizeof(struct bnxt_coredump_record);
		*dump_len = bnxt_get_loggers_coredump_size(bp, dump_type);
		*dump_len = *dump_len + hdr_len;
		return 0;
	}

	if (!(bp->fw_cap & BNXT_FW_CAP_DBG_QCAPS))
		return -EOPNOTSUPP;

	if (dump_type == BNXT_DUMP_CRASH &&
	    !(bp->fw_dbg_cap & BNXT_FW_DBG_CAP_CRASHDUMP_SOC ||
	     (bp->fw_dbg_cap & BNXT_FW_DBG_CAP_CRASHDUMP_HOST)))
		return -EOPNOTSUPP;

	rc = hwrm_req_init(bp, req, HWRM_DBG_QCFG);
	if (rc)
		return rc;

	req->fid = cpu_to_le16(0xffff);
	if (dump_type == BNXT_DUMP_CRASH) {
		if (bp->fw_dbg_cap & BNXT_FW_DBG_CAP_CRASHDUMP_SOC)
			req->flags = cpu_to_le16(BNXT_DBG_FL_CR_DUMP_SIZE_SOC);
		else
			req->flags = cpu_to_le16(BNXT_DBG_FL_CR_DUMP_SIZE_HOST);
	}

	resp = hwrm_req_hold(bp, req);
	rc = hwrm_req_send(bp, req);
	if (rc)
		goto get_dump_len_exit;

	if (dump_type == BNXT_DUMP_CRASH) {
		if (bp->fw_dbg_cap & BNXT_FW_DBG_CAP_CRASHDUMP_SOC)
			*dump_len = BNXT_CRASH_DUMP_LEN;
		else
			*dump_len = le32_to_cpu(resp->crashdump_size);
	} else {
		/* Driver adds coredump headers for "HWRM_VER_GET response"
		 * and null segments additionally to coredump.
		 */
		hdr_len = 2 * sizeof(struct bnxt_coredump_segment_hdr) +
		sizeof(struct hwrm_ver_get_output) +
		sizeof(struct bnxt_coredump_record);
		*dump_len = le32_to_cpu(resp->coredump_size) + hdr_len;
	}
	if (*dump_len <= hdr_len)
		rc = -EINVAL;

get_dump_len_exit:
	hwrm_req_drop(bp, req);
	return rc;
}

u32 bnxt_get_coredump_length(struct bnxt *bp, u16 dump_type)
{
	u32 len = 0;

	if (dump_type == BNXT_DUMP_CRASH &&
	    bp->fw_dbg_cap & BNXT_FW_DBG_CAP_CRASHDUMP_HOST &&
	    bp->fw_crash_mem) {
		if (!bnxt_crash_dump_avail(bp))
			return 0;

		return bp->fw_crash_len;
	}

	if (bnxt_hwrm_get_dump_len(bp, dump_type, &len)) {
		if (dump_type == BNXT_DUMP_LIVE)
			__bnxt_get_coredump(bp, NULL, &len);
	}

	if (dump_type == BNXT_DUMP_LIVE)
		bnxt_append_driver_coredump_len(bp, &len);
	return len;
}

