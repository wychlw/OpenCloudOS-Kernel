/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/vmalloc.h>
#include <linux/errno.h>

#include "bnxt_compat.h"
#include "bnxt.h"
#include "bnxt_log.h"
#include "bnxt_coredump.h"

#define BNXT_LOG_MSG_SIZE	256
#define BNXT_LOG_NUM_BUFFERS(x)	((x) / BNXT_LOG_MSG_SIZE)

int l2_ring_contents_seg_list[] = {
	BNXT_SEGMENT_L2_RING_CONTENT
};

/* Below list of segment creation will be
 * attempted for L2 logger
 */
int l2_seg_list[] = {
	BNXT_SEGMENT_L2
};

/* Below list of segment creation will be
 * attempted for L2 CTX MEM logger
 */
int l2_ctx_mem_seg_list[] = {
	BNXT_SEGMENT_CTX_MEM_QP,
	BNXT_SEGMENT_CTX_MEM_SRQ,
	BNXT_SEGMENT_CTX_MEM_CQ,
	BNXT_SEGMENT_CTX_MEM_VNIC,
	BNXT_SEGMENT_CTX_MEM_STAT,
	BNXT_SEGMENT_CTX_MEM_SP_TQM_RING,
	BNXT_SEGMENT_CTX_MEM_FP_TQM_RING,
	BNXT_SEGMENT_CTX_MEM_MRAV,
	BNXT_SEGMENT_CTX_MEM_TIM,
	BNXT_SEGMENT_CTX_MEM_TX_CK,
	BNXT_SEGMENT_CTX_MEM_RX_CK,
	BNXT_SEGMENT_CTX_MEM_MP_TQM_RING,
	BNXT_SEGMENT_CTX_MEM_SQ_DB_SHADOW,
	BNXT_SEGMENT_CTX_MEM_RQ_DB_SHADOW,
	BNXT_SEGMENT_CTX_MEM_SRQ_DB_SHADOW,
	BNXT_SEGMENT_CTX_MEM_CQ_DB_SHADOW
};

/* Below list of segment creation will be
 * attempted for RoCE logger
 */
int roce_seg_list[] = {
	BNXT_SEGMENT_QP_CTX,
	BNXT_SEGMENT_CQ_CTX,
	BNXT_SEGMENT_MR_CTX,
	BNXT_SEGMENT_SRQ_CTX,
	/* Try to fit fixed sized segment first.*/
	BNXT_SEGMENT_ROCE
};

struct bnxt_logger {
	struct list_head list;
	u16 logger_id;
	u32 buffer_size;
	u16 head;
	u16 tail;
	bool valid;
	void *msgs;
	u32 live_max_size;
	void *live_msgs;
	u32 max_live_buff_size;
	u32 live_msgs_len;
	void (*log_live_op)(void *dev, u32 seg_id);
	u32 total_segs;
	int *seg_list;
};

int bnxt_register_logger(struct bnxt *bp, u16 logger_id, u32 num_buffs,
			 void (*log_live)(void *, u32), u32 live_max_size)
{
	struct bnxt_logger *logger;
	void *data;

	if (logger_id == BNXT_LOGGER_L2_CTX_MEM ||
	    logger_id == BNXT_LOGGER_L2_RING_CONTENTS)
		goto register_logger;

	if (!log_live || !live_max_size)
		return -EINVAL;

	if (!is_power_of_2(num_buffs))
		return -EINVAL;

register_logger:
	logger = kzalloc(sizeof(*logger), GFP_KERNEL);
	if (!logger)
		return -ENOMEM;

	logger->logger_id = logger_id;
	logger->buffer_size = num_buffs * BNXT_LOG_MSG_SIZE;
	logger->log_live_op = log_live;
	logger->max_live_buff_size = live_max_size;

	switch (logger_id) {
	case BNXT_LOGGER_L2:
		logger->total_segs = sizeof(l2_seg_list) / sizeof(int);
		logger->seg_list = &l2_seg_list[0];
		break;
	case BNXT_LOGGER_ROCE:
		logger->total_segs = sizeof(roce_seg_list) / sizeof(int);
		logger->seg_list = &roce_seg_list[0];
		break;
	case BNXT_LOGGER_L2_CTX_MEM:
		logger->total_segs = sizeof(l2_ctx_mem_seg_list) / sizeof(int);
		logger->seg_list = &l2_ctx_mem_seg_list[0];
		break;
	case BNXT_LOGGER_L2_RING_CONTENTS:
		logger->total_segs = sizeof(l2_ring_contents_seg_list) / sizeof(int);
		logger->seg_list = &l2_ring_contents_seg_list[0];
		break;
	default:
		logger->total_segs = 1;
		break;
	}

	if (logger->buffer_size) {
		data = vmalloc(logger->buffer_size);
		if (!data) {
			kfree(logger);
			return -ENOMEM;
		}
		logger->msgs = data;
	}

	INIT_LIST_HEAD(&logger->list);
	mutex_lock(&bp->log_lock);
	list_add_tail(&logger->list, &bp->loggers_list);
	mutex_unlock(&bp->log_lock);
	return 0;
}

void bnxt_unregister_logger(struct bnxt *bp, u16 logger_id)
{
	struct bnxt_logger *l = NULL, *tmp;

	mutex_lock(&bp->log_lock);
	list_for_each_entry_safe(l, tmp, &bp->loggers_list, list) {
		if (l->logger_id == logger_id) {
			list_del(&l->list);
			break;
		}
	}
	mutex_unlock(&bp->log_lock);

	if (!l || l->logger_id != logger_id) {
		netdev_err(bp->dev, "logger id %d not registered\n", logger_id);
		return;
	}

	vfree(l->msgs);
	kfree(l);
}

int bnxt_log_ring_contents(struct bnxt *bp)
{
	struct list_head *list_head, *pos, *lg;
	struct bnxt_logger *logger = NULL;
	size_t size = 0;
	u32 offset = 0;
	u8 *data;
	int i, len;

	mutex_lock(&bp->log_lock);
	list_head = &bp->loggers_list;
	list_for_each_safe(pos, lg, list_head) {
		logger = list_entry(pos, struct bnxt_logger, list);
		if (logger->logger_id == BNXT_LOGGER_L2_RING_CONTENTS)
			break;
	}

	if (!logger || logger->logger_id != BNXT_LOGGER_L2_RING_CONTENTS) {
		mutex_unlock(&bp->log_lock);
		return -EINVAL;
	}

	/* Include 2 extra u16 size bytes to store ring's producer & consumer index */
	size = bp->tx_nr_rings * (2 * sizeof(u16) + (bp->tx_nr_pages * HW_TXBD_RING_SIZE));

	if (!logger->msgs || logger->buffer_size < size) {
		if (logger->msgs)
			vfree(logger->msgs);

		logger->msgs = vmalloc(size);
		if (!logger->msgs) {
			mutex_unlock(&bp->log_lock);
			return -ENOMEM;
		}

		logger->buffer_size = size;
	}

	data = logger->msgs;

	for (i = 0; i < bp->tx_nr_rings; i++) {
		struct bnxt_tx_ring_info *txr = &bp->tx_ring[i];
		u16 prod_id = RING_TX(bp, txr->tx_prod);
		u16 cons_id = RING_TX(bp, txr->tx_cons);
		struct bnxt_ring_struct *ring;

		ring = &txr->tx_ring_struct;

		data[offset++] = prod_id && 0xff;
		data[offset++] = (prod_id && 0xff00) >> 8;

		data[offset++] = cons_id && 0xff;
		data[offset++] = (cons_id && 0xff00) >> 8;

		len = bnxt_copy_ring(bp, &ring->ring_mem, data, offset);
		offset += len;
	}
	mutex_unlock(&bp->log_lock);
	return 0;
}

static int bnxt_log_info(char *buf, size_t max_len, const char *format, va_list args)
{
	static char textbuf[BNXT_LOG_MSG_SIZE];
	char *text = textbuf;
	size_t text_len;
	char *next;

	text_len = vscnprintf(text, sizeof(textbuf), format, args);

	next = memchr(text, '\n', text_len);
	if (next)
		text_len = next - text;
	else if (text[text_len] == '\0')
		text[text_len] = '\n';

	if (text_len > max_len) {
		/* Truncate */
		text_len = max_len;
		text[text_len] = '\n';
	}

	memcpy(buf, text, text_len + 1);

	return text_len + 1;
}

void bnxt_log_add_msg(struct bnxt *bp, u16 logger_id, const char *format, ...)
{
	struct list_head *list_head, *pos, *lg;
	struct bnxt_logger *logger = NULL;
	u16 start, tail;
	va_list args;
	void *buf;
	u32 mask;

	mutex_lock(&bp->log_lock);
	list_head = &bp->loggers_list;
	list_for_each_safe(pos, lg, list_head) {
		logger = list_entry(pos, struct bnxt_logger, list);
		if (logger->logger_id == logger_id)
			break;
	}

	if (!logger) {
		mutex_unlock(&bp->log_lock);
		return;
	}

	mask = BNXT_LOG_NUM_BUFFERS(logger->buffer_size) - 1;
	tail = logger->tail;
	start = logger->head;

	if (logger->valid && start == tail)
		logger->head = ++start & mask;

	buf = logger->msgs + BNXT_LOG_MSG_SIZE * logger->tail;
	logger->tail = ++tail & mask;

	if (!logger->valid)
		logger->valid = true;

	va_start(args, format);
	bnxt_log_info(buf, BNXT_LOG_MSG_SIZE, format, args);
	va_end(args);
	mutex_unlock(&bp->log_lock);
}

void bnxt_log_raw(struct bnxt *bp, u16 logger_id, void *data, int len)
{
	struct list_head *head, *pos, *lg;
	struct bnxt_logger *logger = NULL;
	bool match_found = false;

	head = &bp->loggers_list;
	list_for_each_safe(pos, lg, head) {
		logger = list_entry(pos, struct bnxt_logger, list);
		if ((logger->logger_id == logger_id) && logger->live_msgs) {
			match_found = true;
			break;
		}
	}

	if (!match_found)
		return;

	if ((logger->max_live_buff_size - logger->live_msgs_len) >= len) {
		memcpy(logger->live_msgs, data, len);
		logger->live_msgs_len += len;
		logger->live_msgs += len;
	}
}

void bnxt_log_live(struct bnxt *bp, u16 logger_id, const char *format, ...)
{
	struct list_head *head, *pos, *lg;
	struct bnxt_logger *logger = NULL;
	va_list args;
	int len;

	head = &bp->loggers_list;
	list_for_each_safe(pos, lg, head) {
		logger = list_entry(pos, struct bnxt_logger, list);
		if (logger->logger_id == logger_id)
			break;
	}

	if (!logger || !logger->live_msgs || (logger->live_msgs_len >= logger->max_live_buff_size))
		return;

	va_start(args, format);
	len = bnxt_log_info(logger->live_msgs + logger->live_msgs_len,
			    logger->max_live_buff_size - logger->live_msgs_len,
			    format, args);
	va_end(args);

	logger->live_msgs_len += len;
}

static size_t bnxt_get_data_len(char *buf)
{
	size_t count = 0;

	while (*buf++ != '\n')
		count++;
	return count + 1;
}

static size_t bnxt_collect_logs_buffer(struct bnxt_logger *logger, char *dest)
{
	u32 mask = BNXT_LOG_NUM_BUFFERS(logger->buffer_size) - 1;
	u16 head = logger->head;
	u16 tail = logger->tail;
	size_t total_len = 0;
	int count;

	if (!logger->valid)
		return 0;

	count = (tail > head) ? (tail - head) : (tail - head + mask + 1);
	while (count--) {
		void *src = logger->msgs + BNXT_LOG_MSG_SIZE * (head & mask);
		size_t len;

		len = bnxt_get_data_len(src);
		memcpy(dest + total_len, src, len);
		total_len += len;
		head++;
	}

	return total_len;
}

static int bnxt_get_ctx_mem_length(struct bnxt *bp, u32 total_segments)
{
	u32 seg_hdr_len = sizeof(struct bnxt_coredump_segment_hdr);
	struct bnxt_ctx_mem_info *ctx = bp->ctx;
	size_t seg_len;
	size_t length = 0;
	int i;

	if (!ctx)
		return 0;

	for (i = 0; i < total_segments; i++) {
		int type = l2_ctx_mem_seg_list[i] - BNXT_LOG_CTX_MEM_SEG_ID_START;
		struct bnxt_ctx_mem_type *ctxm;

		ctxm = &ctx->ctx_arr[type];
		if (!ctxm)
			continue;

		seg_len = bnxt_copy_ctx_mem(bp, ctxm, NULL, 0);
		length += (seg_hdr_len + seg_len);
	}
	return length;
}

size_t bnxt_get_loggers_coredump_size(struct bnxt *bp, u16 dump_type)
{
	struct list_head *head, *pos, *lg;
	struct bnxt_logger *logger;
	size_t len = 0;

	mutex_lock(&bp->log_lock);
	head = &bp->loggers_list;
	list_for_each_safe(pos, lg, head) {
		logger = list_entry(pos, struct bnxt_logger, list);
		if (logger->logger_id == BNXT_LOGGER_L2_CTX_MEM) {
			if (dump_type != BNXT_DUMP_DRIVER_WITH_CTX_MEM)
				continue;
			len += bnxt_get_ctx_mem_length(bp, logger->total_segs);
			continue;
		}
		len += sizeof(struct bnxt_coredump_segment_hdr) +
		       logger->max_live_buff_size + logger->buffer_size;
	}
	mutex_unlock(&bp->log_lock);
	return len;
}

void bnxt_start_logging_coredump(struct bnxt *bp, char *dest_buf, u32 *dump_len, u16 dump_type)
{
	u32 null_seg_len, requested_buf_len, total_segs_per_logger;
	u32 ver_get_resp_len = sizeof(struct hwrm_ver_get_output);
	u32 offset, seg_hdr_len, total_seg_count;
	struct bnxt_coredump_segment_hdr seg_hdr;
	u32 prev_live_msgs_len, seg_id_in_hdr;
	struct list_head *head, *pos, *lg;
	struct bnxt_time start_time;
	struct bnxt_logger *logger;
	void *seg_hdr_dest;
	s16 start_utc;
	size_t seg_len;
	int i;

	seg_hdr_len = sizeof(seg_hdr);
	total_seg_count = 0;
	offset = 0;

	requested_buf_len = *dump_len;
	start_time = bnxt_get_current_time(bp);
	start_utc = sys_tz.tz_minuteswest;

	mutex_lock(&bp->log_lock);

	/* First segment should be hwrm_ver_get response.
	 * For hwrm_ver_get response Component id = 2 and Segment id = 0
	 */
	bnxt_fill_coredump_seg_hdr(bp, &seg_hdr, NULL, ver_get_resp_len,
				   0, 0, 0, 2, 0);
	memcpy(dest_buf + offset, &seg_hdr, seg_hdr_len);
	offset += seg_hdr_len;
	memcpy(dest_buf + offset, &bp->ver_resp, ver_get_resp_len);
	offset += ver_get_resp_len;
	*dump_len = seg_hdr_len + ver_get_resp_len;

	head = &bp->loggers_list;
	list_for_each_safe(pos, lg, head) {
		seg_hdr_dest = NULL;
		seg_len = 0;

		logger = list_entry(pos, struct bnxt_logger, list);
		total_segs_per_logger = logger->total_segs;
		logger->live_msgs_len = 0;
		prev_live_msgs_len = 0;

		if (logger->logger_id == BNXT_LOGGER_L2_CTX_MEM) {
			if (dump_type != BNXT_DUMP_DRIVER_WITH_CTX_MEM || !bp->ctx)
				continue;
		}

		netdev_dbg(bp->dev, "logger id %d -> total seg %d\n",
			   logger->logger_id, total_segs_per_logger);
		for (i = 0; i < total_segs_per_logger; i++) {
			seg_hdr_dest = dest_buf + offset;
			offset += seg_hdr_len;
			seg_len = 0;

			if (logger->logger_id == BNXT_LOGGER_L2_CTX_MEM) {
				struct bnxt_ctx_mem_info *ctx = bp->ctx;
				struct bnxt_ctx_mem_type *ctxm;
				u16 type;

				type = l2_ctx_mem_seg_list[i] - BNXT_LOG_CTX_MEM_SEG_ID_START;
				ctxm = &ctx->ctx_arr[type];
				seg_len = bnxt_copy_ctx_mem(bp, ctxm, dest_buf, offset);
				offset += seg_len;
				seg_id_in_hdr = logger->seg_list ?
						logger->seg_list[i] : total_seg_count;
			} else if (logger->logger_id == BNXT_LOGGER_L2_RING_CONTENTS) {
				if (logger->msgs) {
					memcpy(dest_buf + offset, logger->msgs,
					       logger->buffer_size);
					seg_len = logger->buffer_size;
					offset += seg_len;
				}
				seg_id_in_hdr = logger->seg_list ?
					logger->seg_list[i] : total_seg_count;
			} else {
				/* First collect logs from buffer */
				seg_len = bnxt_collect_logs_buffer(logger, dest_buf + offset);
				offset += seg_len;

				/* Let logger to collect live messages */
				logger->live_msgs = dest_buf + offset;

				prev_live_msgs_len = logger->live_msgs_len;
				seg_id_in_hdr = logger->seg_list ?
						logger->seg_list[i] : total_seg_count;
				logger->log_live_op(bp, logger->seg_list ?
						    logger->seg_list[i] : total_seg_count);
				seg_len += (logger->live_msgs_len - prev_live_msgs_len);
				offset += seg_len;
			}

			bnxt_fill_coredump_seg_hdr(bp, &seg_hdr, NULL, seg_len,
						   0, 0, 0, 13, 0);
			seg_hdr.segment_id = cpu_to_le32(seg_id_in_hdr);
			memcpy(seg_hdr_dest, &seg_hdr, sizeof(seg_hdr));
			total_seg_count++;
			*dump_len += (seg_hdr_len + seg_len);
			netdev_dbg(bp->dev, "seg 0x%x seg_len (%d + %d) offset %d len %d\n",
				   seg_id_in_hdr, seg_hdr_len, (unsigned int)seg_len,
				   offset, *dump_len);
		}
	}

	null_seg_len = BNXT_COREDUMP_BUF_LEN(requested_buf_len) - *dump_len;
	offset = *dump_len;
	bnxt_fill_empty_seg(bp, dest_buf + offset, null_seg_len);

	/* Fix the coredump record at last 1024 bytes */
	offset = requested_buf_len - sizeof(struct bnxt_coredump_record);
	netdev_dbg(bp->dev, "From %s %d offset %d buf len %d\n",
		   __func__, __LINE__, offset, requested_buf_len);
	bnxt_fill_coredump_record(bp, (void *)dest_buf + offset,
				  start_time, start_utc,
				  total_seg_count + 2, 0);

	*dump_len = *dump_len + null_seg_len +
		    sizeof(struct bnxt_coredump_record) +
		    sizeof(struct bnxt_coredump_segment_hdr);

	mutex_unlock(&bp->log_lock);
}

void bnxt_reset_loggers(struct bnxt *bp)
{
	struct list_head *head, *pos, *lg;
	struct bnxt_logger *logger;

	mutex_lock(&bp->log_lock);
	head = &bp->loggers_list;
	list_for_each_safe(pos, lg, head) {
		logger = list_entry(pos, struct bnxt_logger, list);
		logger->head = 0;
		logger->tail = 0;
		logger->valid = false;
	}
	mutex_unlock(&bp->log_lock);
}
