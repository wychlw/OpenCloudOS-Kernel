/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_LOG_H
#define BNXT_LOG_H

#define BNXT_LOGGER_L2			1
#define BNXT_LOGGER_ROCE		2
#define BNXT_LOGGER_L2_CTX_MEM		3
#define BNXT_LOGGER_L2_RING_CONTENTS	4

#define BNXT_SEGMENT_L2	0
#define BNXT_SEGMENT_ROCE	255
#define BNXT_SEGMENT_QP_CTX	256
#define BNXT_SEGMENT_SRQ_CTX	257
#define BNXT_SEGMENT_CQ_CTX	258
#define BNXT_SEGMENT_MR_CTX	270

#define BNXT_LOG_CTX_MEM_SEG_ID_START  0x100
#define BNXT_SEGMENT_L2_RING_CONTENT	0x200

#define BNXT_SEGMENT_CTX_MEM_QP			(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_QP)
#define BNXT_SEGMENT_CTX_MEM_SRQ		(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_SRQ)
#define BNXT_SEGMENT_CTX_MEM_CQ			(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_CQ)
#define BNXT_SEGMENT_CTX_MEM_VNIC		(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_VNIC)
#define BNXT_SEGMENT_CTX_MEM_STAT		(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_STAT)
#define BNXT_SEGMENT_CTX_MEM_SP_TQM_RING	(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_STQM)
#define BNXT_SEGMENT_CTX_MEM_FP_TQM_RING	(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_FTQM)
#define BNXT_SEGMENT_CTX_MEM_MRAV		(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_MRAV)
#define BNXT_SEGMENT_CTX_MEM_TIM		(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_TIM)
#define BNXT_SEGMENT_CTX_MEM_TX_CK		(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_TCK)
#define BNXT_SEGMENT_CTX_MEM_RX_CK		(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_RCK)
#define BNXT_SEGMENT_CTX_MEM_MP_TQM_RING	(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_MTQM)
#define BNXT_SEGMENT_CTX_MEM_SQ_DB_SHADOW	(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_SQDBS)
#define BNXT_SEGMENT_CTX_MEM_RQ_DB_SHADOW	(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_RQDBS)
#define BNXT_SEGMENT_CTX_MEM_SRQ_DB_SHADOW	(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_SRQDBS)
#define BNXT_SEGMENT_CTX_MEM_CQ_DB_SHADOW	(BNXT_LOG_CTX_MEM_SEG_ID_START + BNXT_CTX_CQDBS)

int bnxt_register_logger(struct bnxt *bp, u16 logger_id, u32 num_buffers,
			 void (*log_live)(void *, u32), u32 live_size);
void bnxt_unregister_logger(struct bnxt *bp, u16 logger_id);
void bnxt_log_add_msg(struct bnxt *bp, u16 logger_id, const char *format, ...);
void bnxt_log_live(struct bnxt *bp, u16 logger_id, const char *format, ...);
void bnxt_log_raw(struct bnxt *bp, u16 logger_id, void *data, int len);
void bnxt_reset_loggers(struct bnxt *bp);
size_t bnxt_get_loggers_coredump_size(struct bnxt *bp, u16 dump_type);
void bnxt_start_logging_coredump(struct bnxt *bp, char *dest_buf, u32 *dump_len, u16 dump_type);
int bnxt_log_ring_contents(struct bnxt *bp);
#endif
