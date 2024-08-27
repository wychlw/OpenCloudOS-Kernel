/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_TFC_H
#define BNXT_TFC_H

#include <linux/hashtable.h>
#include "bnxt_mpc.h"

struct bnxt_tfc_mpc_info {
	struct kmem_cache	*mpc_cache;
	atomic_t		pending;
};

struct tfc_cmpl {
	__le16	client_status_type;
	#define TFC_CMPL_TYPE_MASK			0x3fUL
	#define TFC_CMPL_TYPE_SFT			0
	#define TFC_CMPL_TYPE_MID_PATH_SHORT		0x1eUL
	#define TFC_CMPL_TYPE_MID_PATH_LONG		0x1fUL

	#define TFC_CMPL_STATUS_MASK			0xf00UL
	#define TFC_CMPL_STATUS_SFT			8
	#define TFC_CMPL_STATUS_OK			0x0UL
	#define TFC_CMPL_STATUS_UNSPRT_ERR		0x1UL
	#define TFC_CMPL_STATUS_FMT_ERR			0x2UL
	#define TFC_CMPL_STATUS_SCOPE_ERR		0x3UL
	#define TFC_CMPL_STATUS_ADDR_ERR		0x4UL
	#define TFC_CMPL_STATUS_CACHE_ERR		0x5UL

	#define TFC_CMPL_MP_CLIENT_MASK			0xf000UL
	#define TFC_CMPL_MP_CLIENT_SFT			12
	#define TFC_CMPL_MP_CLIENT_TE_CFA		0x2UL
	#define TFC_CMPL_MP_CLIENT_RE_CFA		0x3UL

	__le16	opc_dmalen;

	#define TFC_CMPL_OPC_MASK			0xffUL
	#define TFC_CMPL_OPC_SFT			0
	#define TFC_CMPL_OPC_TBL_READ			0
	#define TFC_CMPL_OPC_TBL_WRITE			1
	#define TFC_CMPL_OPC_TBL_READ_CLR		2
	#define TFC_CMPL_OPC_TBL_INVALIDATE		5
	#define TFC_CMPL_OPC_TBL_EVENT_COLLECTION	6
	#define TFC_CMPL_OPC_TBL_EM_SEARCH		8
	#define TFC_CMPL_OPC_TBL_EM_INSERT		9
	#define TFC_CMPL_OPC_TBL_EM_DELETE		10
	#define TFC_CMPL_OPC_TBL_EM_CHAIN		11

	u32	opaque;

	__le32	v_hmsb_tbl_type_scope;
	#define TFC_CMPL_V				0x1UL
	#define TFC_CMPL_V_MASK				0x1UL
	#define TFC_CMPL_V_SFT				0
	#define TFC_CMPL_HASH_MSB_MASK			0xfffUL
	#define TFC_CMPL_HASH_MSB_SFT			12
	#define TFC_CMPL_TBL_TYPE_MASK			0xf000UL
	#define TFC_CMPL_TBL_TYPE_SFT			12
	#define TFC_CMPL_TBL_TYPE_ACTION		0
	#define TFC_CMPL_TBL_TYPE_EM			1
	#define TFC_CMPL_TBL_SCOPE_MASK			0x1f000000UL
	#define TFC_CMPL_TBL_SCOPE_SFT			24

	__le32	v_tbl_index;
	#define TFC_CMPL_TBL_IDX_MASK			0x3ffffffUL
	#define TFC_CMPL_TBL_IDX_SFT			0

	__le32	l_cmpl[4];
};

/*
 * Use a combination of opcode, table_type, table_scope and table_index to
 * generate a unique opaque field, which can be used to verify the completion
 * later.
 *
 * cccc_ssss_siii_iiii_iiii_iiii_iiii_iiii
 * opaque[31:28]      (c) opcode
 * opaque[27:23]      (s) tbl scope
 * opaque[22:00]      (i) tbl index
 *
 * 0x1080000a
 * 0x01000001
 * 0x1000000a
 */
#define TFC_CMPL_OPC_NIB_MASK				0xfUL
#define TFC_CMPL_OPQ_OPC_SFT				28
#define TFC_CMPL_TBL_23B_IDX_MASK			0x7fffffUL
#define TFC_CMPL_TBL_SCOPE_OPQ_SFT			1
#define TFC_CMD_TBL_SCOPE_OPQ_SFT			23

/* Used to generate opaque field for command send */
#define BNXT_TFC_CMD_OPQ(opc, ts, ti)					\
	((((opc) & TFC_CMPL_OPC_NIB_MASK) << TFC_CMPL_OPQ_OPC_SFT) |	\
	 ((ts) << TFC_CMD_TBL_SCOPE_OPQ_SFT) |				\
	 ((ti) & TFC_CMPL_TBL_23B_IDX_MASK))

/* Used to generate opaque field for completion verification */
#define BNXT_TFC_CMPL_OPAQUE(tfc_cmpl)                                      \
	((((u32)le16_to_cpu((tfc_cmpl)->opc_dmalen) & TFC_CMPL_OPC_NIB_MASK) << \
						TFC_CMPL_OPQ_OPC_SFT) | \
	((le32_to_cpu((tfc_cmpl)->v_hmsb_tbl_type_scope) & TFC_CMPL_TBL_SCOPE_MASK) >> \
						TFC_CMPL_TBL_SCOPE_OPQ_SFT) |\
	(le32_to_cpu((tfc_cmpl)->v_tbl_index) & TFC_CMPL_TBL_23B_IDX_MASK))

#define BNXT_INV_TMPC_OPAQUE				0xffffffff

#define TFC_CMPL_STATUS(tfc_cmpl)				\
	(le16_to_cpu((tfc_cmpl)->client_status_type) &		\
	TFC_CMPL_STATUS_MASK)

struct bnxt_tfc_cmd_ctx {
	struct completion cmp;
	struct tfc_cmpl tfc_cmp;
};

struct bnxt_mpc_mbuf {
	uint32_t chnl_id;
	uint8_t	cmp_type;
	uint8_t	*msg_data;
	/* MPC msg size in bytes, must be multiple of 16Bytes */
	uint16_t msg_size;
};

static inline bool bnxt_tfc_busy(struct bnxt *bp)
{
	struct bnxt_tfc_mpc_info *tfc_info = bp->tfc_info;

	return tfc_info && atomic_read(&tfc_info->pending) > 0;
}

void bnxt_tfc_buf_dump(struct bnxt *bp, char *hdr,
		       uint8_t *msg, int msglen,
		       int prtwidth, int linewidth);
void bnxt_free_tfc_mpc_info(struct bnxt *bp);
int bnxt_alloc_tfc_mpc_info(struct bnxt *bp);

int bnxt_mpc_send(struct bnxt *bp,
		  struct bnxt_mpc_mbuf *in_msg,
		  struct bnxt_mpc_mbuf *out_msg,
		  uint32_t *opaque);
void bnxt_tfc_mpc_cmp(struct bnxt *bp, u32 client, unsigned long handle,
		      struct bnxt_cmpl_entry cmpl[], u32 entries);
#endif
