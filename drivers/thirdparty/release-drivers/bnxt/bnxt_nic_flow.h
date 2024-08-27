/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Broadcom
 * All rights reserved.
 */
#ifndef BNXT_NIC_FLOW_H
#define BNXT_NIC_FLOW_H

int bnxt_nic_flows_init(struct bnxt *bp);
void bnxt_nic_flows_deinit(struct bnxt *bp);
int bnxt_nic_flows_open(struct bnxt *bp);
void bnxt_nic_flows_close(struct bnxt *bp);
int bnxt_nic_flows_filter_add(struct bnxt *bp, __le64 filter_id, const u8 *mac_addr);
int bnxt_nic_flows_roce_add(struct bnxt *bp);
int bnxt_nic_flows_roce_rem(struct bnxt *bp, __le64 filter_id);
int bnxt_nic_flows_filter_info_get(struct bnxt *bp, __le64 filter_id,
				   u32 *l2_ctxt_id, u32 *prof_func);
int bnxt_nic_flow_dmac_filter_get(struct bnxt *bp, u8 *dmac, __le64 *filter_id);
#endif /* BNXT_NIC_FLOW_H */
