/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Broadcom
 * All rights reserved.
 */

#ifndef _ULP_NIC_FLOW_H_
#define _ULP_NIC_FLOW_H_

/* Add per DMAC RoCE and RoCE CNP flows
 * @l2_ctxt_id[out]: pointer to where to store the allocated l2 context ident
 * @prof_func[out]: pointer to where to store the allocated profile func ident
 * @roce_flow_id[out]: pointer to where to store  per DMAC RoCE flow id
 * @roce_cnp_flow_id[out]: pointer to where to store per DMAC RoCE CNP flow id
 * return 0 on success and - on failure
 */
int bnxt_ulp_nic_flows_roce_add(struct bnxt *bp, __u64 l2_filter_id,
				u32 *l2_ctxt_id, u32 *prof_func,
				u32 *flow_id, u64 *flow_cnt_hndl,
				u32 *cnp_flow_id, u64 *cnp_flow_cnt_hndl);

/* Delete per DMAC RoCE and RoCE CNP flows
 * @l2_ctxt_id[in]: The l2 context identifier to free
 * @prof_func[in]: The profile func identifier to free
 * @roce_flow_id[in]: The per DMAC RoCE flow id to free
 * @roce_cnp_flow_id[in]: The per DMAC RoCE CNP flow id to free
 * return 0 on success and - on failure
 */
int bnxt_ulp_nic_flows_roce_del(struct bnxt *bp, __u64 l2_filter_id,
				u32 l2_ctxt_id, u32 prof_func,
				u32 flow_id, u32 cnp_flow_id);

#endif /* #ifndef _ULP_NIC_FLOW_H_ */
