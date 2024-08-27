/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2016-2018 Broadcom Limited
 * Copyright (c) 2018-2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_ULP_H
#define BNXT_ULP_H

#define BNXT_ROCE_ULP	0
#define BNXT_OTHER_ULP	1
#define BNXT_MAX_ULP	2

#define BNXT_MIN_ROCE_CP_RINGS	2
#define BNXT_MIN_ROCE_STAT_CTXS	1

#define BNXT_MAX_ROCE_MSIX_VF		2
#define BNXT_MAX_ROCE_MSIX_PF		9
#define BNXT_MAX_ROCE_MSIX_NPAR_PF	5
#define BNXT_MAX_ROCE_MSIX		64
#define BNXT_MAX_ROCE_MSIX_GEN_P5_PF	BNXT_MAX_ROCE_MSIX

#define BNXT_ULP_MAX_LOG_BUFFERS	1024
#define BNXT_ULP_MAX_LIVE_LOG_SIZE	(32 << 20)

struct hwrm_async_event_cmpl;
struct bnxt;

struct bnxt_msix_entry {
	u32	vector;
	u32	ring_idx;
	u32	db_offset;
};

struct bnxt_ulp_ops {
	/* async_notifier() cannot sleep (in BH context) */
	void (*ulp_async_notifier)(void *, struct hwrm_async_event_cmpl *);
	void (*ulp_irq_stop)(void *, bool);
	void (*ulp_irq_restart)(void *, struct bnxt_msix_entry *);
	void (*ulp_log_live)(void *handle, u32 seg_id);
};

struct bnxt_fw_msg {
	void	*msg;
	int	msg_len;
	void	*resp;
	int	resp_max_len;
	int	timeout;
};

struct bnxt_ulp {
	void		*handle;
	struct bnxt_ulp_ops __rcu *ulp_ops;
	unsigned long	*async_events_bmap;
	u16		max_async_event_id;
	u16		msix_requested;
};

struct bnxt_en_dev {
	struct net_device *net;
	struct pci_dev *pdev;
	struct bnxt_msix_entry			msix_entries[BNXT_MAX_ROCE_MSIX];
	u32 flags;
	#define BNXT_EN_FLAG_ROCEV1_CAP		0x1
	#define BNXT_EN_FLAG_ROCEV2_CAP		0x2
	#define BNXT_EN_FLAG_ROCE_CAP		(BNXT_EN_FLAG_ROCEV1_CAP | \
						 BNXT_EN_FLAG_ROCEV2_CAP)
	#define BNXT_EN_FLAG_MSIX_REQUESTED	0x4
	#define BNXT_EN_FLAG_ULP_STOPPED	0x8
	#define BNXT_EN_FLAG_ASYM_Q		0x10
	#define BNXT_EN_FLAG_MULTI_HOST		0x20
	#define BNXT_EN_FLAG_VF			0x40
	#define BNXT_EN_FLAG_HW_LAG		0x80
	#define BNXT_EN_FLAG_ROCE_VF_RES_MGMT	0x100
	#define BNXT_EN_FLAG_MULTI_ROOT		0x200
	#define BNXT_EN_FLAG_SW_RES_LMT		0x400
#define BNXT_EN_ASYM_Q(edev)		((edev)->flags & BNXT_EN_FLAG_ASYM_Q)
#define BNXT_EN_MH(edev)		((edev)->flags & BNXT_EN_FLAG_MULTI_HOST)
#define BNXT_EN_VF(edev)		((edev)->flags & BNXT_EN_FLAG_VF)
#define BNXT_EN_HW_LAG(edev)		((edev)->flags & BNXT_EN_FLAG_HW_LAG)
#define BNXT_EN_MR(edev)		((edev)->flags & BNXT_EN_FLAG_MULTI_ROOT)
#define BNXT_EN_SW_RES_LMT(edev)	((edev)->flags & BNXT_EN_FLAG_SW_RES_LMT)
	struct bnxt_ulp			*ulp_tbl;
	int				l2_db_size;	/* Doorbell BAR size in
							 * bytes mapped by L2
							 * driver.
							 */
	int				l2_db_size_nc;	/* Doorbell BAR size in
							 * bytes mapped as non-
							 * cacheable.
							 */
	u32				ulp_version;	/* bnxt_re checks the
							 * ulp_version is correct
							 * to ensure compatibility
							 * with bnxt_en.
							 */
	#define BNXT_ULP_VERSION	0x695a000f	/* Change this when any interface
							 * structure or API changes
							 * between bnxt_en and bnxt_re.
							 */
	unsigned long			en_state;
	void __iomem			*bar0;
	u16				hw_ring_stats_size;
	u16				pf_port_id;
	u8				port_partition_type;
#define BNXT_EN_NPAR(edev)		((edev)->port_partition_type)
	u8				port_count;
	struct bnxt_dbr			*en_dbr;

	struct bnxt_hdbr_info		*hdbr_info;
	u16				chip_num;
	int				l2_db_offset;	/* Doorbell BAR offset
							 * of non-cacheable.
							 */

	u16				ulp_num_msix_vec;
	u16				ulp_num_ctxs;
	struct mutex			en_dev_lock;	/* serialize ulp operations */
};

static inline bool bnxt_ulp_registered(struct bnxt_en_dev *edev)
{
	if (edev && rcu_access_pointer(edev->ulp_tbl->ulp_ops))
		return true;
	return false;
}

int bnxt_get_ulp_msix_num(struct bnxt *bp);
int bnxt_get_ulp_msix_num_in_use(struct bnxt *bp);
void bnxt_set_ulp_msix_num(struct bnxt *bp, int num);
int bnxt_get_ulp_stat_ctxs(struct bnxt *bp);
int bnxt_get_ulp_stat_ctxs_in_use(struct bnxt *bp);
void bnxt_set_ulp_stat_ctxs(struct bnxt *bp, int num_ctxs);
void bnxt_set_dflt_ulp_stat_ctxs(struct bnxt *bp);
void bnxt_ulp_stop(struct bnxt *bp);
void bnxt_ulp_start(struct bnxt *bp, int err);
void bnxt_ulp_sriov_cfg(struct bnxt *bp, int num_vfs);
#ifndef HAVE_AUXILIARY_DRIVER
void bnxt_ulp_shutdown(struct bnxt *bp);
#endif
void bnxt_ulp_irq_stop(struct bnxt *bp);
void bnxt_ulp_irq_restart(struct bnxt *bp, int err);
void bnxt_ulp_async_events(struct bnxt *bp, struct hwrm_async_event_cmpl *cmpl);
void bnxt_rdma_aux_device_uninit(struct bnxt *bp);
void bnxt_rdma_aux_device_init(struct bnxt *bp);
void bnxt_rdma_aux_device_add(struct bnxt *bp);
void bnxt_rdma_aux_device_del(struct bnxt *bp);
int bnxt_register_dev(struct bnxt_en_dev *edev,
		      struct bnxt_ulp_ops *ulp_ops, void *handle);
int bnxt_unregister_dev(struct bnxt_en_dev *edev);
int bnxt_send_msg(struct bnxt_en_dev *edev, struct bnxt_fw_msg *fw_msg);
int bnxt_register_async_events(struct bnxt_en_dev *edev,
			       unsigned long *events_bmap, u16 max_id);
int bnxt_dbr_complete(struct bnxt_en_dev *edev, u32 epoch);
void bnxt_ulp_log_live(struct bnxt_en_dev *edev, u16 logger_id,
		       const char *format, ...);
void bnxt_ulp_log_raw(struct bnxt_en_dev *edev, u16 logger_id, void *data, int len);
#endif
