/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2022-2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef __BNXT_HDBR_H__
#define __BNXT_HDBR_H__

/*
 * 64-bit doorbell
 * +------+-----+-----------+-----+-----+------+-----+------+------+-----+-----+
 * |Offset|63,60|         59|   58|57,56|  (4) |51,32|31,,27| 26,25|   24| 23,0|
 * +------+-----+-----------+-----+-----+------+-----+------+------+-----+-----+
 * |      |     |           |     |     |unused|     |unused|toggle|epoch|     |
 * |  0x0 | type|   unused  |valid| path|------| xID |------+------+-----+index|
 * |      |     |           |     |     | pi-hi|     |       pi-lo       |     |
 * +------+-----+-----------+-----+-----+------+-----+------+------+-----+-----+
 *
 * 64-bit doorbell copy format for HW DBR recovery
 * +------+-----+-----------+-----+-----+------+-----+------+------+-----+-----+
 * |Offset|63,60|         59|   58|57,56|  (4) |51,32|  (5) | 26,25|   24| 23,0|
 * +------+-----+-----------+-----+-----+------+-----+------+------+-----+-----+
 * |0x0   | type|debug_trace|valid| path|unused| xID |unused|toggle|epoch|index|
 * +------+-----+-----------+-----+-----+------+-----+------+------+-----+-----+
 */

#define DBC_TYPE_MASK		(0xfULL << 60)

#define DBC_VALUE_INIT		DBR_INDEX_MASK
#define DBC_VALUE_LAST		(DBC_TYPE_MASK | DBR_VALID)

/* Doorbell Recovery Kernel Memory Structures
 * +------+------+-----+------+-----+------+------+---------+------+----+-----+
 * |Offset| 63,48|47,32| 31,12|11,10|   9,8|   7,4|        3|     2|   1|    0|
 * +------+------+-----+------+-----+------+------+---------+------+----+-----+
 * |0x0   |unused|  pi |unused| size|stride|unused|db_format|linked|last|valid|
 * +------+------+-----+------+-----+------+------+---------+------+----+-----+
 * |0x8   |                          memptr                                   |
 * +------+-------------------------------------------------------------------+
 */
#define DBC_KERNEL_ENTRY_SIZE 16

#define PAGE_SIZE_4K		4096
#define MAX_KMEM_4K_PAGES	1029
#define NSLOT_PER_4K_PAGE	(PAGE_SIZE_4K / DBC_KERNEL_ENTRY_SIZE - 1)

struct bnxt_hdbr_ktbl {
	struct pci_dev	*pdev;
	/* protect this main DB copy kernel memory table data structure */
	spinlock_t	hdbr_kmem_lock;
	int		group_type;
	int		first_avail;
	int		first_empty;
	int		last_entry;
	int		num_4k_pages;
	int		slot_avail;
	void		*pages[MAX_KMEM_4K_PAGES];
	dma_addr_t	daddr;
	struct dbc_drk64 *link_slot;
};

static inline struct dbc_drk64 *get_slot(struct bnxt_hdbr_ktbl *ktbl, int idx)
{
	return ((struct dbc_drk64 *)ktbl->pages[idx / NSLOT_PER_4K_PAGE])
		+ idx % NSLOT_PER_4K_PAGE;
}

static inline void bnxt_hdbr_clear_slot(struct dbc_drk64 *slt)
{
	slt->flags = 0;
	wmb();	/* Sync flags before clear memory pointer */
	slt->memptr = 0;
}

static inline void bnxt_hdbr_set_slot(struct dbc_drk64 *slt, dma_addr_t da,
				      u16 pi, bool last)
{
	u64 flags;

	flags = DBC_DRK64_VALID | DBC_DRK64_DB_FORMAT_B64 |
		DBC_DRK64_STRIDE_OFF;
	flags |= ((u64)pi << DBC_DRK64_PI_SFT);
	if (last)
		flags |= DBC_DRK64_LAST;

	slt->memptr = cpu_to_le64(da);
	wmb();	/* Sync memory pointer before setting flags */
	slt->flags = cpu_to_le64(flags);
}

static inline void bnxt_hdbr_set_link(struct dbc_drk64 *ls, dma_addr_t da)
{
	ls->memptr = cpu_to_le64(da);
	wmb();	/* Sync memory pointer before setting flags */
	ls->flags = cpu_to_le64(DBC_DRK64_VALID | DBC_DRK64_LINKED);
}

/* L2 driver part HW based doorbell drop recovery defination */
#define HDBR_DB_SIZE 8
#define HDBR_L2_SQ_BLK_SIZE 1
#define HDBR_L2_SRQ_BLK_SIZE 1
#define HDBR_L2_CQ_BLK_SIZE 3
#define HDBR_DB_PER_PAGE (PAGE_SIZE_4K / HDBR_DB_SIZE)
#define HDBR_L2_SQ_ENTRY_PER_PAGE (HDBR_DB_PER_PAGE / HDBR_L2_SQ_BLK_SIZE)
#define HDBR_L2_SRQ_ENTRY_PER_PAGE (HDBR_DB_PER_PAGE / HDBR_L2_SRQ_BLK_SIZE)
#define HDBR_L2_CQ_ENTRY_PER_PAGE (HDBR_DB_PER_PAGE / HDBR_L2_CQ_BLK_SIZE)

struct hdbr_l2_pg {
	__le64		*ptr;
	dma_addr_t	da;
	int		ktbl_idx;
};

struct bnxt_hdbr_l2_pgs {
	int	max_pages;
	int	alloced_pages;
	int	grp_size;
	int	entries_per_pg;
	int	next_page;
	int	next_entry;
	struct hdbr_l2_pg pages[] __counted_by(max_pages);
};

int bnxt_hdbr_r2g(u32 ring_type);
int bnxt_hdbr_get_grp(u64 db_val);
int bnxt_hdbr_ktbl_init(struct bnxt *bp, int group, void *pg_ptr, dma_addr_t da);
void bnxt_hdbr_ktbl_uninit(struct bnxt *bp, int group);
int bnxt_hdbr_reg_apg(struct bnxt_hdbr_ktbl *ktbl, dma_addr_t ap_da, int *idx, u16 pi);
void bnxt_hdbr_unreg_apg(struct bnxt_hdbr_ktbl *ktbl, int idx);
char *bnxt_hdbr_ktbl_dump(struct bnxt_hdbr_ktbl *ktbl);
int bnxt_hdbr_l2_init(struct bnxt *bp);
void bnxt_hdbr_l2_uninit(struct bnxt *bp, int group);
__le64 *bnxt_hdbr_reg_db(struct bnxt *bp, int group);
void bnxt_hdbr_reset_l2pgs(struct bnxt *bp);
char *bnxt_hdbr_l2pg_dump(struct bnxt_hdbr_l2_pgs *app_pgs);

#endif
