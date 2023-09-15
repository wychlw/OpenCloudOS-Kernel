/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BLK_CGROUP_H
#define _BLK_CGROUP_H
/*
 * Common Block IO controller cgroup interface
 *
 * Based on ideas and code from CFQ, CFS and BFQ:
 * Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
 *
 * Copyright (C) 2008 Fabio Checconi <fabio@gandalf.sssup.it>
 *		      Paolo Valente <paolo.valente@unimore.it>
 *
 * Copyright (C) 2009 Vivek Goyal <vgoyal@redhat.com>
 * 	              Nauman Rafique <nauman@google.com>
 */

#include <linux/types.h>
#include <linux/cgroup.h>
#include <linux/rue.h>

struct bio;
struct cgroup_subsys_state;
struct gendisk;

#define FC_APPID_LEN              129

#ifdef CONFIG_BLK_CGROUP
extern struct cgroup_subsys_state * const blkcg_root_css;

void blkcg_schedule_throttle(struct gendisk *disk, bool use_memdelay);
void blkcg_maybe_throttle_current(void);
bool blk_cgroup_congested(void);
void blkcg_pin_online(struct cgroup_subsys_state *blkcg_css);
void blkcg_unpin_online(struct cgroup_subsys_state *blkcg_css);
struct list_head *blkcg_get_cgwb_list(struct cgroup_subsys_state *css);
struct cgroup_subsys_state *bio_blkcg_css(struct bio *bio);

/*
 * Upstream dec223c92a4 (blk-cgroup: move struct blkcg to block/blk-cgroup.h)
 * move the struct blkcg to block/blk-cgroup.c
 * Move it out for RUE module.
 */
struct blkcg {
	struct cgroup_subsys_state	css;
	spinlock_t			lock;
	refcount_t			online_pin;

	struct radix_tree_root		blkg_tree;
	struct blkcg_gq	__rcu		*blkg_hint;
	struct hlist_head		blkg_list;

	struct blkcg_policy_data	*cpd[BLKCG_MAX_POLS];

	struct list_head		all_blkcgs_node;

	/*
	 * List of updated percpu blkg_iostat_set's since the last flush.
	 */
	struct llist_head __percpu	*lhead;

#ifdef CONFIG_BLK_CGROUP_FC_APPID
	char                            fc_app_id[FC_APPID_LEN];
#endif
#ifdef CONFIG_CGROUP_WRITEBACK
	struct list_head		cgwb_list;
#endif
#ifdef CONFIG_BLK_CGROUP_DISKSTATS
	unsigned int			dkstats_on;
	struct list_head		dkstats_list;
	struct blkcg_dkstats		*dkstats_hint;
#endif

#ifdef CONFIG_BLK_DEV_THROTTLING_CGROUP_V1
	struct percpu_counter           nr_dirtied;
	unsigned long                   bw_time_stamp;
	unsigned long                   dirtied_stamp;
	unsigned long                   dirty_ratelimit;
	unsigned long long              buffered_write_bps;
#endif

	KABI_RESERVE(1);
	KABI_RESERVE(2);
	KABI_RESERVE(3);
	KABI_RESERVE(4);
};

struct rue_io_module_ops {
	void (*blkcg_update_bandwidth)(struct blkcg *blkcg);

	KABI_RESERVE(1);
	KABI_RESERVE(2);
	KABI_RESERVE(3);
	KABI_RESERVE(4);
};
extern struct rue_io_module_ops rue_io_ops;

#ifdef CONFIG_BLK_DEV_THROTTLING_CGROUP_V1
static inline uint64_t blkcg_buffered_write_bps(struct blkcg *blkcg)
{
	return blkcg->buffered_write_bps;
}

static inline unsigned long blkcg_dirty_ratelimit(struct blkcg *blkcg)
{
	return blkcg->dirty_ratelimit;
}

static inline struct blkcg *get_task_blkcg(struct task_struct *tsk)
{
	struct cgroup_subsys_state *css;

	rcu_read_lock();
	do {
		css = kthread_blkcg();
		if (!css)
			css = task_css(tsk, io_cgrp_id);
	} while (!css_tryget(css));
	rcu_read_unlock();

	return container_of(css, struct blkcg, css);
}
#endif

#else	/* CONFIG_BLK_CGROUP */

#define blkcg_root_css	((struct cgroup_subsys_state *)ERR_PTR(-EINVAL))

static inline void blkcg_maybe_throttle_current(void) { }
static inline bool blk_cgroup_congested(void) { return false; }
static inline struct cgroup_subsys_state *bio_blkcg_css(struct bio *bio)
{
	return NULL;
}
#endif	/* CONFIG_BLK_CGROUP */

int blkcg_set_fc_appid(char *app_id, u64 cgrp_id, size_t app_id_len);
char *blkcg_get_fc_appid(struct bio *bio);

#endif	/* _BLK_CGROUP_H */
