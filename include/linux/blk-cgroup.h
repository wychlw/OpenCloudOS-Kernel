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

enum blkg_rwstat_type {
	BLKG_RWSTAT_READ,
	BLKG_RWSTAT_WRITE,
	BLKG_RWSTAT_SYNC,
	BLKG_RWSTAT_ASYNC,
	BLKG_RWSTAT_DISCARD,

	BLKG_RWSTAT_NR,
	BLKG_RWSTAT_TOTAL = BLKG_RWSTAT_NR,
};

/*
 * blkg_[rw]stat->aux_cnt is excluded for local stats but included for
 * recursive.  Used to carry stats of dead children.
 */
struct blkg_rwstat {
	struct percpu_counter       cpu_cnt[BLKG_RWSTAT_NR];
	atomic64_t          aux_cnt[BLKG_RWSTAT_NR];
};

struct blkg_rwstat_sample {
	u64             cnt[BLKG_RWSTAT_NR];
};

/*
 * A blkcg_gq (blkg) is association between a block cgroup (blkcg) and a
 * request_queue (q).  This is used by blkcg policies which need to track
 * information per blkcg - q pair.
 *
 * There can be multiple active blkcg policies and each blkg:policy pair is
 * represented by a blkg_policy_data which is allocated and freed by each
 * policy's pd_alloc/free_fn() methods.  A policy can allocate private data
 * area by allocating larger data structure which embeds blkg_policy_data
 * at the beginning.
 */
struct blkg_policy_data {
	/* the blkg and policy id this per-policy data belongs to */
	struct blkcg_gq         *blkg;
	int             plid;
	bool                online;
};

enum {
	LIMIT_LOW,
	LIMIT_MAX,
	LIMIT_CNT,
};

/*
 * To implement hierarchical throttling, throtl_grps form a tree and bios
 * are dispatched upwards level by level until they reach the top and get
 * issued.  When dispatching bios from the children and local group at each
 * level, if the bios are dispatched into a single bio_list, there's a risk
 * of a local or child group which can queue many bios at once filling up
 * the list starving others.
 *
 * To avoid such starvation, dispatched bios are queued separately
 * according to where they came from.  When they are again dispatched to
 * the parent, they're popped in round-robin order so that no single source
 * hogs the dispatch window.
 *
 * throtl_qnode is used to keep the queued bios separated by their sources.
 * Bios are queued to throtl_qnode which in turn is queued to
 * throtl_service_queue and then dispatched in round-robin order.
 *
 * It's also used to track the reference counts on blkg's.  A qnode always
 * belongs to a throtl_grp and gets queued on itself or the parent, so
 * incrementing the reference of the associated throtl_grp when a qnode is
 * queued and decrementing when dequeued is enough to keep the whole blkg
 * tree pinned while bios are in flight.
 */
struct throtl_qnode {
	struct list_head	node;		/* service_queue->queued[] */
	struct bio_list		bios;		/* queued bios */
	struct throtl_grp	*tg;		/* tg this qnode belongs to */
};

struct throtl_service_queue {
	struct throtl_service_queue *parent_sq;	/* the parent service_queue */

	/*
	 * Bios queued directly to this service_queue or dispatched from
	 * children throtl_grp's.
	 */
	struct list_head	queued[2];	/* throtl_qnode [READ/WRITE] */
	unsigned int		nr_queued[2];	/* number of queued bios */

	/*
	 * RB tree of active children throtl_grp's, which are sorted by
	 * their ->disptime.
	 */
	struct rb_root_cached	pending_tree;	/* RB tree of active tgs */
	unsigned int		nr_pending;	/* # queued in the tree */
	unsigned long		first_pending_disptime;	/* disptime of the first tg */
	struct timer_list	pending_timer;	/* fires on first_pending_disptime */
};

struct throtl_grp {
	/* must be the first member */
	struct blkg_policy_data pd;

	/* active throtl group service_queue member */
	struct rb_node rb_node;

	/* throtl_data this group belongs to */
	struct throtl_data *td;

	/* this group's service queue */
	struct throtl_service_queue service_queue;

	/*
	 * qnode_on_self is used when bios are directly queued to this
	 * throtl_grp so that local bios compete fairly with bios
	 * dispatched from children.  qnode_on_parent is used when bios are
	 * dispatched from this throtl_grp into its parent and will compete
	 * with the sibling qnode_on_parents and the parent's
	 * qnode_on_self.
	 */
	struct throtl_qnode qnode_on_self[2];
	struct throtl_qnode qnode_on_parent[2];

	/*
	 * Dispatch time in jiffies. This is the estimated time when group
	 * will unthrottle and is ready to dispatch more bio. It is used as
	 * key to sort active groups in service tree.
	 */
	unsigned long disptime;

	unsigned int flags;

	/* are there any throtl rules between this group and td? */
	bool has_rules_bps[2];
	bool has_rules_iops[2];

	/* internally used bytes per second rate limits */
	uint64_t bps[3][LIMIT_CNT];
	/* user configured bps limits */
	uint64_t bps_conf[3][LIMIT_CNT];

	/* internally used IOPS limits */
	unsigned int iops[3][LIMIT_CNT];
	/* user configured IOPS limits */
	unsigned int iops_conf[3][LIMIT_CNT];

	/* Number of bytes dispatched in current slice */
	uint64_t bytes_disp[2];
	/* Number of bio's dispatched in current slice */
	unsigned int io_disp[2];

	/* Number of bytes disptached pre sec in previous slice */
	uint64_t pre_bdisp[2];
	/* Number of bio's dispatched pre sec in previous slice */
	unsigned int pre_iodisp[2];
	/* Number of slice jump in trim slice */
	unsigned int nr_trim_slice[2];

	unsigned long last_low_overflow_time[2];

	uint64_t last_bytes_disp[2];
	unsigned int last_io_disp[2];

	atomic_t io_split_cnt[2];
	atomic_t last_io_split_cnt[2];

	/*
	 * The following two fields are updated when new configuration is
	 * submitted while some bios are still throttled, they record how many
	 * bytes/ios are waited already in previous configuration, and they will
	 * be used to calculate wait time under new configuration.
	 */
	long long carryover_bytes[2];
	int carryover_ios[2];

	unsigned long arrive_time[2];
	unsigned long last_check_time;

	unsigned long latency_target; /* us */
	unsigned long latency_target_conf; /* us */
	/* When did we start a new slice */
	unsigned long slice_start[2];
	unsigned long slice_end[2];

	unsigned long last_finish_time; /* ns / 1024 */
	unsigned long checked_last_finish_time; /* ns / 1024 */
	unsigned long avg_idletime; /* ns / 1024 */
	unsigned long idletime_threshold; /* us */
	unsigned long idletime_threshold_conf; /* us */

	unsigned int bio_cnt; /* total bios */
	unsigned int bad_bio_cnt; /* bios exceeding latency threshold */
	unsigned long bio_cnt_reset_time;

	struct blkg_rwstat stat_bytes;
	struct blkg_rwstat stat_ios;
};

#ifdef CONFIG_BLK_CGROUP
extern struct cgroup_subsys_state * const blkcg_root_css;

void blkcg_schedule_throttle(struct gendisk *disk, bool use_memdelay);
void blkcg_maybe_throttle_current(void);
bool blk_cgroup_congested(void);
void blkcg_pin_online(struct cgroup_subsys_state *blkcg_css);
void blkcg_unpin_online(struct cgroup_subsys_state *blkcg_css);
struct list_head *blkcg_get_cgwb_list(struct cgroup_subsys_state *css);
struct cgroup_subsys_state *bio_blkcg_css(struct bio *bio);

enum blkg_iostat_type {
	BLKG_IOSTAT_READ,
	BLKG_IOSTAT_WRITE,
	BLKG_IOSTAT_DISCARD,

	BLKG_IOSTAT_NR,
};

struct blkg_iostat {
	u64				bytes[BLKG_IOSTAT_NR];
	u64				ios[BLKG_IOSTAT_NR];
};

struct blkg_iostat_set {
	struct u64_stats_sync		sync;
	struct blkcg_gq		       *blkg;
	struct llist_node		lnode;
	int				lqueued;	/* queued in llist */
	struct blkg_iostat		cur;
	struct blkg_iostat		last;
};

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

	unsigned int			readwrite_dynamic_ratio;

	KABI_RESERVE(1);
	KABI_RESERVE(2);
	KABI_RESERVE(3);
	KABI_RESERVE(4);
};

/* association between a blk cgroup and a request queue */
struct blkcg_gq {
	/* Pointer to the associated request_queue */
	struct request_queue		*q;
	struct list_head		q_node;
	struct hlist_node		blkcg_node;
	struct blkcg			*blkcg;

	/* all non-root blkcg_gq's are guaranteed to have access to parent */
	struct blkcg_gq			*parent;

	/* reference count */
	struct percpu_ref		refcnt;

	/* is this blkg online? protected by both blkcg and q locks */
	bool				online;

	struct blkg_iostat_set __percpu	*iostat_cpu;
	struct blkg_iostat_set		iostat;

	struct blkg_policy_data		*pd[BLKCG_MAX_POLS];
#ifdef CONFIG_BLK_CGROUP_PUNT_BIO
	spinlock_t			async_bio_lock;
	struct bio_list			async_bios;
#endif
	union {
		struct work_struct	async_bio_work;
		struct work_struct	free_work;
	};

	atomic_t			use_delay;
	atomic64_t			delay_nsec;
	atomic64_t			delay_start;
	u64				last_delay;
	int				last_use;

	struct rcu_head			rcu_head;
};

/* Dynamic read/write ratio limitation */
#define MAX_READ_RATIO (5)
#define MIN_READ_RATIO (1)
#define DFL_READ_RATIO (3)

/*
 * When throttle by IOPS. The jiffy_wait of approx time could be one
 * throtl_slice of arrive time, which may not enough for small READ IOPS quota.
 *
 * In this case, if nr_queued[READ] of sq is 0, it is possible that iops
 * limitaion won't split by ratio. Write can use the read quota, which make
 * the quota overflow by about 50%. Add a RW_GRANULARITY to avoid this and
 * make ratio change smoothly.
 */
#define RW_GRANULARITY (5)

/* We measure latency for request size from <= 4k to >= 1M */
#define LATENCY_BUCKET_SIZE 9

struct latency_bucket {
	unsigned long total_latency; /* ns / 1024 */
	int samples;
};

struct avg_latency_bucket {
	unsigned long latency; /* ns / 1024 */
	bool valid;
};

struct throtl_data {
	/* service tree for active throtl groups */
	struct throtl_service_queue service_queue;

	struct request_queue *queue;

	/* Total Number of queued bios on READ and WRITE lists */
	unsigned int nr_queued[2];

	unsigned int throtl_slice;

	/* Work for dispatching throttled bios */
	struct work_struct dispatch_work;
	unsigned int limit_index;
	bool limit_valid[LIMIT_CNT];

	unsigned long low_upgrade_time;
	unsigned long low_downgrade_time;

	unsigned int scale;

	struct latency_bucket tmp_buckets[2][LATENCY_BUCKET_SIZE];
	struct avg_latency_bucket avg_buckets[2][LATENCY_BUCKET_SIZE];
	struct latency_bucket __percpu *latency_buckets[2];
	unsigned long last_calculate_time;
	unsigned long filtered_latency;

	bool track_bio_latency;
};

struct rue_io_module_ops {
	void (*blkcg_update_bandwidth)(struct blkcg *blkcg);
	void (*cgroup_sync)(struct mem_cgroup *memcg);
	uint64_t (*calc_readwrite_bps_limit)(struct throtl_data *td, struct throtl_grp *tg,
			struct blkcg_gq *blkg, int rw, uint64_t ret);
	unsigned int (*calc_readwrite_iops_limit)(struct throtl_data *td, struct throtl_grp *tg,
			struct blkcg_gq *blkg, int rw, unsigned int ret);
	int (*new_dynamic_ratio)(struct throtl_grp *tg);
	bool (*throtl_info_scale_up)(struct wbt_throtl_info *ti, bool force_max);
	bool (*throtl_info_scale_down)(struct wbt_throtl_info *ti, bool hard_throttle);
	void (*throtl_info_calc_limit)(struct wbt_throtl_info *ti);

	KABI_RESERVE(1);
	KABI_RESERVE(2);
	KABI_RESERVE(3);
	KABI_RESERVE(4);
};
extern struct rue_io_module_ops rue_io_ops;

static inline struct blkcg *css_to_blkcg(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct blkcg, css) : NULL;
}

/**
 * blkcg_parent - get the parent of a blkcg
 * @blkcg: blkcg of interest
 *
 * Return the parent blkcg of @blkcg.  Can be called anytime.
 */
static inline struct blkcg *blkcg_parent(struct blkcg *blkcg)
{
	return css_to_blkcg(blkcg->css.parent);
}

#ifdef CONFIG_BLK_DEV_THROTTLING_CGROUP_V1
extern unsigned int sysctl_buffered_write_bps_hierarchy __read_mostly;
extern unsigned int sysctl_skip_throttle_prio_req __read_mostly;

static inline uint64_t blkcg_buffered_write_bps(struct blkcg *blkcg)
{
	return blkcg->buffered_write_bps;
}

static inline unsigned long blkcg_dirty_ratelimit(struct blkcg *blkcg)
{
	return blkcg->dirty_ratelimit;
}

static inline int blkcg_buffered_write_bps_enabled(struct blkcg *blkcg)
{
	if (!rue_io_enabled())
		return 0;

	if (!sysctl_buffered_write_bps_hierarchy)
		return blkcg_buffered_write_bps(blkcg);

	while (blkcg) {
		if (blkcg->buffered_write_bps)
			return blkcg_buffered_write_bps(blkcg);

		blkcg = blkcg_parent(blkcg);
	}

	return 0;
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

struct latency_bucket {
};

struct avg_latency_bucket {
};

struct throtl_data {
};

struct blkcg {
};

struct blkcg_gq {
};

struct blkg_iostat {
};

struct blkg_iostat_set {
};
#endif	/* CONFIG_BLK_CGROUP */

int blkcg_set_fc_appid(char *app_id, u64 cgrp_id, size_t app_id_len);
char *blkcg_get_fc_appid(struct bio *bio);

#endif	/* _BLK_CGROUP_H */
