// SPDX-License-Identifier: GPL-2.0
/*
 * buffered writeback throttling. loosely based on CoDel. We can't drop
 * packets for IO scheduling, so the logic is something like this:
 *
 * - Monitor latencies in a defined window of time.
 * - If the minimum latency in the above window exceeds some target, increment
 *   scaling step and scale down queue depth by a factor of 2x. The monitoring
 *   window is then shrunk to 100 / sqrt(scaling step + 1).
 * - For any window where we don't have solid data on what the latencies
 *   look like, retain status quo.
 * - If latencies look good, decrement scaling step.
 * - If we're only doing writes, allow the scaling step to go negative. This
 *   will temporarily boost write performance, snapping back to a stable
 *   scaling step of 0 if reads show up or the heavy writers finish. Unlike
 *   positive scaling steps where we shrink the monitoring window, a negative
 *   scaling step retains the default step==0 window size.
 *
 * Copyright (C) 2016 Jens Axboe
 *
 */
#include <linux/kernel.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/swap.h>
#include <linux/blk-mq.h>

#include "blk-stat.h"
#include "blk-wbt.h"
#include "blk-rq-qos.h"
#include "elevator.h"
#include "blk-cgroup.h"

#define CREATE_TRACE_POINTS
#include <trace/events/wbt.h>

#ifdef CONFIG_BLK_CGROUP
#include <linux/blk-cgroup.h>
#include <linux/rue.h>

/*per device per cgroup struct*/
struct wbt_grp {
	struct blkg_policy_data pd;
	struct wbt_throtl_info throtl_info;
};

static inline struct wbt_grp *pd_to_wg(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct wbt_grp, pd) : NULL;
}

static struct blkcg_policy blkcg_policy_wbt;

static inline struct wbt_grp *blkg_to_wg(struct blkcg_gq *blkg)
{
	return pd_to_wg(blkg_to_pd(blkg, &blkcg_policy_wbt));
}

static inline struct blkcg_gq *wg_to_blkg(struct wbt_grp *wg)
{
	return pd_to_blkg(&wg->pd);
}
#endif

enum wbt_flags {
	WBT_TRACKED		= 1,	/* write, tracked for throttling */
	WBT_READ		= 2,	/* read */
	WBT_KSWAPD		= 4,	/* write, from kswapd */
	WBT_DISCARD		= 8,	/* discard */

#ifndef CONFIG_BLK_CGROUP
	WBT_NR_BITS		= 4,	/* number of bits */
#else
	WBT_CLASS_TRACKED = 16, /* bio tracked wbt class */

	WBT_NR_BITS		= 5,	/* number of bits */
#endif
};

/*
 * If current state is WBT_STATE_ON/OFF_DEFAULT, it can be covered to any other
 * state, if current state is WBT_STATE_ON/OFF_MANUAL, it can only be covered
 * to WBT_STATE_OFF/ON_MANUAL.
 */
enum {
	WBT_STATE_ON_DEFAULT	= 1,	/* on by default */
	WBT_STATE_ON_MANUAL	= 2,	/* on manually by sysfs */
	WBT_STATE_OFF_DEFAULT	= 3,	/* off by default */
	WBT_STATE_OFF_MANUAL	= 4,	/* off manually by sysfs */
};

#ifdef CONFIG_BLK_CGROUP
#define WBT_CLASS_NR 3
#define WBT_CLASS_BITS 2
#define WBT_CLASS_OFFSET WBT_NR_BITS
#define WBT_CLASS_MASK (((1 << WBT_CLASS_BITS) - 1) << WBT_CLASS_OFFSET)
static inline enum wbt_flags bio_flags_to_wbt_class(enum wbt_flags wbt_acct)
{
	return (wbt_acct & WBT_CLASS_MASK) >> WBT_CLASS_OFFSET;
}

static inline void bio_flags_set_wbt_class(enum wbt_flags *wbt_acct, u16 wbt_class)
{
	enum wbt_flags tmp = 0;

	tmp = (*wbt_acct) & (~WBT_CLASS_MASK);
	tmp |= wbt_class << WBT_CLASS_OFFSET;
	*wbt_acct = tmp;
}
#endif

struct rq_wb {
	/*
	 * Settings that govern how we throttle
	 */
	unsigned int wb_background;		/* background writeback */
	unsigned int wb_normal;			/* normal writeback */

	short enable_state;			/* WBT_STATE_* */

	/*
	 * Number of consecutive periods where we don't have enough
	 * information to make a firm scale up/down decision.
	 */
	unsigned int unknown_cnt;

	u64 win_nsec;				/* default window size */
	u64 cur_win_nsec;			/* current window size */

	struct blk_stat_callback *cb;

	u64 sync_issue;
	void *sync_cookie;

	unsigned int wc;

	unsigned long last_issue;		/* last non-throttled issue */
	unsigned long last_comp;		/* last non-throttled comp */
	unsigned long min_lat_nsec;
	struct rq_qos rqos;
	struct rq_wait rq_wait[WBT_NUM_RWQ];
	struct rq_depth rq_depth;

#ifdef CONFIG_BLK_CGROUP
	struct timer_list wbt_class_timer; /*cooridnate all wbt classes*/
	struct wbt_throtl_info class_throtl_infos[WBT_CLASS_NR];
#endif
};

static inline struct rq_wb *RQWB(struct rq_qos *rqos)
{
	return container_of(rqos, struct rq_wb, rqos);
}

static inline void wbt_clear_state(struct request *rq)
{
	rq->wbt_flags = 0;
}

static inline enum wbt_flags wbt_flags(struct request *rq)
{
	return rq->wbt_flags;
}

static inline bool wbt_is_tracked(struct request *rq)
{
	return rq->wbt_flags & WBT_TRACKED;
}

static inline bool wbt_is_read(struct request *rq)
{
	return rq->wbt_flags & WBT_READ;
}

enum {
	/*
	 * Default setting, we'll scale up (to 75% of QD max) or down (min 1)
	 * from here depending on device stats
	 */
	RWB_DEF_DEPTH	= 16,

	/*
	 * 100msec window
	 */
	RWB_WINDOW_NSEC		= 100 * 1000 * 1000ULL,

	/*
	 * Disregard stats, if we don't meet this minimum
	 */
	RWB_MIN_WRITE_SAMPLES	= 3,

	/*
	 * If we have this number of consecutive windows with not enough
	 * information to scale up or down, scale up.
	 */
	RWB_UNKNOWN_BUMP	= 5,
};

static inline bool rwb_enabled(struct rq_wb *rwb)
{
	return rwb && rwb->enable_state != WBT_STATE_OFF_DEFAULT &&
		      rwb->enable_state != WBT_STATE_OFF_MANUAL;
}

static void wb_timestamp(struct rq_wb *rwb, unsigned long *var)
{
	if (rwb_enabled(rwb)) {
		const unsigned long cur = jiffies;

		if (cur != *var)
			*var = cur;
	}
}

/*
 * If a task was rate throttled in balance_dirty_pages() within the last
 * second or so, use that to indicate a higher cleaning rate.
 */
static bool wb_recent_wait(struct rq_wb *rwb)
{
	struct backing_dev_info *bdi = rwb->rqos.disk->bdi;

	return time_before(jiffies, bdi->last_bdp_sleep + HZ);
}

static inline struct rq_wait *get_rq_wait(struct rq_wb *rwb,
					  enum wbt_flags wb_acct)
{
	if (wb_acct & WBT_KSWAPD)
		return &rwb->rq_wait[WBT_RWQ_KSWAPD];
	else if (wb_acct & WBT_DISCARD)
		return &rwb->rq_wait[WBT_RWQ_DISCARD];

	return &rwb->rq_wait[WBT_RWQ_BG];
}

static void rwb_wake_all(struct rq_wb *rwb)
{
	int i;

	for (i = 0; i < WBT_NUM_RWQ; i++) {
		struct rq_wait *rqw = &rwb->rq_wait[i];

		if (wq_has_sleeper(&rqw->wait))
			wake_up_all(&rqw->wait);
	}
}

static void wbt_rqw_done(struct rq_wb *rwb, struct rq_wait *rqw,
			 enum wbt_flags wb_acct)
{
	int inflight, limit;

	inflight = atomic_dec_return(&rqw->inflight);

	/*
	 * For discards, our limit is always the background. For writes, if
	 * the device does write back caching, drop further down before we
	 * wake people up.
	 */
	if (wb_acct & WBT_DISCARD)
		limit = rwb->wb_background;
	else if (rwb->wc && !wb_recent_wait(rwb))
		limit = 0;
	else
		limit = rwb->wb_normal;

	/*
	 * Don't wake anyone up if we are above the normal limit.
	 */
	if (inflight && inflight >= limit)
		return;

	if (wq_has_sleeper(&rqw->wait)) {
		int diff = limit - inflight;

		if (!inflight || diff >= rwb->wb_background / 2)
			wake_up_all(&rqw->wait);
	}
}

static void __wbt_done(struct rq_qos *rqos, enum wbt_flags wb_acct)
{
	struct rq_wb *rwb = RQWB(rqos);
	struct rq_wait *rqw;

	if (!(wb_acct & WBT_TRACKED))
		return;

	rqw = get_rq_wait(rwb, wb_acct);
	wbt_rqw_done(rwb, rqw, wb_acct);
}

/*
 * Called on completion of a request. Note that it's also called when
 * a request is merged, when the request gets freed.
 */
static void wbt_done(struct rq_qos *rqos, struct request *rq)
{
	struct rq_wb *rwb = RQWB(rqos);

	if (!wbt_is_tracked(rq)) {
		if (rwb->sync_cookie == rq) {
			rwb->sync_issue = 0;
			rwb->sync_cookie = NULL;
		}

		if (wbt_is_read(rq))
			wb_timestamp(rwb, &rwb->last_comp);
	} else {
		WARN_ON_ONCE(rq == rwb->sync_cookie);
		__wbt_done(rqos, wbt_flags(rq));
	}
	wbt_clear_state(rq);
}

static inline bool stat_sample_valid(struct blk_rq_stat *stat)
{
	/*
	 * We need at least one read sample, and a minimum of
	 * RWB_MIN_WRITE_SAMPLES. We require some write samples to know
	 * that it's writes impacting us, and not just some sole read on
	 * a device that is in a lower power state.
	 */
	return (stat[READ].nr_samples >= 1 &&
		stat[WRITE].nr_samples >= RWB_MIN_WRITE_SAMPLES);
}

static u64 rwb_sync_issue_lat(struct rq_wb *rwb)
{
	u64 now, issue = READ_ONCE(rwb->sync_issue);

	if (!issue || !rwb->sync_cookie)
		return 0;

	now = ktime_to_ns(ktime_get());
	return now - issue;
}

static inline unsigned int wbt_inflight(struct rq_wb *rwb)
{
	unsigned int i, ret = 0;

	for (i = 0; i < WBT_NUM_RWQ; i++)
		ret += atomic_read(&rwb->rq_wait[i].inflight);

	return ret;
}

enum {
	LAT_OK = 1,
	LAT_UNKNOWN,
	LAT_UNKNOWN_WRITES,
	LAT_EXCEEDED,
};

static int latency_exceeded(struct rq_wb *rwb, struct blk_rq_stat *stat)
{
	struct backing_dev_info *bdi = rwb->rqos.disk->bdi;
	struct rq_depth *rqd = &rwb->rq_depth;
	u64 thislat;

	/*
	 * If our stored sync issue exceeds the window size, or it
	 * exceeds our min target AND we haven't logged any entries,
	 * flag the latency as exceeded. wbt works off completion latencies,
	 * but for a flooded device, a single sync IO can take a long time
	 * to complete after being issued. If this time exceeds our
	 * monitoring window AND we didn't see any other completions in that
	 * window, then count that sync IO as a violation of the latency.
	 */
	thislat = rwb_sync_issue_lat(rwb);
	if (thislat > rwb->cur_win_nsec ||
	    (thislat > rwb->min_lat_nsec && !stat[READ].nr_samples)) {
		trace_wbt_lat(bdi, thislat);
		return LAT_EXCEEDED;
	}

	/*
	 * No read/write mix, if stat isn't valid
	 */
	if (!stat_sample_valid(stat)) {
		/*
		 * If we had writes in this stat window and the window is
		 * current, we're only doing writes. If a task recently
		 * waited or still has writes in flights, consider us doing
		 * just writes as well.
		 */
		if (stat[WRITE].nr_samples || wb_recent_wait(rwb) ||
		    wbt_inflight(rwb))
			return LAT_UNKNOWN_WRITES;
		return LAT_UNKNOWN;
	}

	/*
	 * If the 'min' latency exceeds our target, step down.
	 */
	if (stat[READ].min > rwb->min_lat_nsec) {
		trace_wbt_lat(bdi, stat[READ].min);
		trace_wbt_stat(bdi, stat);
		return LAT_EXCEEDED;
	}

	if (rqd->scale_step)
		trace_wbt_stat(bdi, stat);

	return LAT_OK;
}

static void rwb_trace_step(struct rq_wb *rwb, const char *msg)
{
	struct backing_dev_info *bdi = rwb->rqos.disk->bdi;
	struct rq_depth *rqd = &rwb->rq_depth;

	trace_wbt_step(bdi, msg, rqd->scale_step, rwb->cur_win_nsec,
			rwb->wb_background, rwb->wb_normal, rqd->max_depth);
}

static void calc_wb_limits(struct rq_wb *rwb)
{
	if (rwb->min_lat_nsec == 0) {
		rwb->wb_normal = rwb->wb_background = 0;
	} else if (rwb->rq_depth.max_depth <= 2) {
		rwb->wb_normal = rwb->rq_depth.max_depth;
		rwb->wb_background = 1;
	} else {
		rwb->wb_normal = (rwb->rq_depth.max_depth + 1) / 2;
		rwb->wb_background = (rwb->rq_depth.max_depth + 3) / 4;
	}
}

static void scale_up(struct rq_wb *rwb)
{
	if (!rq_depth_scale_up(&rwb->rq_depth))
		return;
	calc_wb_limits(rwb);
	rwb->unknown_cnt = 0;
	rwb_wake_all(rwb);
	rwb_trace_step(rwb, tracepoint_string("scale up"));
}

static void scale_down(struct rq_wb *rwb, bool hard_throttle)
{
	if (!rq_depth_scale_down(&rwb->rq_depth, hard_throttle))
		return;
	calc_wb_limits(rwb);
	rwb->unknown_cnt = 0;
	rwb_trace_step(rwb, tracepoint_string("scale down"));
}

static void rwb_arm_timer(struct rq_wb *rwb)
{
	struct rq_depth *rqd = &rwb->rq_depth;

	if (rqd->scale_step > 0) {
		/*
		 * We should speed this up, using some variant of a fast
		 * integer inverse square root calculation. Since we only do
		 * this for every window expiration, it's not a huge deal,
		 * though.
		 */
		rwb->cur_win_nsec = div_u64(rwb->win_nsec << 4,
					int_sqrt((rqd->scale_step + 1) << 8));
	} else {
		/*
		 * For step < 0, we don't want to increase/decrease the
		 * window size.
		 */
		rwb->cur_win_nsec = rwb->win_nsec;
	}

	blk_stat_activate_nsecs(rwb->cb, rwb->cur_win_nsec);
}

static void wb_timer_fn(struct blk_stat_callback *cb)
{
	struct rq_wb *rwb = cb->data;
	struct rq_depth *rqd = &rwb->rq_depth;
	unsigned int inflight = wbt_inflight(rwb);
	int status;

	if (!rwb->rqos.disk)
		return;

	status = latency_exceeded(rwb, cb->stat);

	trace_wbt_timer(rwb->rqos.disk->bdi, status, rqd->scale_step, inflight);

	/*
	 * If we exceeded the latency target, step down. If we did not,
	 * step one level up. If we don't know enough to say either exceeded
	 * or ok, then don't do anything.
	 */
	switch (status) {
	case LAT_EXCEEDED:
		scale_down(rwb, true);
		break;
	case LAT_OK:
		scale_up(rwb);
		break;
	case LAT_UNKNOWN_WRITES:
		/*
		 * We started a the center step, but don't have a valid
		 * read/write sample, but we do have writes going on.
		 * Allow step to go negative, to increase write perf.
		 */
		scale_up(rwb);
		break;
	case LAT_UNKNOWN:
		if (++rwb->unknown_cnt < RWB_UNKNOWN_BUMP)
			break;
		/*
		 * We get here when previously scaled reduced depth, and we
		 * currently don't have a valid read/write sample. For that
		 * case, slowly return to center state (step == 0).
		 */
		if (rqd->scale_step > 0)
			scale_up(rwb);
		else if (rqd->scale_step < 0)
			scale_down(rwb, false);
		break;
	default:
		break;
	}

	/*
	 * Re-arm timer, if we have IO in flight
	 */
	if (rqd->scale_step || inflight)
		rwb_arm_timer(rwb);
}

static void wbt_update_limits(struct rq_wb *rwb)
{
	struct rq_depth *rqd = &rwb->rq_depth;

	rqd->scale_step = 0;
	rqd->scaled_max = false;

	rq_depth_calc_max_depth(rqd);
	calc_wb_limits(rwb);

	rwb_wake_all(rwb);
}

bool wbt_disabled(struct request_queue *q)
{
	struct rq_qos *rqos = wbt_rq_qos(q);

	return !rqos || !rwb_enabled(RQWB(rqos));
}

u64 wbt_get_min_lat(struct request_queue *q)
{
	struct rq_qos *rqos = wbt_rq_qos(q);
	if (!rqos)
		return 0;
	return RQWB(rqos)->min_lat_nsec;
}

void wbt_set_min_lat(struct request_queue *q, u64 val)
{
	struct rq_qos *rqos = wbt_rq_qos(q);
	if (!rqos)
		return;

	RQWB(rqos)->min_lat_nsec = val;
	if (val)
		RQWB(rqos)->enable_state = WBT_STATE_ON_MANUAL;
	else
		RQWB(rqos)->enable_state = WBT_STATE_OFF_MANUAL;

	wbt_update_limits(RQWB(rqos));
}


static bool close_io(struct rq_wb *rwb)
{
	const unsigned long now = jiffies;

	return time_before(now, rwb->last_issue + HZ / 10) ||
		time_before(now, rwb->last_comp + HZ / 10);
}

#define REQ_HIPRIO	(REQ_SYNC | REQ_META | REQ_PRIO)

static inline unsigned int get_limit(struct rq_wb *rwb, blk_opf_t opf)
{
	unsigned int limit;

	if ((opf & REQ_OP_MASK) == REQ_OP_DISCARD)
		return rwb->wb_background;

	/*
	 * At this point we know it's a buffered write. If this is
	 * kswapd trying to free memory, or REQ_SYNC is set, then
	 * it's WB_SYNC_ALL writeback, and we'll use the max limit for
	 * that. If the write is marked as a background write, then use
	 * the idle limit, or go to normal if we haven't had competing
	 * IO for a bit.
	 */
	if ((opf & REQ_HIPRIO) || wb_recent_wait(rwb) || current_is_kswapd())
		limit = rwb->rq_depth.max_depth;
	else if ((opf & REQ_BACKGROUND) || close_io(rwb)) {
		/*
		 * If less than 100ms since we completed unrelated IO,
		 * limit us to half the depth for background writeback.
		 */
		limit = rwb->wb_background;
	} else
		limit = rwb->wb_normal;

	return limit;
}

struct wbt_wait_data {
	struct rq_wb *rwb;
	enum wbt_flags wb_acct;
	blk_opf_t opf;
#ifdef CONFIG_BLK_CGROUP
	struct wbt_throtl_info *ti;
#endif
};

static bool wbt_inflight_cb(struct rq_wait *rqw, void *private_data)
{
	struct wbt_wait_data *data = private_data;
	return rq_wait_inc_below(rqw, get_limit(data->rwb, data->opf));
}

static void wbt_cleanup_cb(struct rq_wait *rqw, void *private_data)
{
	struct wbt_wait_data *data = private_data;
	wbt_rqw_done(data->rwb, rqw, data->wb_acct);
}

/*
 * Block if we will exceed our limit, or if we are currently waiting for
 * the timer to kick off queuing again.
 */
static void __wbt_wait(struct rq_wb *rwb, enum wbt_flags wb_acct,
		       blk_opf_t opf)
{
	struct rq_wait *rqw = get_rq_wait(rwb, wb_acct);
	struct wbt_wait_data data = {
		.rwb = rwb,
		.wb_acct = wb_acct,
		.opf = opf,
	};

	rq_qos_wait(rqw, &data, wbt_inflight_cb, wbt_cleanup_cb);
}

static inline bool wbt_should_throttle(struct bio *bio)
{
	switch (bio_op(bio)) {
	case REQ_OP_WRITE:
		/*
		 * Don't throttle WRITE_ODIRECT
		 */
		if ((bio->bi_opf & (REQ_SYNC | REQ_IDLE)) ==
		    (REQ_SYNC | REQ_IDLE))
			return false;
		fallthrough;
	case REQ_OP_DISCARD:
		return true;
	default:
		return false;
	}
}

#ifdef CONFIG_BLK_CGROUP
static inline struct wbt_grp *bio_to_wg(struct bio *bio)
{
	return blkg_to_wg(bio->bi_blkg);
}

static inline u16 bio_to_cgprio(struct bio *bio)
{
	struct blkcg_gq *blkg = bio->bi_blkg;
	struct blkcg *blkcg = blkg->blkcg;

	return cgroup_priority(&blkcg->css);
}

static u16 cgprio_to_wbt_class(u16 cgprio)
{
	static int cgprio_wbt_class_map[CGROUP_PRIORITY_MAX] = {
		[0] = 0,
		[1 ... CGROUP_PRIORITY_MAX - 2] = 1,
		[CGROUP_PRIORITY_MAX - 1] = 2,
	};
	if (cgprio < ARRAY_SIZE(cgprio_wbt_class_map))
		return cgprio_wbt_class_map[cgprio];
	return 0;
}

static inline u16 bio_to_wbt_class(struct bio *bio)
{
	return cgprio_to_wbt_class(bio_to_cgprio(bio));
}

static enum wbt_flags bio_to_wbt_class_flags(struct bio *bio)
{
	enum wbt_flags flags = 0;
	u16 wbt_class = bio_to_wbt_class(bio);

	if (bio_op(bio) == REQ_OP_READ) {
		flags = WBT_READ;
	} else if (wbt_should_throttle(bio)) {
		if (current_is_kswapd())
			flags |= WBT_KSWAPD;
		if (bio_op(bio) == REQ_OP_DISCARD)
			flags |= WBT_DISCARD;
		flags |= WBT_CLASS_TRACKED;
	}
	bio_flags_set_wbt_class(&flags, wbt_class);

	return flags;
}
#endif

static enum wbt_flags bio_to_wbt_flags(struct rq_wb *rwb, struct bio *bio)
{
	enum wbt_flags flags = 0;

	if (!rwb_enabled(rwb))
		return 0;

	if (bio_op(bio) == REQ_OP_READ) {
		flags = WBT_READ;
	} else if (wbt_should_throttle(bio)) {
		if (current_is_kswapd())
			flags |= WBT_KSWAPD;
		if (bio_op(bio) == REQ_OP_DISCARD)
			flags |= WBT_DISCARD;
		flags |= WBT_TRACKED;
	}
	return flags;
}

static void wbt_cleanup(struct rq_qos *rqos, struct bio *bio)
{
	struct rq_wb *rwb = RQWB(rqos);
	enum wbt_flags flags = bio_to_wbt_flags(rwb, bio);
	__wbt_done(rqos, flags);
}

#ifdef CONFIG_BLK_CGROUP
static int throtl_info_alloc(struct wbt_throtl_info *ti, gfp_t gfp_mask)
{
	ti->read_lat_stats = alloc_percpu_gfp(struct blk_rq_stat, gfp_mask);
	if (!ti->read_lat_stats)
		return -1;
	return 0;
}

static void throtl_info_free(struct wbt_throtl_info *ti)
{
	if (ti->read_lat_stats) {
		free_percpu(ti->read_lat_stats);
		ti->read_lat_stats = NULL;
	}
}

static void throtl_info_init(struct wbt_throtl_info *ti,
			     struct request_queue *q)
{
	struct blk_rq_stat *stat;
	int j;
	int cpu;

	ti->max_depth = min_t(unsigned int, RWB_DEF_DEPTH, blk_queue_depth(q));
	ti->min_depth = 1;
	ti->current_depth = ti->max_depth;
	ti->scale_up_percent = 50;
	ti->scale_down_percent = 50;

	for_each_possible_cpu(cpu) {
		stat = per_cpu_ptr(ti->read_lat_stats, cpu);
		blk_rq_stat_init(stat);
	}

	for (j = 0; j < WBT_NUM_RWQ; j++)
		rq_wait_init(&ti->rq_wait[j]);

	/*calc normal and background depth*/
	RUE_CALL_VOID(IO, throtl_info_calc_limit, ti);
}

static inline struct wbt_throtl_info *rwb_to_wbt_class_info(struct rq_wb *rwb,
							    u16 wbt_class)
{
	if (wbt_class < WBT_CLASS_NR)
		return &rwb->class_throtl_infos[wbt_class];

	pr_err("%s: Failed to find wbt_throtl_info with wbt_class %d\n",
			__func__, wbt_class);
	return NULL;
}

static int wbt_flags_to_counter_idx(enum wbt_flags flags)
{
	int i;

	if (flags & WBT_KSWAPD)
		i = WBT_RWQ_KSWAPD;
	else if (flags & WBT_DISCARD)
		i = WBT_RWQ_DISCARD;
	else
		i = WBT_RWQ_BG;

	return i;
}

static inline struct wbt_throtl_info *bio_to_wbt_class_info(struct rq_wb *rwb,
							    struct bio *bio)
{
	u16 wbt_class = cgprio_to_wbt_class(bio_to_cgprio(bio));

	return rwb_to_wbt_class_info(rwb, wbt_class);
}

static bool throtl_info_enabled(struct wbt_throtl_info *ti)
{
	return rue_io_enabled() && ti->wb_normal != 0;
}

static inline void throtl_info_wake_all(struct wbt_throtl_info *ti)
{
	int i;

	for (i = 0; i < WBT_NUM_RWQ; i++) {
		struct rq_wait *rqw = &ti->rq_wait[i];

		if (wq_has_sleeper(&rqw->wait))
			wake_up_all(&rqw->wait);
	}
}

static inline struct rq_wait *
throtl_info_get_rq_wait(struct wbt_throtl_info *ti, enum wbt_flags wb_acct)
{
	if (wb_acct & WBT_KSWAPD)
		return &ti->rq_wait[WBT_RWQ_KSWAPD];
	else if (wb_acct & WBT_DISCARD)
		return &ti->rq_wait[WBT_RWQ_DISCARD];

	return &ti->rq_wait[WBT_RWQ_BG];
}

static int throtl_info_inflight(struct wbt_throtl_info *ti)
{
	unsigned int i, ret = 0;

	for (i = 0; i < WBT_NUM_RWQ; i++)
		ret += atomic_read(&ti->rq_wait[i].inflight);

	return ret;
}

static inline unsigned int throtl_info_get_limit(struct wbt_throtl_info *ti,
						 unsigned long rw)
{
	unsigned int limit;

	if (!throtl_info_enabled(ti))
		return UINT_MAX;
	if ((rw & REQ_OP_MASK) == REQ_OP_DISCARD)
		return ti->wb_background;
	if (rw & REQ_HIPRIO || current_is_kswapd())
		limit = ti->max_depth;
	else if (rw & REQ_BACKGROUND)
		limit = ti->wb_background;
	else
		limit = ti->wb_normal;

	return limit;
}

static void throtl_info_rqw_done(struct rq_wb *rwb, struct wbt_throtl_info *ti,
				 struct rq_wait *rqw, enum wbt_flags wbt_acct)
{
	int inflight, limit;

	if (!(wbt_acct & WBT_CLASS_TRACKED))
		return;

	inflight = atomic_dec_return(&rqw->inflight);

	if (!throtl_info_enabled(ti)) {
		throtl_info_wake_all(ti);
		return;
	}

	if (wbt_acct & WBT_DISCARD)
		limit = ti->wb_background;
	else
		limit = ti->wb_normal;

	/*
	 * Don't wake anyone up if we are above the normal limit.
	 */
	if (inflight && inflight >= limit)
		return;

	if (wq_has_sleeper(&rqw->wait)) {
		int diff = limit - inflight;

		if (!inflight || diff >= ti->wb_background / 2)
			wake_up_nr(&rqw->wait, diff);
	}
}

static void wbt_class_timer_fn(struct timer_list *t)
{
	struct rq_wb *rwb = from_timer(rwb, t, wbt_class_timer);
	struct wbt_throtl_info *ti;
	u64 rd_expired_cnt;
	int highest_class = WBT_CLASS_NR;
	int i;

	for (i = 0; i < WBT_CLASS_NR; i++) {
		ti = rwb_to_wbt_class_info(rwb, i);
		rd_expired_cnt = atomic64_read(&ti->read_expired_cnt);
		atomic64_set(&ti->read_expired_cnt, 0);

		if (rd_expired_cnt && highest_class == WBT_CLASS_NR)
			highest_class = i;
	}

	if (highest_class == WBT_CLASS_NR)
		goto depth_scale_up;

	/*expired read did happen!!! throttle from the lowest class*/
	for (i = WBT_CLASS_NR - 1; i >= highest_class; i--) {
		struct wbt_throtl_info *throtl_ti =
			rwb_to_wbt_class_info(rwb, i);

		if (!throtl_info_enabled(throtl_ti))
			continue;

		/*skip if can't be scaled down*/
		if (!RUE_CALL_TYPE(IO, throtl_info_scale_down, bool, throtl_ti, true))
			continue;

		/*current_depth changed, recal wb_normal and wb_background */
		RUE_CALL_VOID(IO, throtl_info_calc_limit, throtl_ti);

		if (throtl_info_inflight(throtl_ti) >
		    throtl_ti->wb_background) {
			/*
			 * we did throttle some buffer write,
			 * go and observe the effect
			 */
			break;
		}
	}
	goto out;

depth_scale_up:
	/*amazing!!! everything goes fine, try to scale up queue depth*/
	for (i = 0; i < WBT_CLASS_NR; i++) {
		struct wbt_throtl_info *ti = rwb_to_wbt_class_info(rwb, i);

		if (ti->current_depth < ti->max_depth) {
			if (RUE_CALL_TYPE(IO, throtl_info_scale_up, bool, ti, false)) {
				RUE_CALL_VOID(IO, throtl_info_calc_limit, ti);
				throtl_info_wake_all(ti);
				goto out;
			}
		}
	}

out:
	for (i = 0; i < WBT_CLASS_NR; i++) {
		ti = rwb_to_wbt_class_info(rwb, i);
		if (throtl_info_inflight(ti) ||
		    ti->current_depth < ti->max_depth) {
			mod_timer(t, jiffies + nsecs_to_jiffies(rwb->win_nsec));
			break;
		}
	}
}

static void wbt_class_account_bio_begin(struct rq_wb *rwb, struct bio *bio)
{
	int i;
	enum wbt_flags flags;
	struct wbt_throtl_info *ti = bio_to_wbt_class_info(rwb, bio);

	flags = bio_to_wbt_class_flags(bio);
	if (bio_op(bio) == REQ_OP_READ)
		atomic64_inc(&ti->read_cnt);

	if (bio_op(bio) == REQ_OP_WRITE &&
	    (bio->bi_opf & (REQ_SYNC | REQ_IDLE)) == (REQ_SYNC | REQ_IDLE))
		atomic64_inc(&ti->direct_write_cnt);

	if (bio_op(bio) == REQ_OP_WRITE && (bio->bi_opf & REQ_SYNC) &&
	    !(bio->bi_opf & REQ_IDLE))
		atomic64_inc(&ti->wr_sync_cnt);

	if (flags & WBT_CLASS_TRACKED) {
		i = wbt_flags_to_counter_idx(flags);
		atomic64_inc(&ti->tracked_cnt[i]);
	}
}

static bool wbt_class_inflight_cb(struct rq_wait *rqw, void *private_data)
{
	struct wbt_wait_data *data = private_data;

	return rq_wait_inc_below(rqw,
				 throtl_info_get_limit(data->ti, data->opf));
}

static void wbt_class_cleanup_cb(struct rq_wait *rqw, void *private_data)
{
	struct wbt_wait_data *data = private_data;

	throtl_info_rqw_done(data->rwb, data->ti, rqw, data->wb_acct);
}

static void wbt_class_wait(struct rq_wb *rwb, struct bio *bio)
{
	u16 wbt_class = bio_to_wbt_class(bio);
	struct wbt_throtl_info *ti = rwb_to_wbt_class_info(rwb, wbt_class);
	enum wbt_flags flags = bio_to_wbt_class_flags(bio);
	struct rq_wait *rqw;
	struct wbt_wait_data data;

	if (!throtl_info_enabled(ti))
		return;

	wbt_class_account_bio_begin(rwb, bio);

	/* bi_wbt_acct initialized in bio_init() as 0 */
	bio->bi_wbt_acct = flags;

	if (!(flags & WBT_CLASS_TRACKED))
		return;

	rqw = throtl_info_get_rq_wait(ti, flags);

	data.rwb = rwb;
	data.wb_acct = flags;
	data.opf = bio->bi_opf;
	data.ti = ti;
	rq_qos_wait(rqw, &data, wbt_class_inflight_cb, wbt_class_cleanup_cb);
	if (!timer_pending(&rwb->wbt_class_timer))
		mod_timer(&rwb->wbt_class_timer,
			  jiffies + nsecs_to_jiffies(rwb->win_nsec));
}
#endif

/*
 * May sleep, if we have exceeded the writeback limits. Caller can pass
 * in an irq held spinlock, if it holds one when calling this function.
 * If we do sleep, we'll release and re-grab it.
 */
static void wbt_wait(struct rq_qos *rqos, struct bio *bio)
{
	struct rq_wb *rwb = RQWB(rqos);
	enum wbt_flags flags;

#ifdef CONFIG_BLK_CGROUP
	wbt_class_wait(rwb, bio);
#endif
	flags = bio_to_wbt_flags(rwb, bio);
	if (!(flags & WBT_TRACKED)) {
		if (flags & WBT_READ)
			wb_timestamp(rwb, &rwb->last_issue);
		return;
	}

	__wbt_wait(rwb, flags, bio->bi_opf);

	if (!blk_stat_is_active(rwb->cb))
		rwb_arm_timer(rwb);
}

static void wbt_track(struct rq_qos *rqos, struct request *rq, struct bio *bio)
{
	struct rq_wb *rwb = RQWB(rqos);
	rq->wbt_flags |= bio_to_wbt_flags(rwb, bio);
}

static void wbt_issue(struct rq_qos *rqos, struct request *rq)
{
	struct rq_wb *rwb = RQWB(rqos);

	if (!rwb_enabled(rwb))
		return;

	/*
	 * Track sync issue, in case it takes a long time to complete. Allows us
	 * to react quicker, if a sync IO takes a long time to complete. Note
	 * that this is just a hint. The request can go away when it completes,
	 * so it's important we never dereference it. We only use the address to
	 * compare with, which is why we store the sync_issue time locally.
	 */
	if (wbt_is_read(rq) && !rwb->sync_issue) {
		rwb->sync_cookie = rq;
		rwb->sync_issue = rq->io_start_time_ns;
	}
}

static void wbt_requeue(struct rq_qos *rqos, struct request *rq)
{
	struct rq_wb *rwb = RQWB(rqos);
	if (!rwb_enabled(rwb))
		return;
	if (rq == rwb->sync_cookie) {
		rwb->sync_issue = 0;
		rwb->sync_cookie = NULL;
	}
}

void wbt_set_write_cache(struct request_queue *q, bool write_cache_on)
{
	struct rq_qos *rqos = wbt_rq_qos(q);
	if (rqos)
		RQWB(rqos)->wc = write_cache_on;
}

#ifdef CONFIG_BLK_CGROUP
static u64 bio_latency_nsec(struct bio *bio)
{
	u64 start = bio_issue_time(&bio->bi_issue);
	u64 now = ktime_get_ns();
	u64 latency_ns;

	now = __bio_issue_time(now);
	if (now <= start)
		return 0;
	latency_ns = now - start;
	return latency_ns;
}

static void wbt_class_account_bio_end(struct rq_wb *rwb, struct bio *bio)
{
	int i;
	enum wbt_flags flags = bio->bi_wbt_acct;
	u16 wbt_class = bio_flags_to_wbt_class(flags);
	struct wbt_throtl_info *ti = rwb_to_wbt_class_info(rwb, wbt_class);
	struct wbt_grp *wg = bio_to_wg(bio);
	u64 latency_ns;
	struct blk_rq_stat *stat;

	if (flags & WBT_CLASS_TRACKED) {
		i = wbt_flags_to_counter_idx(flags);
		atomic64_inc(&ti->finished_cnt[i]);
	}

	if (throtl_info_enabled(ti) && (flags & WBT_READ)) {
		latency_ns = bio_latency_nsec(bio);
		ti->recent_rd_latency_us = (latency_ns / 1000);
		if (latency_ns > ti->min_lat_nsec)
			atomic64_inc(&ti->read_expired_cnt);
		ti->last_comp = jiffies;

		stat = get_cpu_ptr(ti->read_lat_stats);
		blk_rq_stat_add(stat, latency_ns / 1000);
		put_cpu_ptr(stat);

		stat = get_cpu_ptr(wg->throtl_info.read_lat_stats);
		blk_rq_stat_add(stat, latency_ns / 1000);
		put_cpu_ptr(stat);
	}
}

static void wbt_class_done_bio(struct rq_wb *rwb, struct bio *bio)
{
	u16 wbt_class = bio_flags_to_wbt_class(bio->bi_wbt_acct);
	struct wbt_throtl_info *ti = rwb_to_wbt_class_info(rwb, wbt_class);
	enum wbt_flags wbt_acct = bio->bi_wbt_acct;
	struct rq_wait *rqw = throtl_info_get_rq_wait(ti, wbt_acct);

	throtl_info_rqw_done(rwb, ti, rqw, wbt_acct);
}

static void wbt_done_bio(struct rq_qos *rqos, struct bio *bio)
{
	wbt_class_account_bio_end(RQWB(rqos), bio);

	if (bio->bi_wbt_acct & WBT_CLASS_TRACKED)
		wbt_class_done_bio(RQWB(rqos), bio);

	bio->bi_wbt_acct = 0;
}

static void wbt_merge(struct rq_qos *rqos, struct request *rq, struct bio *bio)
{
	struct wbt_throtl_info *ti = bio_to_wbt_class_info(RQWB(rqos), bio);

	if (!throtl_info_enabled(ti))
		return;

	if (wbt_should_throttle(bio))
		atomic64_inc(&ti->escaped_merge_cnt);
}
#endif

/*
 * Enable wbt if defaults are configured that way
 */
void wbt_enable_default(struct gendisk *disk)
{
	struct request_queue *q = disk->queue;
	struct rq_qos *rqos;
	bool enable = IS_ENABLED(CONFIG_BLK_WBT_MQ);

	if (q->elevator &&
	    test_bit(ELEVATOR_FLAG_DISABLE_WBT, &q->elevator->flags))
		enable = false;

	/* Throttling already enabled? */
	rqos = wbt_rq_qos(q);
	if (rqos) {
		if (enable && RQWB(rqos)->enable_state == WBT_STATE_OFF_DEFAULT)
			RQWB(rqos)->enable_state = WBT_STATE_ON_DEFAULT;
		return;
	}

	/* Queue not registered? Maybe shutting down... */
	if (!blk_queue_registered(q))
		return;

	if (queue_is_mq(q) && enable)
		wbt_init(disk);
}
EXPORT_SYMBOL_GPL(wbt_enable_default);

u64 wbt_default_latency_nsec(struct request_queue *q)
{
	/*
	 * We default to 2msec for non-rotational storage, and 75msec
	 * for rotational storage.
	 */
	if (blk_queue_nonrot(q))
		return 2000000ULL;
	else
		return 75000000ULL;
}

static int wbt_data_dir(const struct request *rq)
{
	const enum req_op op = req_op(rq);

	if (op == REQ_OP_READ)
		return READ;
	else if (op_is_write(op))
		return WRITE;

	/* don't account */
	return -1;
}

static void wbt_queue_depth_changed(struct rq_qos *rqos)
{
	RQWB(rqos)->rq_depth.queue_depth = blk_queue_depth(rqos->disk->queue);
	wbt_update_limits(RQWB(rqos));
}

static void wbt_exit(struct rq_qos *rqos)
{
	struct rq_wb *rwb = RQWB(rqos);
#ifdef CONFIG_BLK_CGROUP
	struct wbt_throtl_info *ti;
	int i;
#endif

	blk_stat_remove_callback(rqos->disk->queue, rwb->cb);
	blk_stat_free_callback(rwb->cb);
#ifdef CONFIG_BLK_CGROUP
	del_timer_sync(&rwb->wbt_class_timer);
	for (i = 0; i < WBT_CLASS_NR; i++) {
		ti = rwb_to_wbt_class_info(rwb, i);
		throtl_info_free(ti);
	}
#endif
	kfree(rwb);
}

/*
 * Disable wbt, if enabled by default.
 */
void wbt_disable_default(struct gendisk *disk)
{
	struct rq_qos *rqos = wbt_rq_qos(disk->queue);
	struct rq_wb *rwb;
	if (!rqos)
		return;
	rwb = RQWB(rqos);
	if (rwb->enable_state == WBT_STATE_ON_DEFAULT) {
		blk_stat_deactivate(rwb->cb);
		rwb->enable_state = WBT_STATE_OFF_DEFAULT;
	}
}
EXPORT_SYMBOL_GPL(wbt_disable_default);

#ifdef CONFIG_BLK_DEBUG_FS
static int wbt_curr_win_nsec_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);

	seq_printf(m, "%llu\n", rwb->cur_win_nsec);
	return 0;
}

static int wbt_enabled_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);

	seq_printf(m, "%d\n", rwb->enable_state);
	return 0;
}

#ifdef CONFIG_BLK_CGROUP
static int wbt_rue_cls_enabled_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);

	seq_printf(m, "%d\n", rue_io_enabled() && rwb->enable_state);
	return 0;
}
#endif

static int wbt_id_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;

	seq_printf(m, "%u\n", rqos->id);
	return 0;
}

static int wbt_inflight_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);
	int i;

	for (i = 0; i < WBT_NUM_RWQ; i++)
		seq_printf(m, "%d: inflight %d\n", i,
			   atomic_read(&rwb->rq_wait[i].inflight));
	return 0;
}

static int wbt_min_lat_nsec_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);

	seq_printf(m, "%lu\n", rwb->min_lat_nsec);
	return 0;
}

static int wbt_unknown_cnt_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);

	seq_printf(m, "%u\n", rwb->unknown_cnt);
	return 0;
}

static int wbt_normal_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);

	seq_printf(m, "%u\n", rwb->wb_normal);
	return 0;
}

static int wbt_background_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);

	seq_printf(m, "%u\n", rwb->wb_background);
	return 0;
}

#ifdef CONFIG_BLK_CGROUP
static int wbt_class_rd_expired_cnt_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);
	u64 lat_cnt;
	int i;

	seq_puts(m, "class\tcnt\n");
	for (i = 0; i < WBT_CLASS_NR; i++) {
		lat_cnt = atomic64_read(
			&rwb->class_throtl_infos[i].read_expired_cnt);
		seq_printf(m, "%d\t%llu\n", i, lat_cnt);
	}
	return 0;
}

static int wbt_class_lat_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);
	struct blk_rq_stat stat;
	int cpu;
	int i;
	struct wbt_throtl_info *ti;

	for (i = 0; i < WBT_CLASS_NR; i++) {
		ti = rwb_to_wbt_class_info(rwb, i);

		blk_rq_stat_init(&stat);
		for_each_online_cpu(cpu) {
			struct blk_rq_stat *s;

			s = per_cpu_ptr(ti->read_lat_stats, cpu);
			blk_rq_stat_sum(&stat, s);
			blk_rq_stat_init(s);
		}

		seq_printf(m, "%d mean_lat_usec=%llu total_io=%u\n", i,
			   stat.mean, stat.nr_samples);
	}

	return 0;
}

static int wbt_debug_show(void *data, struct seq_file *m)
{
	struct rq_qos *rqos = data;
	struct rq_wb *rwb = RQWB(rqos);
	int i;
	struct wbt_throtl_info *ti;

	for (i = 0; i < WBT_CLASS_NR; i++) {
		ti = rwb_to_wbt_class_info(rwb, i);
		seq_printf(m, "%d inflight=%d ", i, throtl_info_inflight(ti));
		seq_printf(
			m,
			"track_bg=%llu track_kswp=%llu track_disc=%llu "
			"finished_bg=%llu finished_kswp=%llu finished_disc=%llu "
			"untrack_read=%llu untrack_direct_wr=%llu escape_merg=%llu "
			"sync_write=%llu rd_expired=%llu ",
			atomic64_read(&ti->tracked_cnt[WBT_RWQ_BG]),
			atomic64_read(&ti->tracked_cnt[WBT_RWQ_KSWAPD]),
			atomic64_read(&ti->tracked_cnt[WBT_RWQ_DISCARD]),
			atomic64_read(&ti->finished_cnt[WBT_RWQ_BG]),
			atomic64_read(&ti->finished_cnt[WBT_RWQ_KSWAPD]),
			atomic64_read(&ti->finished_cnt[WBT_RWQ_DISCARD]),
			atomic64_read(&ti->read_cnt),
			atomic64_read(&ti->direct_write_cnt),
			atomic64_read(&ti->escaped_merge_cnt),
			atomic64_read(&ti->wr_sync_cnt),
			atomic64_read(&ti->read_expired_cnt));
		seq_printf(
			m,
			"rd_issue=%lu rd_compl=%lu rd_recent_latency_us=%llu\n",
			ti->last_issue, ti->last_comp,
			ti->recent_rd_latency_us);
	}

	return 0;
}
#endif

static const struct blk_mq_debugfs_attr wbt_debugfs_attrs[] = {
	{ "curr_win_nsec", 0400, wbt_curr_win_nsec_show },
	{ "enabled", 0400, wbt_enabled_show },
	{ "id", 0400, wbt_id_show },
	{ "inflight", 0400, wbt_inflight_show },
	{ "min_lat_nsec", 0400, wbt_min_lat_nsec_show },
	{ "unknown_cnt", 0400, wbt_unknown_cnt_show },
	{ "wb_normal", 0400, wbt_normal_show },
	{ "wb_background", 0400, wbt_background_show },
#ifdef CONFIG_BLK_CGROUP
	{ "cls_enabled", 0400, wbt_rue_cls_enabled_show },
	{ "wbt_class_rd_expired_cnt", 0400, wbt_class_rd_expired_cnt_show },
	{ "wbt_class_lat", 0400, wbt_class_lat_show },
	{ "wbt_debug", 0400, wbt_debug_show },
#endif
	{},
};
#endif

static const struct rq_qos_ops wbt_rqos_ops = {
	.throttle = wbt_wait,
	.issue = wbt_issue,
	.track = wbt_track,
	.requeue = wbt_requeue,
	.done = wbt_done,
#ifdef CONFIG_BLK_CGROUP
	.merge = wbt_merge,
	.done_bio = wbt_done_bio,
#endif
	.cleanup = wbt_cleanup,
	.queue_depth_changed = wbt_queue_depth_changed,
	.exit = wbt_exit,
#ifdef CONFIG_BLK_DEBUG_FS
	.debugfs_attrs = wbt_debugfs_attrs,
#endif
};

int wbt_init(struct gendisk *disk)
{
	struct request_queue *q = disk->queue;
	struct rq_wb *rwb;
	int i;
	int ret;

	rwb = kzalloc(sizeof(*rwb), GFP_KERNEL);
	if (!rwb)
		return -ENOMEM;

	rwb->cb = blk_stat_alloc_callback(wb_timer_fn, wbt_data_dir, 2, rwb);
	if (!rwb->cb) {
		kfree(rwb);
		return -ENOMEM;
	}

	for (i = 0; i < WBT_NUM_RWQ; i++)
		rq_wait_init(&rwb->rq_wait[i]);

	rwb->last_comp = rwb->last_issue = jiffies;
	rwb->win_nsec = RWB_WINDOW_NSEC;
	rwb->enable_state = WBT_STATE_ON_DEFAULT;
	rwb->wc = test_bit(QUEUE_FLAG_WC, &q->queue_flags);
	rwb->rq_depth.default_depth = RWB_DEF_DEPTH;
	rwb->min_lat_nsec = wbt_default_latency_nsec(q);
	rwb->rq_depth.queue_depth = blk_queue_depth(q);
	wbt_update_limits(rwb);

	/*
	 * Assign rwb and add the stats callback.
	 */
	mutex_lock(&q->rq_qos_mutex);
	ret = rq_qos_add(&rwb->rqos, disk, RQ_QOS_WBT, &wbt_rqos_ops);
	mutex_unlock(&q->rq_qos_mutex);
	if (ret)
		goto err_free;

	blk_stat_add_callback(q, rwb->cb);

#ifdef CONFIG_BLK_CGROUP
	for (i = 0; i < WBT_CLASS_NR; i++) {
		struct wbt_throtl_info *ti;

		ti = rwb_to_wbt_class_info(rwb, i);

		if (throtl_info_alloc(ti, GFP_KERNEL)) {
			ret = -ENOMEM;
			goto fail_no_mem;
		}
		throtl_info_init(ti, q);
	}
	timer_setup(&rwb->wbt_class_timer, wbt_class_timer_fn, 0);
#endif
	return 0;

#ifdef CONFIG_BLK_CGROUP
fail_no_mem:
	for (i = 0; i < WBT_CLASS_NR; i++) {
		struct wbt_throtl_info *ti;

		ti = rwb_to_wbt_class_info(rwb, i);
		throtl_info_free(ti);
	}
#endif
err_free:
	blk_stat_free_callback(rwb->cb);
	kfree(rwb);
	return ret;
}

#ifdef CONFIG_BLK_CGROUP
int blk_wbt_init(struct gendisk *disk)
{
	/*create wbt policy structure for each blkg*/
	return blkcg_activate_policy(disk, &blkcg_policy_wbt);
}

static struct blkg_policy_data *wbt_pd_alloc(struct gendisk *disk,
		struct blkcg *blkcg, gfp_t gfp)
{
	struct wbt_grp *wg;

	wg = kzalloc_node(sizeof(*wg), gfp, disk->node_id);
	if (!wg)
		return NULL;

	if (throtl_info_alloc(&wg->throtl_info, gfp)) {
		kfree(wg);
		return NULL;
	}

	return wg ? &wg->pd : NULL;
}

static void wbt_pd_init(struct blkg_policy_data *pd)
{
	struct request_queue *q = pd->blkg->q;
	struct wbt_grp *wg;
	struct wbt_throtl_info *ti;

	wg = pd_to_wg(pd);
	ti = &wg->throtl_info;

	throtl_info_init(ti, q);
}

/*sysfs interface*/
ssize_t queue_wbt_class_lat_show(struct request_queue *q, char *page)
{
	struct wbt_throtl_info *ti;
	struct rq_qos *rqos = wbt_rq_qos(q);
	struct rq_wb *rwb;
	int i;
	int p = 0;

	if (!rqos)
		return 0;

	rwb = RQWB(rqos);

	for (i = 0; i < WBT_CLASS_NR; i++) {
		ti = rwb_to_wbt_class_info(rwb, i);
		p += snprintf(page + p, PAGE_SIZE - p, "%d %llu(usec)\n", i,
			      ti->min_lat_nsec / 1000);
	}
	return p;
}

ssize_t queue_wbt_class_lat_store(struct request_queue *q, const char *page,
				  size_t count)
{
	u16 wbt_class;
	u64 latency_us;
	struct wbt_throtl_info *ti;
	struct rq_qos *rqos = wbt_rq_qos(q);
	struct rq_wb *rwb;

	if (!rue_io_enabled())
		return -EPERM;

	if (!rqos)
		return 0;

	rwb = RQWB(rqos);

	if (sscanf(page, "%hu %llu", &wbt_class, &latency_us) != 2)
		return -EINVAL;

	ti = rwb_to_wbt_class_info(rwb, wbt_class);
	if (ti == NULL)
		return -EINVAL;

	blk_mq_freeze_queue(q);
	blk_mq_quiesce_queue(q);
	ti->min_lat_nsec = latency_us * 1000;
	RUE_CALL_VOID(IO, throtl_info_calc_limit, ti);

	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q);

	return count;
}

ssize_t queue_wbt_class_conf_show(struct request_queue *q, char *page)
{
	struct wbt_throtl_info *ti;
	struct rq_qos *rqos = wbt_rq_qos(q);
	struct rq_wb *rwb;
	int i;
	int p = 0;

	if (!rqos)
		return 0;

	rwb = RQWB(rqos);

	for (i = 0; i < WBT_CLASS_NR; i++) {
		ti = rwb_to_wbt_class_info(rwb, i);
		p += snprintf(page + p, PAGE_SIZE,
			"%d max_depth=%u min_depth=%u cur_depth=%u normal=%u bg=%u\n",
			i, ti->max_depth, ti->min_depth, ti->current_depth,
			ti->wb_normal, ti->wb_background);
	}
	return p;
}

ssize_t queue_wbt_class_conf_store(struct request_queue *q, const char *page,
				   size_t count)
{
	struct wbt_throtl_info *ti;
	struct rq_qos *rqos = wbt_rq_qos(q);
	struct rq_wb *rwb;
	u16 wbt_class;
	u64 val;
	char tok[64];
	int ret, rc;
	char *p;

	if (!rue_io_enabled())
		return -EPERM;

	if (!rqos)
		return 0;

	rwb = RQWB(rqos);

	if (sscanf(page, "%hu %s", &wbt_class, tok) != 2)
		return -EINVAL;
	if (tok[0] == '\0')
		return -EINVAL;
	p = tok;
	strsep(&p, "=");
	rc = kstrtou64(p, 0, &val);

	if (!p || rc)
		return -EINVAL;

	ti = rwb_to_wbt_class_info(rwb, wbt_class);

	blk_mq_freeze_queue(q);
	blk_mq_quiesce_queue(q);

	ret = -EINVAL;
	if (!strcmp(tok, "max_depth")) {
		if (val == 0 || val < ti->min_depth)
			goto out_finish;
		ti->max_depth = min_t(u64, val, 1024);
		ti->current_depth = ti->max_depth;
	} else if (!strcmp(tok, "min_depth")) {
		if (val > ti->max_depth || val == 0)
			goto out_finish;
		ti->min_depth = (unsigned int)val;
	} else if (!strcmp(tok, "scale_up_pct")) {
		if (val > 100 || val == 0)
			goto out_finish;
		ti->scale_up_percent = val;
	} else if (!strcmp(tok, "scale_down_pct")) {
		if (val > 100 || val == 0)
			goto out_finish;
		ti->scale_down_percent = val;
	} else
		goto out_finish;
	ret = 0;
	ti->current_depth = ti->max_depth;
	RUE_CALL_VOID(IO, throtl_info_calc_limit, ti);
	throtl_info_wake_all(ti);

out_finish:
	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q);

	return ret ?: count;
}

static void wbt_pd_free(struct blkg_policy_data *pd)
{
	struct wbt_grp *wg = pd_to_wg(pd);

	throtl_info_free(&wg->throtl_info);
	kfree(wg);
}

static inline u16 wg_to_cgprio(struct wbt_grp *wg)
{
	struct blkcg_gq *blkg;

	blkg = wg_to_blkg(wg);

	return cgroup_priority(&blkg->blkcg->css);
}

static inline u16 wg_to_wbt_class(struct wbt_grp *wg)
{
	u16 cgprio;

	cgprio = wg_to_cgprio(wg);

	return cgprio_to_wbt_class(cgprio);
}

static u64 wg_prfill_stat(struct seq_file *sf, struct blkg_policy_data *pd,
			  int off)
{
	struct wbt_grp *wg = pd_to_wg(pd);
	const char *dname = blkg_dev_name(pd->blkg);
	struct blk_rq_stat stat;
	int cpu;

	blk_rq_stat_init(&stat);
	for_each_online_cpu(cpu) {
		struct blk_rq_stat *s;

		s = per_cpu_ptr(wg->throtl_info.read_lat_stats, cpu);
		blk_rq_stat_sum(&stat, s);
		blk_rq_stat_init(s);
	}

	seq_printf(sf, "%s wbt_class=%d read_mean_lat_usec=%llu\n", dname,
		   wg_to_wbt_class(wg), stat.mean);

	return 0;
}
static int wg_stat_show(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)), wg_prfill_stat,
			  &blkcg_policy_wbt, 0, false);
	return 0;
}

static struct cftype wbt_grp_files[] = {

	{
		.name = "wbt.stat",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = wg_stat_show,
	},
	{}
};

static struct blkcg_policy blkcg_policy_wbt = {
	.pd_alloc_fn = wbt_pd_alloc,
	.pd_init_fn = wbt_pd_init,
	.pd_free_fn = wbt_pd_free,
	.dfl_cftypes = wbt_grp_files,
};

static int __init wbt_policy_init(void)
{
	/*create for wbt structure for each blkcg */
	return blkcg_policy_register(&blkcg_policy_wbt);
}

static void __exit wbt_policy_exit(void)
{
	return blkcg_policy_unregister(&blkcg_policy_wbt);
}

module_init(wbt_policy_init);
module_exit(wbt_policy_exit);
#endif
