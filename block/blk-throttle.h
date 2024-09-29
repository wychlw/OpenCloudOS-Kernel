#ifndef BLK_THROTTLE_H
#define BLK_THROTTLE_H

#include "blk-cgroup-rwstat.h"

enum tg_state_flags {
	THROTL_TG_PENDING	= 1 << 0,	/* on parent's pending tree */
	THROTL_TG_WAS_EMPTY	= 1 << 1,	/* bio_lists[] became non-empty */
	THROTL_TG_CANCELING	= 1 << 2,	/* starts to cancel bio */
};

extern struct blkcg_policy blkcg_policy_throtl;

static inline struct throtl_grp *pd_to_tg(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct throtl_grp, pd) : NULL;
}

static inline struct throtl_grp *blkg_to_tg(struct blkcg_gq *blkg)
{
	return pd_to_tg(blkg_to_pd(blkg, &blkcg_policy_throtl));
}

/*
 * Internal throttling interface
 */
#ifndef CONFIG_BLK_DEV_THROTTLING
static inline int blk_throtl_init(struct gendisk *disk) { return 0; }
static inline void blk_throtl_exit(struct gendisk *disk) { }
static inline void blk_throtl_register(struct gendisk *disk) { }
static inline bool blk_throtl_bio(struct bio *bio) { return false; }
static inline void blk_throtl_cancel_bios(struct gendisk *disk) { }
#else /* CONFIG_BLK_DEV_THROTTLING */
int blk_throtl_init(struct gendisk *disk);
void blk_throtl_exit(struct gendisk *disk);
void blk_throtl_register(struct gendisk *disk);
bool __blk_throtl_bio(struct bio *bio);
void blk_throtl_cancel_bios(struct gendisk *disk);

static inline bool blk_should_throtl(struct bio *bio)
{
	struct throtl_grp *tg = blkg_to_tg(bio->bi_blkg);
	int rw = bio_data_dir(bio);

	if (!cgroup_subsys_on_dfl(io_cgrp_subsys)) {
		if (!bio_flagged(bio, BIO_CGROUP_ACCT)) {
			bio_set_flag(bio, BIO_CGROUP_ACCT);
			blkg_rwstat_add(&tg->stat_bytes, bio->bi_opf,
					bio->bi_iter.bi_size);
		}
		blkg_rwstat_add(&tg->stat_ios, bio->bi_opf, 1);
	}

	/* iops limit is always counted */
	if (tg->has_rules_iops[rw])
		return true;

	if (tg->has_rules_bps[rw] && !bio_flagged(bio, BIO_BPS_THROTTLED))
		return true;

	return false;
}

static inline bool blk_throtl_bio(struct bio *bio)
{

	if (!blk_should_throtl(bio))
		return false;

	return __blk_throtl_bio(bio);
}
#endif /* CONFIG_BLK_DEV_THROTTLING */

#endif
