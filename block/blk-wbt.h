/* SPDX-License-Identifier: GPL-2.0 */
#ifndef WB_THROTTLE_H
#define WB_THROTTLE_H

#ifdef CONFIG_BLK_WBT

int wbt_init(struct gendisk *disk);
void wbt_disable_default(struct gendisk *disk);
void wbt_enable_default(struct gendisk *disk);

u64 wbt_get_min_lat(struct request_queue *q);
void wbt_set_min_lat(struct request_queue *q, u64 val);
bool wbt_disabled(struct request_queue *);

void wbt_set_write_cache(struct request_queue *, bool);

u64 wbt_default_latency_nsec(struct request_queue *);

#ifdef CONFIG_BLK_CGROUP
ssize_t queue_wbt_class_lat_show(struct request_queue *q, char *page);
ssize_t queue_wbt_class_lat_store(struct request_queue *q, const char *page, size_t count);
ssize_t queue_wbt_class_conf_show(struct request_queue *q, char *page);
ssize_t queue_wbt_class_conf_store(struct request_queue *q, const char *page, size_t count);

int blk_wbt_init(struct gendisk *disk);
#endif
#else

static inline void wbt_disable_default(struct gendisk *disk)
{
}
static inline void wbt_enable_default(struct gendisk *disk)
{
}
static inline void wbt_set_write_cache(struct request_queue *q, bool wc)
{
}

static inline ssize_t queue_wbt_class_lat_show(struct request_queue *q,
		char *page)
{
	return 0;
}

static inline ssize_t queue_wbt_class_lat_store(struct request_queue *q,
		const char *page, size_t count)
{
	return 0;
}

static inline ssize_t queue_wbt_class_conf_show(struct request_queue *q,
		char *page)
{
	return 0;
}

static inline ssize_t queue_wbt_class_conf_store(struct request_queue *q,
		const char *page, size_t count)
{
	return 0;
}

static inline int blk_wbt_init(struct gendisk *disk)
{
	return 0;
}
#endif /* CONFIG_BLK_WBT */

#endif
