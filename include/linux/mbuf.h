/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 mengensun <mengensun@tencent.com>
 */

#ifndef _CGROUP_MBUF_H
#define _CGROUP_MBUF_H

#ifdef CONFIG_RQM
struct mbuf_struct {
	u32 mbuf_len;
	u32 mbuf_max_slots;
	u32 mbuf_frees;
	u32 mbuf_next_id;
	u32 mbuf_size_per_cg;
	spinlock_t mbuf_lock;
	char *mbuf;
	unsigned long *mbuf_bitmap;
};

struct mbuf_ring_desc {
	/* timestamp of this message */
	u64 ts_ns;
	/* message total len, ring_item + ->len = next_item */
	u16 len;
	/* text len text_len + sizeof(ring) = len */
	u16 text_len;
};

struct mbuf_ring {
	u32 base_idx;
	u32 first_idx;
	u64 first_seq;
	u32 next_idx;
	u64 next_seq;
	u32 end_idx;
};

struct mbuf_user_desc {
	u64 user_seq;
	u32 user_idx;
	char buf[1024];
};

/* each cgroup has a mbuf_slot struct */
struct mbuf_slot {
	u32 idx;
	/* snapshot/write op must hold this lock */
	seqlock_t slot_lock;
	/* rate limit */
	struct ratelimit_state ratelimit;
	void *owner;
	const struct mbuf_operations *ops;
	struct mbuf_ring *mring;
};

struct mbuf_operations {
	/* read message */
	ssize_t (*read)(struct mbuf_slot *_slot, struct mbuf_user_desc *udest);

	/* get next available idx */
	u32 (*next)(struct mbuf_ring *mring, u32 idx);

	/* write message */
	ssize_t (*write)(struct mbuf_slot *mbuf, const char *fmt, va_list args);
} ____cacheline_aligned;


void __init mbuf_bmap_init(void);
void __init setup_mbuf(void);

struct mbuf_slot *mbuf_slot_alloc(struct cgroup *cg);
struct mbuf_slot *mbuf_slot_alloc_v2(void *owner, struct mbuf_operations *ops);
void mbuf_free(struct cgroup *cg);

ssize_t mbuf_print(struct cgroup *cgrp, const char *fmt, ...);
void snapshot_mbuf(struct mbuf_slot *, struct mbuf_slot*, seqlock_t *);
u32 get_mbuf_slot_len(void);
void mbuf_free_slot(struct mbuf_slot *slot);
void mbuf_reset(struct mbuf_slot *mbuf);
#endif
#endif
