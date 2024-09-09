// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Quality Monitor Buffer
 *  Aim to provide backup buffer for RQM to record critical message.
 *  Could be used to catch critical context when abnormal jitters occur.
 *
 *	Author: mengensun <mengensun@tencent.com>
 *	Copyright (C) 2024 Tencent, Inc
 */

#include <linux/kernel.h>
#include <linux/cgroup.h>
#include <linux/memblock.h>
#include <linux/cpu.h>
#include <linux/uaccess.h>
#include <linux/mbuf.h>
#include <linux/slab.h>
#include <linux/sched/clock.h>
#include <linux/ratelimit.h>

/* Define max mbuf len is 8M, and min is 2M */
#define MBUF_LEN_MAX (1 << 23)
#define MBUF_LEN_MIN (1 << 21)
/*
 * from now, every netns has a mbuf, because
 * change the mbuf slot size is dangerous, so
 * double the total buffer size to double
 * total mbuf slot num (see MBUF_SLOTS_DEF)
 */
#define MBUF_LEN_DEF (1 << 22)

#define MBUF_MSG_LEN_MAX 1024

/* Monitor buffer support max 1024 items */
#define MBUF_SLOTS_MAX	1024
#define MBUF_SLOTS_MIN	256
#define MBUF_SLOTS_DEF  1024

/* Global mbuf metadata struct */
static struct mbuf_struct g_mbuf = {
	.mbuf_len = MBUF_LEN_DEF,
	.mbuf_max_slots = MBUF_SLOTS_DEF,
	.mbuf_next_id = 0,
	.mbuf_size_per_cg = 0,
	.mbuf = NULL,
	.mbuf_bitmap = NULL,
};

static void __init mbuf_len_update(u64 size)
{
	if (size)
		size = roundup_pow_of_two(size);

	if (size > MBUF_LEN_MAX) {
		size = (u64)MBUF_LEN_MAX;
		pr_warn("mbuf: monitor buffer over [ %llu ] is not supported.\n",
				(u64)MBUF_LEN_MAX);
	}

	if (size < MBUF_LEN_MIN) {
		size = (u64) MBUF_LEN_MIN;
		pr_warn("mbuf: monitor buffer less [ %llu ] is not supported.\n",
				(u64) MBUF_LEN_MIN);
	}

	g_mbuf.mbuf_len = size;
}

static int  __init mbuf_len_setup(char *str)
{

	u64 size;

	if (!str)
		return -EINVAL;

	size = memparse(str, &str);

	mbuf_len_update(size);

	return 0;

}
early_param("mbuf_len", mbuf_len_setup);

static int __init mbuf_max_items_setup(char *str)
{
	int num;

	if (!str)
		return -EINVAL;

	if (!get_option(&str, &num))
		return -EINVAL;

	if (num)
		num = roundup_pow_of_two(num);

	if (num > MBUF_SLOTS_MAX)
		num = MBUF_SLOTS_MAX;

	if (num < MBUF_SLOTS_MIN)
		num = MBUF_SLOTS_MIN;

	g_mbuf.mbuf_max_slots = num;

	return 0;
}
early_param("mbuf_max_items", mbuf_max_items_setup);

/* Alloc mbuf global bitmap, each bit stands for a mbuf slot. */
void __init mbuf_bmap_init(void)
{
	size_t alloc_size;
	void *mbuf_bitmap;

	alloc_size = max_t(size_t, g_mbuf.mbuf_max_slots / BITS_PER_BYTE + 1,
					   L1_CACHE_BYTES);
	mbuf_bitmap = kmalloc(alloc_size, __GFP_HIGH|__GFP_ZERO);

	if (!mbuf_bitmap) {
		pr_err("mbuf: alloc mbuf_bitmap failed!\n");
		return;
	}
	g_mbuf.mbuf_bitmap = mbuf_bitmap;
	g_mbuf.mbuf_size_per_cg = g_mbuf.mbuf_len / g_mbuf.mbuf_max_slots;
}

/* Called by start_kernel() */
void __init setup_mbuf(void)
{
	/* mbuf has been alloced */
	if (g_mbuf.mbuf)
		return;

	g_mbuf.mbuf = memblock_alloc(g_mbuf.mbuf_len, PAGE_SIZE);
	if (unlikely(!g_mbuf.mbuf)) {
		pr_err("mbuf: memblock_alloc [ %u ] bytes failed\n",
				g_mbuf.mbuf_len);
		return;
	}

	g_mbuf.mbuf_frees = g_mbuf.mbuf_max_slots;
	spin_lock_init(&g_mbuf.mbuf_lock);

	pr_info("mbuf: mbuf_len:%u\n", g_mbuf.mbuf_len);
}

/* Get mbuf ring desc text pointer */
static char *mbuf_text(struct mbuf_ring_desc *desc)
{
	return (char *)desc + sizeof(struct mbuf_ring_desc);
}

/* Get next mbuf_slot idx */
static u32 mbuf_next(struct mbuf_ring *mring, u32 curr_idx)
{
	struct mbuf_ring_desc *cdesc, *ndesc;
	u32 frees, next_idx;

	cdesc = (struct mbuf_ring_desc *)(g_mbuf.mbuf + curr_idx);
	next_idx = curr_idx + cdesc->len;
	/*
	 * If frees are not enough to store mbuf_ring_desc struct,
	 * just goto head
	 */
	frees = mring->end_idx - next_idx;
	if (frees < sizeof(struct mbuf_ring_desc)) {
		next_idx = mring->base_idx;
		goto next;
	}

	ndesc = (struct mbuf_ring_desc *)(g_mbuf.mbuf + next_idx);
	if (!ndesc->len && next_idx != mring->next_idx)
		next_idx = mring->base_idx;

next:
	return next_idx;
}

static inline struct mbuf_ring_desc *get_ring_desc_from_idx(
					struct mbuf_ring *ring, u32 idx)
{
	return (struct mbuf_ring_desc *)(g_mbuf.mbuf + idx);
}

/* Read mbuf message according to its idx */
static ssize_t mbuf_read(struct mbuf_slot *mb, struct mbuf_user_desc *udesc)
{
	struct mbuf_ring *mring;
	struct mbuf_ring_desc *desc;
	ssize_t ret;
	size_t i, len, tbuf_len;

	tbuf_len = sizeof(udesc->buf);
	mring = mb->mring;

	if (udesc->user_seq < mring->first_seq) {
		udesc->user_seq = mring->first_seq;
		udesc->user_idx = mring->first_idx;
		ret = -1;
		goto out;
	}

	desc = get_ring_desc_from_idx(mring, udesc->user_idx);

	len = sprintf(udesc->buf, "%llu:", desc->ts_ns);
	for (i = 0; i < desc->text_len; i++) {
		unsigned char c = mbuf_text(desc)[i];

		if (c < ' ' || c >= 127 || c == '\\')
			continue;
		else
			udesc->buf[len++] = c;

		if (len >= tbuf_len)
			break;
	}

	len = len >= tbuf_len ? tbuf_len - 1 : len;
	udesc->buf[len] = '\n';
	udesc->user_seq++;
	ret = len;

out:
	return ret;
}

static int mbuf_prepare(struct mbuf_ring *mring, u32 msg_size)
{
	u32 frees;

	if (unlikely(msg_size > MBUF_MSG_LEN_MAX))
		return -ENOMEM;

	while (mring->first_seq < mring->next_seq) {

		if (mring->first_idx < mring->next_idx)
			frees = max(mring->end_idx - mring->next_idx,
					   mring->first_idx - mring->base_idx);
		else
			frees = mring->first_idx - mring->next_idx;

		if (frees > msg_size)
			break;

		/* Drop old message until se have enough contiguous space */
		mring->first_idx = mbuf_next(mring, mring->first_idx);
		mring->first_seq++;
	}
	return 0;
}

/* Write monitor buffer message */
static ssize_t do_mbuf_write(struct mbuf_slot *mbuf, char *buffer, size_t size)
{
	struct mbuf_ring *mring;
	struct mbuf_ring_desc *desc;
	size_t len;
	unsigned long flags;

	if (size >= g_mbuf.mbuf_size_per_cg) {
		pr_err("mbuf: write message need less than [ %u ] bytes\n",
				g_mbuf.mbuf_size_per_cg);
		return 0;
	}

	mring = mbuf->mring;
	len = sizeof(struct mbuf_ring_desc) + size;

	write_seqlock_irqsave(&mbuf->slot_lock, flags);

	if (mbuf_prepare(mring, len)) {
		write_sequnlock_irqrestore(&mbuf->slot_lock, flags);
		pr_err("mbuf: Can not find enough space.\n");
		return 0;
	}

	if (mring->next_idx + len >= mring->end_idx) {
		/* Set remain buffer to 0 if we go to head */
		memset(g_mbuf.mbuf + mring->next_idx, 0, mring->end_idx - mring->next_idx);
		mring->next_idx = mring->base_idx;
	}

	desc = (struct mbuf_ring_desc *)(g_mbuf.mbuf + mring->next_idx);
	memcpy(mbuf_text(desc), buffer, size);
	desc->len = size + sizeof(struct mbuf_ring_desc);
	desc->text_len = size;
	desc->ts_ns = local_clock();
	mring->next_idx += desc->len;
	mring->next_seq++;

	write_sequnlock_irqrestore(&mbuf->slot_lock, flags);

	return size;
}

void mbuf_reset(struct mbuf_slot *mbuf)
{
	unsigned long flags;

	write_seqlock_irqsave(&mbuf->slot_lock, flags);
	mbuf->mring->first_idx = mbuf->mring->base_idx;
	mbuf->mring->first_seq = 0;
	mbuf->mring->next_idx = mbuf->mring->base_idx;
	mbuf->mring->next_seq = 0;
	write_sequnlock_irqrestore(&mbuf->slot_lock, flags);
}
EXPORT_SYMBOL(mbuf_reset);

static ssize_t mbuf_write(struct mbuf_slot *mbuf, const char *fmt, va_list args)
{
	static char buf[MBUF_MSG_LEN_MAX];
	char *text = buf;
	size_t t_len;
	ssize_t ret;
	/* Store string to buffer */
	t_len = vscnprintf(text, sizeof(buf), fmt, args);

	/* Write string to mbuf */
	ret = do_mbuf_write(mbuf, text, t_len);

	return ret;
}

const struct mbuf_operations mbuf_ops = {
	.read		= mbuf_read,
	.next		= mbuf_next,
	.write		= mbuf_write,
};

static int get_next_mbuf_id(unsigned long *addr, u32 start)
{
	u32 index;

	index = find_next_zero_bit(addr, g_mbuf.mbuf_max_slots, start);
	if (unlikely(index >= g_mbuf.mbuf_max_slots))
		return g_mbuf.mbuf_max_slots;

	return index;
}

static void mbuf_slot_init(struct mbuf_slot *mb,
			   void *owner, u32 index, struct mbuf_operations *ops)
{
	mb->owner = owner;
	mb->idx = index;

	if (!ops)
		mb->ops = &mbuf_ops;
	else
		mb->ops = ops;

	seqlock_init(&mb->slot_lock);
	ratelimit_state_init(&mb->ratelimit, 5 * HZ, 50);

	mb->mring = (struct mbuf_ring *)((char *)mb + sizeof(struct mbuf_slot));
	mb->mring->base_idx = index * g_mbuf.mbuf_size_per_cg
				+ sizeof(struct mbuf_slot)
				+ sizeof(struct mbuf_ring);
	mb->mring->end_idx = (index + 1) * g_mbuf.mbuf_size_per_cg - 1;

	mbuf_reset(mb);
}

struct mbuf_slot *mbuf_slot_alloc_v2(void *owner, struct mbuf_operations *ops)
{
	struct mbuf_slot *mb;
	u32 index = 0;
	u32 try_times;
	unsigned long *m_bitmap;
	unsigned long flags;

	/* If mbuf_bitmap or mbuf not ready, just return NULL. */
	if (!g_mbuf.mbuf_bitmap || !g_mbuf.mbuf) {
		pr_warn_ratelimited("mbuf: mbuf bitmap or mbuf pointer is NULL, alloc failed\n");
		return NULL;
	}

	spin_lock_irqsave(&g_mbuf.mbuf_lock, flags);

	if (g_mbuf.mbuf_frees == 0) {
		pr_warn_ratelimited("mbuf: reached max num, alloc failed\n");
		spin_unlock_irqrestore(&g_mbuf.mbuf_lock, flags);
		return NULL;
	}

	/* Alloc a free mbuf_slot from global mbuf, according mbuf_bitmap */
	m_bitmap = g_mbuf.mbuf_bitmap;

	try_times = 1;
again:
	index = get_next_mbuf_id(m_bitmap, g_mbuf.mbuf_next_id);

	/* Rescan next avail idx from head if current idx reach end */
	if (index == g_mbuf.mbuf_max_slots && try_times--) {
		g_mbuf.mbuf_next_id = 0;
		goto again;
	}

	if (unlikely(index == g_mbuf.mbuf_max_slots)) {
		/*
		 * Just a protection mechanism, its must be a bug
		 * if function reached here.
		 */
		pr_warn_ratelimited("mbuf: frees and bitmap not coincident, just return\n");
		spin_unlock_irqrestore(&g_mbuf.mbuf_lock, flags);
		return NULL;
	}

	__set_bit(index, m_bitmap);
	g_mbuf.mbuf_next_id = index;

	mb = (struct mbuf_slot *)(g_mbuf.mbuf + index * g_mbuf.mbuf_size_per_cg);
	mbuf_slot_init(mb, owner, index, ops);
	g_mbuf.mbuf_frees--;

	spin_unlock_irqrestore(&g_mbuf.mbuf_lock, flags);

	return mb;
}
EXPORT_SYMBOL(mbuf_slot_alloc_v2);

struct mbuf_slot *mbuf_slot_alloc(struct cgroup *cg)
{
	return mbuf_slot_alloc_v2((void *)cg, NULL);
}
EXPORT_SYMBOL(mbuf_slot_alloc);

void mbuf_free_slot(struct mbuf_slot *slot)
{
	unsigned long flags;

	spin_lock_irqsave(&g_mbuf.mbuf_lock, flags);
	/* Make current idx the next available buffer */
	g_mbuf.mbuf_next_id = slot->idx;
	__clear_bit(g_mbuf.mbuf_next_id, g_mbuf.mbuf_bitmap);
	g_mbuf.mbuf_frees++;
	spin_unlock_irqrestore(&g_mbuf.mbuf_lock, flags);

}
EXPORT_SYMBOL(mbuf_free_slot);

void mbuf_free(struct cgroup *cg)
{
	mbuf_free_slot(cg->mbuf);
}

static u32 rd_mbuf_next(struct mbuf_ring *mring, u32 curr_idx)
{
	struct mbuf_ring_desc *cdesc, *ndesc;
	u32 frees, next_idx;
	void *start;

	start = (void *)(mring + 1);
	cdesc = (struct mbuf_ring_desc *)(start + curr_idx);
	next_idx = curr_idx + cdesc->len;

	frees = mring->end_idx - next_idx;
	if (frees < sizeof(struct mbuf_ring_desc)) {
		/* end */
		if (next_idx == mring->next_idx)
			return next_idx;

		/*buffer wrapped to head */
		next_idx = mring->base_idx;
		goto next;
	}

	ndesc = (struct mbuf_ring_desc *)(start + next_idx);

	/* same magic can't be said */
	if (!ndesc->len && next_idx != mring->next_idx)
		next_idx = mring->base_idx;
next:
	return next_idx;
}

static ssize_t rd_mbuf_read(struct mbuf_slot *mb, struct mbuf_user_desc *udesc)
{
	struct mbuf_ring_desc *desc;
	ssize_t ret;
	size_t i, len, tbuf_len;
	char *start;

	tbuf_len = sizeof(udesc->buf);
	start = (char *)(mb->mring + 1);
	desc = (struct mbuf_ring_desc *)(start + udesc->user_idx);

	len = sprintf(udesc->buf, "%llu:", desc->ts_ns);
	start = (char *)(desc + 1);

	for (i = 0; i < desc->text_len; i++) {
		unsigned char c = start[i];

		if (c < ' ' || c >= 127 || c == '\\')
			continue;
		else
			udesc->buf[len++] = c;
		if (len >= tbuf_len)
			break;
	}

	len = len >= tbuf_len ? tbuf_len - 1 : len;
	udesc->buf[len] = '\n';
	udesc->user_seq++;
	ret = len;
	return ret;
}

/* this ops is just for read-side abi of mbuf, mbuf has a write ops
 * which is protect by spinlock, while there is no read-write side
 * protection.
 * you can use like follow:
 *
 * called snapshot_mbuf copy data from mbuf to the `dst`. then read
 * the dst use the following ops
 *
 * all the index is offset from the end point of mring of the
 * snapshot, instead of from the global mbuf memory pool
 *
 * btw: the private data of seq file is the ideal place to hold the
 * snapshot
 */
const struct mbuf_operations rd_mbuf_ops = {
	.read		= rd_mbuf_read,
	.next		= rd_mbuf_next,
};

void snapshot_mbuf(struct mbuf_slot *dst, struct mbuf_slot *src, seqlock_t *lock)
{
	unsigned int seq;

	do {
		/* the peer of the lock is write-side, we want writer
		 * go first when there is confliction, and this reader
		 * retry to read go get a consistent buf snapshot
		 */
		cond_resched();
		seq = read_seqbegin(lock);
		memcpy((void *)dst, (void *)src, g_mbuf.mbuf_size_per_cg);
	} while (read_seqretry(lock, seq));

	/* all the ops in `rd_mbuf_ops` see a idx offset from the end
	 * point of mring. so here adjust the idx as a whole
	 */
	dst->mring = (struct mbuf_ring *)(dst + 1);
	dst->mring->end_idx = dst->mring->end_idx - dst->mring->base_idx;
	dst->mring->first_idx = dst->mring->first_idx - dst->mring->base_idx;
	dst->mring->next_idx = dst->mring->next_idx - dst->mring->base_idx;
	dst->mring->base_idx = 0;
	dst->ops = &rd_mbuf_ops;
}
EXPORT_SYMBOL(snapshot_mbuf);

/* the mbuf size per cg is not changed once the system booted up */
u32 get_mbuf_slot_len(void)
{
	return g_mbuf.mbuf_size_per_cg;
}
EXPORT_SYMBOL(get_mbuf_slot_len);
