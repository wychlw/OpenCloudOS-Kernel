// SPDX-License-Identifier: GPL-2.0
/*
 * Workingset detection
 *
 * Copyright (C) 2013 Red Hat, Inc., Johannes Weiner
 */

#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/writeback.h>
#include <linux/shmem_fs.h>
#include <linux/pagemap.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/mm.h>

/*
 *		Double CLOCK lists
 *
 * Per node, two clock lists are maintained for file pages: the
 * inactive and the active list.  Freshly faulted pages start out at
 * the head of the inactive list and page reclaim scans pages from the
 * tail.  Pages that are accessed multiple times on the inactive list
 * are promoted to the active list, to protect them from reclaim,
 * whereas active pages are demoted to the inactive list when the
 * active list grows too big.
 *
 *   fault ------------------------+
 *                                 |
 *              +--------------+   |            +-------------+
 *   reclaim <- |   inactive   | <-+-- demotion |    active   | <--+
 *              +--------------+                +-------------+    |
 *                     |                                           |
 *                     +-------------- promotion ------------------+
 *
 *
 *		Access frequency and refault distance
 *
 * A workload is thrashing when its pages are frequently used but they
 * are evicted from the inactive list every time before another access
 * would have promoted them to the active list.
 *
 * In cases where the average access distance between thrashing pages
 * is bigger than the size of memory there is nothing that can be
 * done - the thrashing set could never fit into memory under any
 * circumstance.
 *
 * However, the average access distance could be bigger than the
 * inactive list, yet smaller than the size of memory.  In this case,
 * the set could fit into memory if it weren't for the currently
 * active pages - which may be used more, hopefully less frequently:
 *
 *      +-memory available to cache-+
 *      |                           |
 *      +-inactive------+-active----+
 *  a b | c d e f g h i | J K L M N |
 *      +---------------+-----------+
 *
 * It is prohibitively expensive to accurately track access frequency
 * of pages.  But a reasonable approximation can be made to measure
 * thrashing on the inactive list, after which refaulting pages can be
 * activated optimistically to compete with the existing active pages.
 *
 * For such approximation, we introduce a counter `eviction` (E)
 * here. This counter increases each time a page is evicted, and each evicted
 * page will have a shadow that stores the counter reading at the eviction
 * time as a timestamp. So when an evicted page was faulted again, we have:
 *
 *   Let SP = ((E's reading @ current) - (E's reading @ eviction))
 *
 *                            +-memory available to cache-+
 *                            |                           |
 *  +-------------------------+===============+===========+
 *  | *   shadows  O O  O     |   INACTIVE    |   ACTIVE  |
 *  +-+-----------------------+===============+===========+
 *    |                       |
 *    +-----------------------+
 *    |         SP
 *  fault page          O -> Hole left by previously faulted in pages
 *                      * -> The page corresponding to SP
 *
 * Here SP can stands for how far the current workflow could push a page
 * out of available memory. Since all evicted page was once head of
 * INACTIVE list, the page could have such an access distance of:
 *
 *   SP + NR_INACTIVE
 *
 * So if:
 *
 *   SP + NR_INACTIVE < NR_INACTIVE + NR_ACTIVE
 *
 * Which can be simplified to:
 *
 *   SP < NR_ACTIVE
 *
 * Then the page is worth getting re-activated to start from ACTIVE part,
 * since the access distance is shorter than total memory to make it stay.
 *
 * And since this is only an estimation, based on several hypotheses, and
 * it could break the ability of LRU to distinguish a workingset out of
 * caches, so throttle this by two factors:
 *
 * 1. Notice that re-faulted in pages may leave "holes" on the shadow
 *    part of LRU, that part is left unhandled on purpose to decrease
 *    re-activate rate for pages that have a large SP value (the larger
 *    SP value a page have, the more likely it will be affected by such
 *    holes).
 * 2. When the ACTIVE part of LRU is long enough, challenging ACTIVE pages
 *    by re-activating a one-time faulted previously INACTIVE page may not
 *    be a good idea, so throttle the re-activation when ACTIVE > INACTIVE
 *    by comparing with INACTIVE instead.
 *
 * Combined all above, we have:
 * Upon refault, if any of the following conditions is met, mark the page
 * as active:
 *
 * - If ACTIVE LRU is low (NR_ACTIVE < NR_INACTIVE), check if:
 *   SP < NR_ACTIVE
 *
 * - If ACTIVE LRU is high (NR_ACTIVE >= NR_INACTIVE), check if:
 *   SP < NR_INACTIVE
 *
 *		Refaulting inactive pages
 *
 * All that is known about the active list is that the pages have been
 * accessed more than once in the past.  This means that at any given
 * time there is actually a good chance that pages on the active list
 * are no longer in active use.
 *
 * So when a refault distance of (R - E) is observed and there are at
 * least (R - E) pages in the userspace workingset, the refaulting page
 * is activated optimistically in the hope that (R - E) pages are actually
 * used less frequently than the refaulting page - or even not used at
 * all anymore.
 *
 * That means if inactive cache is refaulting with a suitable refault
 * distance, we assume the cache workingset is transitioning and put
 * pressure on the current workingset.
 *
 * If this is wrong and demotion kicks in, the pages which are truly
 * used more frequently will be reactivated while the less frequently
 * used once will be evicted from memory.
 *
 * But if this is right, the stale pages will be pushed out of memory
 * and the used pages get to stay in cache.
 *
 *		Refaulting active pages
 *
 * If on the other hand the refaulting pages have recently been
 * deactivated, it means that the active list is no longer protecting
 * actively used cache from reclaim. The cache is NOT transitioning to
 * a different workingset; the existing workingset is thrashing in the
 * space allocated to the page cache.
 *
 *
 *		Implementation
 *
 * For each node's LRU lists, a counter for inactive evictions and
 * activations is maintained (node->evictions).
 *
 * On eviction, a snapshot of this counter (along with some bits to
 * identify the node) is stored in the now empty page cache
 * slot of the evicted page.  This is called a shadow entry.
 *
 * On cache misses for which there are shadow entries, an eligible
 * refault distance will immediately activate the refaulting page.
 */

#define WORKINGSET_SHIFT 1
#define EVICTION_SHIFT	((BITS_PER_LONG - BITS_PER_XA_VALUE) + \
			 WORKINGSET_SHIFT + NODES_SHIFT + \
			 MEM_CGROUP_ID_SHIFT)
#define EVICTION_BITS	(BITS_PER_LONG - (EVICTION_SHIFT))
#define EVICTION_MASK	(~0UL >> EVICTION_SHIFT)
#define LRU_GEN_EVICTION_BITS	(EVICTION_BITS - LRU_REFS_WIDTH)

/*
 * Eviction timestamps need to be able to cover the full range of
 * actionable refaults. However, bits are tight in the xarray
 * entry, and after storing the identifier for the lruvec there might
 * not be enough left to represent every single actionable refault. In
 * that case, we have to sacrifice granularity for distance, and group
 * evictions into coarser buckets by shaving off lower timestamp bits.
 */
static unsigned int bucket_order __read_mostly;
static unsigned int lru_gen_bucket_order __read_mostly;

static void *pack_shadow(int memcgid, pg_data_t *pgdat, unsigned long eviction,
			 bool workingset)
{
	eviction &= EVICTION_MASK;
	eviction = (eviction << MEM_CGROUP_ID_SHIFT) | memcgid;
	eviction = (eviction << NODES_SHIFT) | pgdat->node_id;
	eviction = (eviction << WORKINGSET_SHIFT) | workingset;

	return xa_mk_value(eviction);
}

static void unpack_shadow(void *shadow, int *memcgidp, pg_data_t **pgdat,
			  unsigned long *evictionp, bool *workingsetp)
{
	unsigned long entry = xa_to_value(shadow);
	int memcgid, nid;
	bool workingset;

	workingset = entry & ((1UL << WORKINGSET_SHIFT) - 1);
	entry >>= WORKINGSET_SHIFT;
	nid = entry & ((1UL << NODES_SHIFT) - 1);
	entry >>= NODES_SHIFT;
	memcgid = entry & ((1UL << MEM_CGROUP_ID_SHIFT) - 1);
	entry >>= MEM_CGROUP_ID_SHIFT;

	*memcgidp = memcgid;
	*pgdat = NODE_DATA(nid);
	*evictionp = entry;
	*workingsetp = workingset;
}

#ifdef CONFIG_EMM_WORKINGSET_TRACKING
static void workingset_eviction_file(struct lruvec *lruvec, unsigned long nr_pages)
{
	do {
		atomic_long_add(nr_pages, &lruvec->evicted_file);
	} while ((lruvec = parent_lruvec(lruvec)));
}

/*
 * If a page is evicted and never come back, either this page is really cold or it
 * is deleted on disk.
 *
 * For cold page, it could take up all of memory until kswapd start to shrink it.
 * For deleted page, the shadow will be gone too, so no refault.
 *
 * If a page comes back before it's shadow is released, that's a refault, which means
 * file page reclaim have gone over-aggressive and that page would not have been evicted
 * if all the page, include it self, stayed in memory.
 */
static void workingset_refault_track(struct lruvec *lruvec, unsigned long refault_distance)
{
	do {
		/*
		 * Not taking any lock, for better performance, may lead to some
		 * event got lost, but it's just a rough estimation anyway.
		 */
		WRITE_ONCE(lruvec->refault_count, READ_ONCE(lruvec->refault_count) + 1);
		WRITE_ONCE(lruvec->total_distance, READ_ONCE(lruvec->total_distance) + refault_distance);
	} while ((lruvec = parent_lruvec(lruvec)));
}
#else
static void workingset_eviction_file(struct lruvec *lruvec, unsigned long nr_pages)
{
}
static void workingset_refault_track(struct lruvec *lruvec, unsigned long refault_distance)
{
}
#endif

static inline struct mem_cgroup *try_get_flush_memcg(int memcgid)
{
	struct mem_cgroup *memcg;

	/*
	 * Look up the memcg associated with the stored ID. It might
	 * have been deleted since the folio's eviction.
	 *
	 * Note that in rare events the ID could have been recycled
	 * for a new cgroup that refaults a shared folio. This is
	 * impossible to tell from the available data. However, this
	 * should be a rare and limited disturbance, and activations
	 * are always speculative anyway. Ultimately, it's the aging
	 * algorithm's job to shake out the minimum access frequency
	 * for the active cache.
	 *
	 * XXX: On !CONFIG_MEMCG, this will always return NULL; it
	 * would be better if the root_mem_cgroup existed in all
	 * configurations instead.
	 */
	rcu_read_lock();
	memcg = mem_cgroup_from_id(memcgid);
	if (!mem_cgroup_disabled() &&
	    (!memcg || !mem_cgroup_tryget(memcg))) {
		rcu_read_unlock();
		return NULL;
	}
	rcu_read_unlock();

	/*
	 * Flush stats (and potentially sleep) outside the RCU read section.
	 * XXX: With per-memcg flushing and thresholding, is ratelimiting
	 * still needed here?
	 */
	mem_cgroup_flush_stats_ratelimited(memcg);

	return memcg;
}

/**
 * lru_eviction - age non-resident entries as LRU ages
 *
 * As in-memory pages are aged, non-resident pages need to be aged as
 * well, in order for the refault distances later on to be comparable
 * to the in-memory dimensions. This function allows reclaim and LRU
 * operations to drive the non-resident aging along in parallel.
 */
static inline unsigned long lru_eviction(struct lruvec *lruvec, int type,
					 int nr_pages, int bits, int bucket_order)
{
	unsigned long eviction;

	if (type)
		workingset_eviction_file(lruvec, nr_pages);

	/*
	 * Reclaiming a cgroup means reclaiming all its children in a
	 * round-robin fashion. That means that each cgroup has an LRU
	 * order that is composed of the LRU orders of its child
	 * cgroups; and every page has an LRU position not just in the
	 * cgroup that owns it, but in all of that group's ancestors.
	 *
	 * So when the physical inactive list of a leaf cgroup ages,
	 * the virtual inactive lists of all its parents, including
	 * the root cgroup's, age as well.
	 */
	eviction = atomic_long_fetch_add_relaxed(nr_pages, &lruvec->evictions[type]);
	while ((lruvec = parent_lruvec(lruvec)))
		atomic_long_add(nr_pages, &lruvec->evictions[type]);

	/* Truncate the timestamp to fit in limited bits */
	eviction >>= bucket_order;
	eviction &= ~0UL >> (BITS_PER_LONG - bits);
	return eviction;
}

/*
 * lru_distance - calculate the refault distance based on non-resident age
 */
static inline unsigned long lru_distance(struct lruvec *lruvec, int type,
					 unsigned long eviction, int bits,
					 int bucket_order)
{
	unsigned long refault = atomic_long_read(&lruvec->evictions[type]);

	eviction &= ~0UL >> (BITS_PER_LONG - bits);
	eviction <<= bucket_order;

	/*
	 * The unsigned subtraction here gives an accurate distance
	 * across non-resident age overflows in most cases. There is a
	 * special case: usually, shadow entries have a short lifetime
	 * and are either refaulted or reclaimed along with the inode
	 * before they get too old.  But it is not impossible for the
	 * non-resident age to lap a shadow entry in the field, which
	 * can then result in a false small refault distance, leading
	 * to a false activation should this old entry actually
	 * refault again.  However, earlier kernels used to deactivate
	 * unconditionally with *every* reclaim invocation for the
	 * longest time, so the occasional inappropriate activation
	 * leading to pressure on the active list is not a problem.
	 */
	return (refault - eviction) & (~0UL >> (BITS_PER_LONG - bits));
}

#ifdef CONFIG_LRU_GEN

static void *lru_gen_eviction(struct folio *folio)
{
	int hist;
	unsigned long token;
	struct lruvec *lruvec;
	struct lru_gen_folio *lrugen;
	int type = folio_is_file_lru(folio);
	int delta = folio_nr_pages(folio);
	int refs = folio_lru_refs(folio);
	int tier = lru_tier_from_refs(refs);
	struct mem_cgroup *memcg = folio_memcg(folio);
	struct pglist_data *pgdat = folio_pgdat(folio);

	BUILD_BUG_ON(LRU_REFS_WIDTH > BITS_PER_LONG - EVICTION_SHIFT);

	lruvec = mem_cgroup_lruvec(memcg, pgdat);
	lrugen = &lruvec->lrugen;
	hist = lru_hist_of_min_seq(lruvec, type);

	token = max(refs - 1, 0);
	token <<= LRU_GEN_EVICTION_BITS;
	token |= lru_eviction(lruvec, type, delta,
			      LRU_GEN_EVICTION_BITS, lru_gen_bucket_order);
	atomic_long_add(delta, &lrugen->evicted[hist][type][tier]);

	return pack_shadow(mem_cgroup_id(memcg), pgdat, token, refs);
}

/*
 * Tests if the shadow entry is for a folio that was recently evicted.
 * Fills in @lruvec, @token, @workingset with the values unpacked from shadow.
 */
static bool inline lru_gen_test_recent(struct lruvec *lruvec, bool type,
				       unsigned long distance)
{
	int hist;
	unsigned long evicted = 0;
	struct lru_gen_folio *lrugen;

	lrugen = &lruvec->lrugen;
	hist = lru_hist_of_min_seq(lruvec, type);

	for (int tier = 0; tier < MAX_NR_TIERS; tier++)
		evicted += atomic_long_read(&lrugen->evicted[hist][type][tier]);

	return distance <= evicted;
}

enum lru_gen_refault_distance {
	DISTANCE_SHORT,
	DISTANCE_MID,
	DISTANCE_LONG,
	DISTANCE_NONE,
};

static inline int lru_gen_test_refault(struct lruvec *lruvec, bool file,
				       unsigned long distance, bool can_swap)
{
	unsigned long total;

	total = lruvec_page_state(lruvec, NR_ACTIVE_FILE) +
		lruvec_page_state(lruvec, NR_INACTIVE_FILE);

	if (can_swap)
		total += lruvec_page_state(lruvec, NR_ACTIVE_ANON) +
			lruvec_page_state(lruvec, NR_INACTIVE_ANON);

	/* Imagine having an extra gen outside of available memory */
	if (distance <= total / MAX_NR_GENS)
		return DISTANCE_SHORT;
	if (distance <= total / MIN_NR_GENS)
		return DISTANCE_MID;
	if (distance <= total)
		return DISTANCE_LONG;
	return DISTANCE_NONE;
}

static void lru_gen_refault(struct folio *folio, void *shadow)
{
	int memcgid;
	bool recent;
	bool workingset;
	unsigned long token;
	int hist, tier, refs;
	struct lruvec *lruvec;
	struct mem_cgroup *memcg;
	struct pglist_data *pgdat;
	struct lru_gen_folio *lrugen;
	int type = folio_is_file_lru(folio);
	int delta = folio_nr_pages(folio);
	int distance;
	unsigned long refault_distance, protect_tier;

	unpack_shadow(shadow, &memcgid, &pgdat, &token, &workingset);
	memcg = try_get_flush_memcg(memcgid);
	if (!memcg)
		return;

	lruvec = mem_cgroup_lruvec(memcg, pgdat);
	if (lruvec != folio_lruvec(folio))
		goto unlock;

	mod_lruvec_state(lruvec, WORKINGSET_REFAULT_BASE + type, delta);
	refault_distance = lru_distance(lruvec, type, token,
				LRU_GEN_EVICTION_BITS, lru_gen_bucket_order);
	workingset_refault_track(lruvec, distance);
	/* Check if the gen the page was evicted from still exist */
	recent = lru_gen_test_recent(lruvec, type, refault_distance);
	/* Check if the distance indicates a refault */
	distance = lru_gen_test_refault(lruvec, type, refault_distance,
					mem_cgroup_get_nr_swap_pages(memcg));
	if (!recent && distance == DISTANCE_NONE)
		goto unlock;

	/* see the comment in folio_lru_refs() */
	token >>= LRU_GEN_EVICTION_BITS;
	refs = (token & (BIT(LRU_REFS_WIDTH) - 1)) + workingset;
	tier = lru_tier_from_refs(refs);

	/*
	 * Count the following two cases as stalls:
	 * 1. For pages accessed through page tables, hotter pages pushed out
	 *    hot pages which refaulted immediately.
	 * 2. For pages accessed multiple times through file descriptors,
	 *    they would have been protected by sort_folio().
	 */
	if (lru_gen_in_fault() || refs >= BIT(LRU_REFS_WIDTH) - 1) {
		if (distance <= DISTANCE_SHORT) {
			/* Set ref bits and workingset (increase refs by one) */
			if (!lru_gen_in_fault())
				folio_set_active(folio);
			else
				set_mask_bits(&folio->flags, 0,
					min_t(unsigned long, refs, BIT(LRU_REFS_WIDTH) - 1)
					<< LRU_REFS_PGOFF);
			folio_set_workingset(folio);
		} else if (recent || distance <= DISTANCE_MID) {
			/*
			 * Beyound PID protection range, no point increasing refs
			 * for highest tier, but we can activate file page.
			 */
			set_mask_bits(&folio->flags, 0, (unsigned long)(refs - workingset) << LRU_REFS_PGOFF);
			folio_set_workingset(folio);
		} else {
			set_mask_bits(&folio->flags, 0, 1UL << LRU_REFS_PGOFF);
		}
		mod_lruvec_state(lruvec, WORKINGSET_RESTORE_BASE + type, delta);
	}

	lrugen = &lruvec->lrugen;
	hist = lru_hist_of_min_seq(lruvec, type);
	protect_tier = tier;

	/*
	 * Don't over-protect clean cache page (!tier page), if the page wasn't access
	 * for a while (refault distance > LRU / MAX_NR_GENS), there is no help keeping
	 * it in memory, bias higher tier instead.
	 */
	if (distance <= DISTANCE_SHORT && !tier) {
		/* The folio is referenced one more time in the shadow gen */
		folio_set_workingset(folio);
		protect_tier = lru_tier_from_refs(1);
		mod_lruvec_state(lruvec, WORKINGSET_ACTIVATE_BASE + type, delta);
	}

	if (protect_tier == tier && recent) {
		atomic_long_add(delta, &lrugen->refaulted[hist][type][tier]);
	} else {
		atomic_long_add(delta, &lrugen->avg_total[type][protect_tier]);
		atomic_long_add(delta, &lrugen->avg_refaulted[type][protect_tier]);
	}
unlock:
	mem_cgroup_put(memcg);
}

#else /* !CONFIG_LRU_GEN */

static void *lru_gen_eviction(struct folio *folio)
{
	return NULL;
}

static bool lru_gen_test_recent(struct lruvec *lruvec, bool file,
				unsigned long token)
{
	return false;
}

static void lru_gen_refault(struct folio *folio, void *shadow)
{
}

#endif /* CONFIG_LRU_GEN */

/**
 * workingset_eviction - note the eviction of a folio from memory
 * @target_memcg: the cgroup that is causing the reclaim
 * @folio: the folio being evicted
 *
 * Return: a shadow entry to be stored in @folio->mapping->i_pages in place
 * of the evicted @folio so that a later refault can be detected.
 */
void *workingset_eviction(struct folio *folio, struct mem_cgroup *target_memcg)
{
	struct pglist_data *pgdat = folio_pgdat(folio);
	unsigned long eviction;
	struct lruvec *lruvec;
	int memcgid;

	/* Folio is fully exclusive and pins folio's memory cgroup pointer */
	VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);
	VM_BUG_ON_FOLIO(folio_ref_count(folio), folio);
	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

	if (lru_gen_enabled())
		return lru_gen_eviction(folio);

	lruvec = mem_cgroup_lruvec(target_memcg, pgdat);
	/* XXX: target_memcg can be NULL, go through lruvec */
	memcgid = mem_cgroup_id(lruvec_memcg(lruvec));
	eviction = lru_eviction(lruvec, folio_is_file_lru(folio),
				folio_nr_pages(folio), EVICTION_BITS, bucket_order);
	return pack_shadow(memcgid, pgdat, eviction,
				folio_test_workingset(folio));
}

/**
 * workingset_test_recent - tests if the shadow entry is for a folio that was
 * recently evicted. Also fills in @workingset with the value unpacked from
 * shadow.
 * @shadow: the shadow entry to be tested.
 * @file: whether the corresponding folio is from the file lru.
 * @workingset: where the workingset value unpacked from shadow should
 * be stored.
 * @tracking: whether do workingset tracking or not
 *
 * Return: true if the shadow is for a recently evicted folio; false otherwise.
 */
bool workingset_test_recent(void *shadow, bool file, bool *workingset, bool tracking)
{
	struct mem_cgroup *eviction_memcg;
	struct lruvec *eviction_lruvec;
	unsigned long refault_distance;
	unsigned long inactive;
	unsigned long active;
	int memcgid;
	struct pglist_data *pgdat;
	unsigned long eviction;

	unpack_shadow(shadow, &memcgid, &pgdat, &eviction, workingset);

	/*
	 * Look up the memcg associated with the stored ID. It might
	 * have been deleted since the folio's eviction.
	 *
	 * Note that in rare events the ID could have been recycled
	 * for a new cgroup that refaults a shared folio. This is
	 * impossible to tell from the available data. However, this
	 * should be a rare and limited disturbance, and activations
	 * are always speculative anyway. Ultimately, it's the aging
	 * algorithm's job to shake out the minimum access frequency
	 * for the active cache.
	 *
	 * XXX: On !CONFIG_MEMCG, this will always return NULL; it
	 * would be better if the root_mem_cgroup existed in all
	 * configurations instead.
	 */
	eviction_memcg = try_get_flush_memcg(memcgid);
	if (!eviction_memcg)
		return false;

	/*
	 * Flush stats (and potentially sleep) outside the RCU read section.
	 * XXX: With per-memcg flushing and thresholding, is ratelimiting
	 * still needed here?
	 */
	mem_cgroup_flush_stats_ratelimited(eviction_memcg);
	eviction_lruvec = mem_cgroup_lruvec(eviction_memcg, pgdat);

	if (lru_gen_enabled()) {
		bool recent;
		refault_distance = lru_distance(eviction_lruvec, file, eviction,
						LRU_GEN_EVICTION_BITS, lru_gen_bucket_order);
		recent = lru_gen_test_recent(eviction_lruvec, file, refault_distance);
		mem_cgroup_put(eviction_memcg);
		return recent;
	}

	refault_distance = lru_distance(eviction_lruvec, file,
					eviction, EVICTION_BITS, bucket_order);

	if (tracking)
		workingset_refault_track(eviction_lruvec, refault_distance);

	/*
	 * Compare the distance to the existing workingset size. We
	 * don't activate pages that couldn't stay resident even if
	 * all the memory was available to the workingset. Whether
	 * workingset competition needs to consider anon or not depends
	 * on having free swap space.
	 */
	active = lruvec_page_state(eviction_lruvec, NR_ACTIVE_FILE);
	inactive = lruvec_page_state(eviction_lruvec, NR_INACTIVE_FILE);

	if (mem_cgroup_get_nr_swap_pages(eviction_memcg) > 0) {
		active += lruvec_page_state(eviction_lruvec, NR_ACTIVE_ANON);
		inactive += lruvec_page_state(eviction_lruvec, NR_INACTIVE_ANON);
	}

	mem_cgroup_put(eviction_memcg);

	/*
	 * When there are already enough active pages, be less aggressive
	 * on reactivating pages, challenge an large set of established
	 * active pages with one time refaulted page may not be a good idea.
	 */
	return refault_distance < min(active, inactive);
}

/**
 * workingset_refault - Evaluate the refault of a previously evicted folio.
 * @folio: The freshly allocated replacement folio.
 * @shadow: Shadow entry of the evicted folio.
 *
 * Calculates and evaluates the refault distance of the previously
 * evicted folio in the context of the node and the memcg whose memory
 * pressure caused the eviction.
 */
void workingset_refault(struct folio *folio, void *shadow)
{
	bool file = folio_is_file_lru(folio);
	struct pglist_data *pgdat;
	struct mem_cgroup *memcg;
	struct lruvec *lruvec;
	bool workingset;
	long nr;

	/*
	 * The activation decision for this folio is made at the level
	 * where the eviction occurred, as that is where the LRU order
	 * during folio reclaim is being determined.
	 *
	 * However, the cgroup that will own the folio is the one that
	 * is actually experiencing the refault event. Make sure the folio is
	 * locked to guarantee folio_memcg() stability throughout.
	 */
	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

	if (lru_gen_enabled()) {
		lru_gen_refault(folio, shadow);
		return;
	}

	nr = folio_nr_pages(folio);
	memcg = folio_memcg(folio);
	pgdat = folio_pgdat(folio);
	lruvec = mem_cgroup_lruvec(memcg, pgdat);

	mod_lruvec_state(lruvec, WORKINGSET_REFAULT_BASE + file, nr);

	if (!workingset_test_recent(shadow, file, &workingset, true))
		return;

	folio_set_active(folio);
	mod_lruvec_state(lruvec, WORKINGSET_ACTIVATE_BASE + file, nr);

	/* Folio was active prior to eviction */
	if (workingset) {
		folio_set_workingset(folio);
		/*
		 * XXX: Move to folio_add_lru() when it supports new vs
		 * putback
		 */
		lru_note_cost_refault(folio);
		mod_lruvec_state(lruvec, WORKINGSET_RESTORE_BASE + file, nr);
	}
}

/*
 * Shadow entries reflect the share of the working set that does not
 * fit into memory, so their number depends on the access pattern of
 * the workload.  In most cases, they will refault or get reclaimed
 * along with the inode, but a (malicious) workload that streams
 * through files with a total size several times that of available
 * memory, while preventing the inodes from being reclaimed, can
 * create excessive amounts of shadow nodes.  To keep a lid on this,
 * track shadow nodes and reclaim them when they grow way past the
 * point where they would still be useful.
 */

struct list_lru shadow_nodes;

void workingset_update_node(struct xa_node *node)
{
	struct address_space *mapping;

	/*
	 * Track non-empty nodes that contain only shadow entries;
	 * unlink those that contain pages or are being freed.
	 *
	 * Avoid acquiring the list_lru lock when the nodes are
	 * already where they should be. The list_empty() test is safe
	 * as node->private_list is protected by the i_pages lock.
	 */
	mapping = container_of(node->array, struct address_space, i_pages);
	lockdep_assert_held(&mapping->i_pages.xa_lock);

	if (node->count && node->count == node->nr_values) {
		if (list_empty(&node->private_list)) {
			list_lru_add(&shadow_nodes, &node->private_list);
			__inc_lruvec_kmem_state(node, WORKINGSET_NODES);
		}
	} else {
		if (!list_empty(&node->private_list)) {
			list_lru_del(&shadow_nodes, &node->private_list);
			__dec_lruvec_kmem_state(node, WORKINGSET_NODES);
		}
	}
}

static unsigned long count_shadow_nodes(struct shrinker *shrinker,
					struct shrink_control *sc)
{
	unsigned long max_nodes;
	unsigned long nodes;
	unsigned long pages;

	nodes = list_lru_shrink_count(&shadow_nodes, sc);
	if (!nodes)
		return SHRINK_EMPTY;

	/*
	 * Approximate a reasonable limit for the nodes
	 * containing shadow entries. We don't need to keep more
	 * shadow entries than possible pages on the active list,
	 * since refault distances bigger than that are dismissed.
	 *
	 * The size of the active list converges toward 100% of
	 * overall page cache as memory grows, with only a tiny
	 * inactive list. Assume the total cache size for that.
	 *
	 * Nodes might be sparsely populated, with only one shadow
	 * entry in the extreme case. Obviously, we cannot keep one
	 * node for every eligible shadow entry, so compromise on a
	 * worst-case density of 1/8th. Below that, not all eligible
	 * refaults can be detected anymore.
	 *
	 * On 64-bit with 7 xa_nodes per page and 64 slots
	 * each, this will reclaim shadow entries when they consume
	 * ~1.8% of available memory:
	 *
	 * PAGE_SIZE / xa_nodes / node_entries * 8 / PAGE_SIZE
	 */
#ifdef CONFIG_MEMCG
	if (sc->memcg) {
		struct lruvec *lruvec;
		int i;

		mem_cgroup_flush_stats_ratelimited(sc->memcg);
		lruvec = mem_cgroup_lruvec(sc->memcg, NODE_DATA(sc->nid));
		for (pages = 0, i = 0; i < NR_LRU_LISTS; i++)
			pages += lruvec_page_state_local(lruvec,
							 NR_LRU_BASE + i);
		pages += lruvec_page_state_local(
			lruvec, NR_SLAB_RECLAIMABLE_B) >> PAGE_SHIFT;
		pages += lruvec_page_state_local(
			lruvec, NR_SLAB_UNRECLAIMABLE_B) >> PAGE_SHIFT;
	} else
#endif
		pages = node_present_pages(sc->nid);

	max_nodes = pages >> (XA_CHUNK_SHIFT - 3);

	if (nodes <= max_nodes)
		return 0;
	return nodes - max_nodes;
}

static enum lru_status shadow_lru_isolate(struct list_head *item,
					  struct list_lru_one *lru,
					  spinlock_t *lru_lock,
					  void *arg) __must_hold(lru_lock)
{
	struct xa_node *node = container_of(item, struct xa_node, private_list);
	struct address_space *mapping;
	int ret;

	/*
	 * Page cache insertions and deletions synchronously maintain
	 * the shadow node LRU under the i_pages lock and the
	 * lru_lock.  Because the page cache tree is emptied before
	 * the inode can be destroyed, holding the lru_lock pins any
	 * address_space that has nodes on the LRU.
	 *
	 * We can then safely transition to the i_pages lock to
	 * pin only the address_space of the particular node we want
	 * to reclaim, take the node off-LRU, and drop the lru_lock.
	 */

	mapping = container_of(node->array, struct address_space, i_pages);

	/* Coming from the list, invert the lock order */
	if (!xa_trylock(&mapping->i_pages)) {
		spin_unlock_irq(lru_lock);
		ret = LRU_RETRY;
		goto out;
	}

	/* For page cache we need to hold i_lock */
	if (mapping->host != NULL) {
		if (!spin_trylock(&mapping->host->i_lock)) {
			xa_unlock(&mapping->i_pages);
			spin_unlock_irq(lru_lock);
			ret = LRU_RETRY;
			goto out;
		}
	}

	list_lru_isolate(lru, item);
	__dec_lruvec_kmem_state(node, WORKINGSET_NODES);

	spin_unlock(lru_lock);

	/*
	 * The nodes should only contain one or more shadow entries,
	 * no pages, so we expect to be able to remove them all and
	 * delete and free the empty node afterwards.
	 */
	if (WARN_ON_ONCE(!node->nr_values))
		goto out_invalid;
	if (WARN_ON_ONCE(node->count != node->nr_values))
		goto out_invalid;
	xa_delete_node(node, workingset_update_node);
	__inc_lruvec_kmem_state(node, WORKINGSET_NODERECLAIM);

out_invalid:
	xa_unlock_irq(&mapping->i_pages);
	if (mapping->host != NULL) {
		if (mapping_shrinkable(mapping))
			inode_add_lru(mapping->host);
		spin_unlock(&mapping->host->i_lock);
	}
	ret = LRU_REMOVED_RETRY;
out:
	cond_resched();
	spin_lock_irq(lru_lock);
	return ret;
}

static unsigned long scan_shadow_nodes(struct shrinker *shrinker,
				       struct shrink_control *sc)
{
	/* list_lru lock nests inside the IRQ-safe i_pages lock */
	return list_lru_shrink_walk_irq(&shadow_nodes, sc, shadow_lru_isolate,
					NULL);
}

static struct shrinker workingset_shadow_shrinker = {
	.count_objects = count_shadow_nodes,
	.scan_objects = scan_shadow_nodes,
	.seeks = 0, /* ->count reports only fully expendable nodes */
	.flags = SHRINKER_NUMA_AWARE | SHRINKER_MEMCG_AWARE,
};

/*
 * Our list_lru->lock is IRQ-safe as it nests inside the IRQ-safe
 * i_pages lock.
 */
static struct lock_class_key shadow_nodes_key;

static int __init workingset_init(void)
{
	unsigned int max_order;
	int ret;

	BUILD_BUG_ON(BITS_PER_LONG < EVICTION_SHIFT);
	/*
	 * Calculate the eviction bucket size to cover the longest
	 * actionable refault distance, which is currently half of
	 * memory (totalram_pages/2). However, memory hotplug may add
	 * some more pages at runtime, so keep working with up to
	 * double the initial memory by using totalram_pages as-is.
	 */
	max_order = fls_long(totalram_pages() - 1);
	if (max_order > EVICTION_BITS)
		bucket_order = max_order - EVICTION_BITS;
	pr_info("workingset: timestamp_bits=%d max_order=%d bucket_order=%u\n",
		EVICTION_BITS, max_order, bucket_order);
#ifdef CONFIG_LRU_GEN
	if (max_order > LRU_GEN_EVICTION_BITS)
		lru_gen_bucket_order = max_order - LRU_GEN_EVICTION_BITS;
	pr_info("workingset: lru_gen_timestamp_bits=%d lru_gen_bucket_order=%u\n",
		LRU_GEN_EVICTION_BITS, lru_gen_bucket_order);
#endif

	ret = prealloc_shrinker(&workingset_shadow_shrinker, "mm-shadow");
	if (ret)
		goto err;
	ret = __list_lru_init(&shadow_nodes, true, &shadow_nodes_key,
			      &workingset_shadow_shrinker);
	if (ret)
		goto err_list_lru;
	register_shrinker_prepared(&workingset_shadow_shrinker);
	return 0;
err_list_lru:
	free_prealloced_shrinker(&workingset_shadow_shrinker);
err:
	return ret;
}
module_init(workingset_init);
