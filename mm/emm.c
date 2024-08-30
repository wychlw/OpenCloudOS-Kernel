// SPDX-License-Identifier: GPL-2.0

#include <linux/compiler.h>
#include <linux/mm_types.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/emm.h>

#include <asm-generic/bug.h>

struct emm_memcg_ops *__emm_memcg_ops __read_mostly;

static int _emm_do_memcg_init(struct mem_cgroup *memcg)
{
	struct emm_memcg_ops *ops;

	lockdep_assert_held(&cgroup_mutex);

	ops = READ_ONCE(__emm_memcg_ops);

	if (ops)
		return ops->init(memcg);

	return 0;
}

static void _emm_do_memcg_exit(struct mem_cgroup *memcg)
{
	struct emm_memcg_ops *ops;

	lockdep_assert_held(&cgroup_mutex);

	ops = READ_ONCE(__emm_memcg_ops);

	if (ops)
		ops->exit(memcg);
}

int emm_memcg_init(struct mem_cgroup *memcg)
{
	return _emm_do_memcg_init(memcg);
}

void emm_memcg_exit(struct mem_cgroup *memcg)
{
	/* cgroup should be dying */
	WARN_ON_ONCE(!css_is_dying(&memcg->css));

	_emm_do_memcg_exit(memcg);
}

int emm_init(struct emm_memcg_ops *ops)
{
	int ret = 0;
	struct mem_cgroup *memcg;

	if (!root_mem_cgroup) {
		pr_err("Memory Cgroup is disabled, EMM init aborting.");
		return -EINVAL;
	}

	/*
	 * Going to iterate through exiting cgroups,
	 * also use it to protect __emm_memcg_ops
	 */
	cgroup_lock();

	if (READ_ONCE(__emm_memcg_ops)) {
		ret = -EBUSY;
		goto out;
	}

	WRITE_ONCE(__emm_memcg_ops, ops);

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		_emm_do_memcg_init(memcg);
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)));

out:
	cgroup_unlock();

	return ret;
}
EXPORT_SYMBOL(emm_init);

int emm_exit(void)
{
	int ret = 0;
	struct mem_cgroup *memcg;

	/*
	 * Going to iterate through exiting cgroups,
	 * also use it to protect __emm_memcg_ops
	 */
	cgroup_lock();

	if (!READ_ONCE(__emm_memcg_ops)) {
		ret = -EINVAL;
		goto out;
	}

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		_emm_do_memcg_exit(memcg);
	} while ((memcg = mem_cgroup_iter(NULL, memcg, NULL)));

	WRITE_ONCE(__emm_memcg_ops, NULL);
out:
	cgroup_unlock();

	return ret;
}
EXPORT_SYMBOL(emm_exit);
