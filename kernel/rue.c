// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/blk-cgroup.h>
#include <linux/rue.h>

bool rue_installed;
DEFINE_PER_CPU(long, nr_rue_calls);
struct rue_ops *rue_mod_ops;
DEFINE_MUTEX(rue_mutex);

static bool rue_used(void)
{
	int cpu;
	long total = 0;

	for_each_possible_cpu(cpu)
		total += per_cpu(nr_rue_calls, cpu);

	pr_info("RUE: cpu %d sees the sum of nr_rue_calls %ld\n",
		smp_processor_id(), total);

	return !!total;
}

static int check_net_patch_state(struct rue_ops *ops, bool state)
{
#ifdef CONFIG_CGROUP_NET_CLASSID
	if (state && !ops->net)
		return -EINVAL;

	if (!state)
		sysctl_net_qos_enable = 0;
#endif

	return 0;
}

static int check_mem_patch_state(struct rue_ops *ops, bool state)
{
#ifdef CONFIG_MEMCG
	if (state && !ops->mem)
		return -EINVAL;

	if (!state)
		sysctl_vm_memory_qos = 0;
#endif

	return 0;
}

static int check_io_patch_state(struct rue_ops *ops, bool state)
{
#ifdef CONFIG_BLK_CGROUP
	if (state && !ops->io)
		return -EINVAL;
#endif

	return 0;
}

static int check_patch_state(struct rue_ops *ops)
{
	int ret = 0;
	bool state = !!ops; /* true: patch, false: unpatch */

	ret = check_net_patch_state(ops, state);
	if (ret)
		return ret;

	ret = check_mem_patch_state(ops, state);
	if (ret)
		return ret;

	ret = check_io_patch_state(ops, state);
	if (ret)
		return ret;

	return 0;
}

int register_rue_ops(struct rue_ops *ops)
{
	int ret = 0;

	cpus_read_lock();
	mutex_lock(&rue_mutex);
	if (rue_used()) {
		ret =  -EBUSY;
		pr_warn("RUE: system corrupted, "
			"failed to register rue_ops");
		goto out;
	}
	ret = check_patch_state(ops);
	if (ret)
		goto out;
	WRITE_ONCE(rue_mod_ops, ops);
out:
	WRITE_ONCE(rue_installed, !ret);
	mutex_unlock(&rue_mutex);
	cpus_read_unlock();

	return ret;
}
EXPORT_SYMBOL(register_rue_ops);

int try_unregister_rue_ops(void)
{
	int ret = 0;

	cpus_read_lock();
	mutex_lock(&rue_mutex);
	ret = check_patch_state(NULL);
	if (ret)
		goto out;
	WRITE_ONCE(rue_mod_ops, NULL);
	synchronize_rcu();
	while (rue_used()) {
		if (!cond_resched())
			cpu_relax();
	}
out:
	WRITE_ONCE(rue_installed, !!ret);
	mutex_unlock(&rue_mutex);
	cpus_read_unlock();

	return ret;
}
EXPORT_SYMBOL(try_unregister_rue_ops);

/**
 * rue_io_enabled - whether RUE IO feature enabled
 */
int rue_io_enabled(void)
{
	return sysctl_io_qos_enabled && READ_ONCE(rue_installed);
}
EXPORT_SYMBOL(rue_io_enabled);
