#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/cpu.h>
#include <linux/hook_frame.h>
#include <linux/slab.h>
#include "list.h"
#include "hook_info.h"
#include "module.h"

#define HOOKINFO_WAKEUP_LENGTH	1
static struct proc_dir_entry *hook_dir_entry;


unsigned long percpu_total_num(long __percpu *num)
{
	int cpu;
	unsigned long total = 0;

	get_online_cpus();
	for_each_cpu((cpu), hook_cpu_mask)
		total += *per_cpu_ptr(num, cpu);
	put_online_cpus();

	return total;
}

unsigned long percpu_total_num_atomic64(atomic64_t __percpu *num)
{
	int cpu;
	unsigned long total = 0;

	get_online_cpus();
	for_each_cpu((cpu), hook_cpu_mask)
		total += atomic64_read(per_cpu_ptr(num, cpu));
	put_online_cpus();

	return total;
}

int clear_hookinfo_list(struct hook_info *info)
{
	struct list_head *info_head, *tmp;
	int cpu;
	bool try = true;

	get_online_cpus();
	for_each_possible_cpu(cpu) {
		struct list_head *list = per_cpu_ptr(info->lists, cpu);
retry:
		list_for_each_safe(info_head, tmp, list) {
			if (info->extra_free_func)
				info->extra_free_func(info_head);
			list_del(info_head);
			kfree(info_head);
		}

		if (try) {
			list = &info->list;
			try = false;
			goto retry;
		}
	}
	put_online_cpus();
	return 0;
}

void clear_cpu_list(void)
{
	int i = 0;
	struct hook_info *info;

	for (i = 0; hook_info_array[i].dir; i++) {
		info = &hook_info_array[i];
		clear_hookinfo_list(info);
	}
}

void hookinfo_list_in(struct list_head *new, int type)
{
	struct list_head *list = this_cpu_ptr(hook_info_array[type].lists);
	raw_spinlock_t *plock = this_cpu_ptr(hook_info_array[type].lock);

	raw_spin_lock_bh(plock);
	list_add_tail(new, list);
	raw_spin_unlock_bh(plock);
	atomic64_inc(this_cpu_ptr(hook_info_array[type].info_num));

	if (wq_has_sleeper(&hook_info_array[type].wait_queue))
		wake_up_interruptible_poll(&hook_info_array[type].wait_queue, POLLIN);
}

static ssize_t fops_read(struct file *file, char __user *buf,
						size_t count, loff_t *ppos)
{
	ssize_t len = 0;
	struct hook_info *info = pde_data(file_inode(file));

	if (file->hook_flags != HOOK_INFO_READ_FLAG)
		return 0;

	mutex_lock(&info->readlock);
	len = hook_info_read(info, file, buf, count, ppos);
	mutex_unlock(&info->readlock);
	return len;
}

static int fops_open(struct inode *inode, struct file *file)
{
	return try_module_get(THIS_MODULE) ? 0 : -ENOENT;
}

static unsigned int fops_poll(struct file *file, poll_table *wait)
{
	struct hook_info *info = pde_data(file_inode(file));
	unsigned int mask = 0;

	if (file->hook_flags != HOOK_INFO_READ_FLAG)
		return POLLERR;

	poll_wait(file, &info->wait_queue, wait);
	if (percpu_total_num_atomic64(info->info_num) > (sysctl_poll_wakeup_length & SYSCTL_VALID_MASK))
		mask = POLLIN;
	return mask;
}

static int fops_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;
}

static const struct proc_ops hook_info_fops = {
	.proc_open           = fops_open,
	.proc_release        = fops_release,
	.proc_read           = fops_read,
	.proc_poll           = fops_poll,
	.proc_lseek         = noop_llseek,
};

static ssize_t fops_statistics_read(struct file *file, char __user *buf,
						size_t count, loff_t *ppos)
{
	int ret, i;
	struct statistics_info statistics_information = {};
	unsigned int copied = sizeof(struct statistics_info);

	if (count < copied)
		return 0;

	for (i = 0; hook_info_array[i].dir; i++) {
		statistics_information.info_entry[i].type = hook_info_array[i].type;
		statistics_information.info_entry[i].discard =
			percpu_total_num(hook_info_array[i].drop_stats);
		statistics_information.info_entry[i].total =
			percpu_total_num(hook_info_array[i].total_numb);
	}

	statistics_information.version = STATISTIC_VERSION;
	ret = copy_to_user(buf, &statistics_information, copied);
	return copied - ret;
}

static const struct proc_ops stats_info_fops = {
	.proc_open           = fops_open,
	.proc_release        = fops_release,
	.proc_read           = fops_statistics_read,
	.proc_lseek         = noop_llseek,
};

int hook_info_proc_create(void)
{
	int i, ret;

	hook_dir_entry = proc_mkdir("aegis", NULL);
	if (!hook_dir_entry) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; hook_info_array[i].dir; i++) {
		if (!proc_create_data(hook_info_array[i].dir, 0400, hook_dir_entry, &hook_info_fops, (void *)&hook_info_array[i])) {
			ret = -ENOMEM;
			goto err;
		}
		mutex_init(&hook_info_array[i].readlock);
	}

	if (!proc_create("statistics_info", 0400, hook_dir_entry, &stats_info_fops)) {
		ret = -ENOMEM;
		goto err;
	}

	return 0;
err:
	proc_remove(hook_dir_entry);
out:
	return ret;
}

void hook_info_proc_delete(void)
{
	proc_remove(hook_dir_entry);
}

int hook_info_percpu_create(void)
{
	int i, cpu, ret;

	for (i = 0; hook_info_array[i].dir; i++) {
		hook_info_array[i].lists = alloc_percpu(struct list_head);
		hook_info_array[i].lock = alloc_percpu(raw_spinlock_t);
		hook_info_array[i].info_num = alloc_percpu(atomic64_t);
		hook_info_array[i].drop_stats = alloc_percpu(unsigned long);
		hook_info_array[i].total_numb = alloc_percpu(unsigned long);
		if (!hook_info_array[i].lists || !hook_info_array[i].info_num || !hook_info_array[i].total_numb
			|| !hook_info_array[i].drop_stats || !hook_info_array[i].lock) {
			printk(KERN_ERR "security: failed to allocate percpu data\n");
			ret = -ENOMEM;
			goto err;
		}
		get_online_cpus();
		for_each_possible_cpu(cpu) {
			struct list_head *list = per_cpu_ptr(hook_info_array[i].lists, cpu);
			raw_spinlock_t *plock = per_cpu_ptr(hook_info_array[i].lock, cpu);

			INIT_LIST_HEAD(list);
			raw_spin_lock_init(plock);
			atomic64_set(per_cpu_ptr(hook_info_array[i].info_num, cpu), 0);
			*per_cpu_ptr(hook_info_array[i].drop_stats, cpu) = 0;
			*per_cpu_ptr(hook_info_array[i].total_numb, cpu) = 0;
		}
		put_online_cpus();

		INIT_LIST_HEAD(&hook_info_array[i].list);
	}
	return 0;
err:
	for (; i >= 0; i--) {
		free_percpu(hook_info_array[i].lists);
		free_percpu(hook_info_array[i].lock);
		free_percpu(hook_info_array[i].info_num);
		free_percpu(hook_info_array[i].drop_stats);
		free_percpu(hook_info_array[i].total_numb);
	}
	return ret;
}

int hook_info_percpu_delete(void)
{
	int i;

	clear_cpu_list();
	for (i = 0; hook_info_array[i].dir; i++) {
		free_percpu(hook_info_array[i].lists);
		free_percpu(hook_info_array[i].lock);
		free_percpu(hook_info_array[i].info_num);
		free_percpu(hook_info_array[i].drop_stats);
		free_percpu(hook_info_array[i].total_numb);
	}
	return 0;
}

int hook_info_func_register(void)
{
	int i, type, ret;

	for (i = 0; hook_info_array[i].dir; i++) {
		type = hook_info_array[i].type;
		if (!hook_func_array[type])
			hook_func_array[type] = hook_info_array[i].hook_func_addr;
		else {
			ret = -EBUSY;
			goto err;
		}
	}
	return 0;
err:
	for (i = i - 1; i >= 0; i++) {
		type = hook_info_array[i].type;
		hook_func_array[type] = 0;
	}
	return ret;
}

void hook_info_func_unregister(void)
{
	int i, type;

	for (i = 0; hook_info_array[i].dir; i++) {
		type = hook_info_array[i].type;
		hook_func_array[type] = 0;
	}
}

void init_wait_queue(void)
{
	int i;

	for (i = 0; hook_info_array[i].dir; i++)
		init_waitqueue_head(&hook_info_array[i].wait_queue);
}

int list_module_init(void)
{

	int ret;

	ret = hook_info_percpu_create();
	if (ret)
		goto list_err;

	ret = hook_info_proc_create();
	if (ret)
		goto proc_err;

	ret = hook_info_func_register();
	if (ret)
		goto func_err;

	init_wait_queue();

	return 0;

func_err:
	hook_info_proc_delete();
proc_err:
	hook_info_percpu_delete();
list_err:
	return ret;

}

void list_module_exit(void)
{
	hook_info_func_unregister();
	hook_info_proc_delete();
	hook_info_percpu_delete();
}
