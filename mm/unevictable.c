// SPDX-License-Identifier: GPL-2.0-only
/*
 * Pin Process Code Section:
 *   echo PID > /proc/unevictable/add_pid
 *   echo PID > /proc/unevictable/del_pid
 *   cat /proc/unevictable/add_pid
 *
 * Copyright (C) 2019 Alibaba
 * Author: Xunlei Pang <xlpang@linux.alibaba.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/types.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/swap.h>
#include <linux/ksm.h>
#include <linux/hugetlb.h>
#include <linux/rbtree.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/pid_namespace.h>

#define PROC_NAME	"unevictable"
#define NAME_BUF	8

struct evict_pids_t {
	struct rb_root root;
};

struct evict_pid_entry {
	struct rb_node node;
	struct list_head list;
	pid_t rootpid;
	u64 start_time;
	struct task_struct *tsk;
	bool done;
};

static void execute_vm_lock(struct work_struct *unused);
static struct evict_pids_t *base_tree;
static DEFINE_MUTEX(pid_mutex);

LIST_HEAD(pid_list);
static int proc_pids_count;

static DECLARE_DELAYED_WORK(evict_work, execute_vm_lock);

struct proc_pids_t {
	struct rb_root proc_pids_tree;
};

/* Called with pid_mutex held always */
static void __remove_entry(struct evict_pid_entry *pid)
{
	if (pid == NULL)
		return;

	rb_erase(&pid->node, &base_tree->root);
	proc_pids_count--;
}

/* should not be in atomic context(i.e. hrtimer) */
static void __evict_pid(struct evict_pid_entry *pid)
{
	struct task_struct *tsk;
	struct mm_struct *mm;

	if (!pid)
		return;

	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid->rootpid, &init_pid_ns);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();

	if (!tsk)
		return;

	if (tsk == pid->tsk && pid->start_time == tsk->start_boottime) {
		mm = get_task_mm(tsk);
		if (mm) {
			if (!(mm->def_flags & VM_LOCKED)) {
				struct vm_area_struct *vma, *prev = NULL;
				vm_flags_t flag;

				VMA_ITERATOR(vmi, mm, 0);
				mmap_write_lock(mm);

				for_each_vma(vmi, vma) {
					if (vma->vm_file &&
						(vma->vm_flags & VM_EXEC) &&
						(vma->vm_flags & VM_READ)) {
						flag = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
						mlock_fixup(&vmi, vma, &prev,
								vma->vm_start, vma->vm_end, flag);
					}
				}

				mmap_write_unlock(mm);
			}
			mmput(mm);
		}
	}
	put_task_struct(tsk);
}

static void evict_pid(pid_t pid)
{
	struct evict_pid_entry *entry, *result;
	struct rb_node *parent = NULL;
	struct rb_node **link;
	struct task_struct *tsk;
	pid_t rootpid;

	if (pid <= 0)
		return;

	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, task_active_pid_ns(current));
	if (tsk) {
		get_task_struct(tsk);
		rootpid = __task_pid_nr_ns(tsk, PIDTYPE_PID, &init_pid_ns);
		put_task_struct(tsk);
	}
	rcu_read_unlock();

	if (!tsk) {
		struct evict_pid_entry *pid_entry, *tmp;

		mutex_lock(&pid_mutex);
		list_for_each_entry_safe(pid_entry, tmp, &pid_list, list) {
			rcu_read_lock();
			tsk = find_task_by_pid_ns(pid_entry->rootpid,
					&init_pid_ns);
			rcu_read_unlock();
			if (!tsk) {
				list_del(&pid_entry->list);
				__remove_entry(pid_entry);
				kfree(pid_entry);
			}
		}
		mutex_unlock(&pid_mutex);
		return;
	}

	result = NULL;
	mutex_lock(&pid_mutex);
	link = &base_tree->root.rb_node;
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct evict_pid_entry, node);
		if (rootpid < entry->rootpid)
			link = &(*link)->rb_left;
		else if (rootpid > entry->rootpid)
			link = &(*link)->rb_right;
		else {
			result = entry;
			break;
		}
	}

	if (result) {
		list_del(&result->list);
		__remove_entry(result);
		mutex_unlock(&pid_mutex);
		__evict_pid(result);
		kfree(result);
	} else {
		mutex_unlock(&pid_mutex);
	}
}

static void unevict_pid(pid_t pid)
{
	struct task_struct *tsk;
	struct evict_pid_entry *entry, *new_entry, *result;
	struct rb_node *parent = NULL;
	struct rb_node **link;
	pid_t rootpid;

	if (pid <= 0)
		return;

	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, task_active_pid_ns(current));
	if (tsk) {
		get_task_struct(tsk);
		rootpid = __task_pid_nr_ns(tsk, PIDTYPE_PID, &init_pid_ns);
		put_task_struct(tsk);
	}
	rcu_read_unlock();

	if (!tsk)
		return;

	new_entry = kzalloc(sizeof(*new_entry), GFP_NOWAIT);
	if (!new_entry)
		return;

	result = NULL;
	mutex_lock(&pid_mutex);
	link = &base_tree->root.rb_node;
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct evict_pid_entry, node);
		if (rootpid < entry->rootpid) {
			link = &(*link)->rb_left;
		} else if (rootpid > entry->rootpid) {
			link = &(*link)->rb_right;
		} else {
			result = entry;
			break;
		}
	}

	if (!result) {
		result = new_entry;
		result->rootpid = rootpid;
		rb_link_node(&result->node, parent, link);
		rb_insert_color(&result->node, &base_tree->root);
		list_add_tail(&result->list, &pid_list);
		proc_pids_count++;
		mutex_unlock(&pid_mutex);
	} else {
		rcu_read_lock();
		tsk = find_task_by_pid_ns(rootpid, &init_pid_ns);
		if (tsk)
			get_task_struct(tsk);
		rcu_read_unlock();
		if (!tsk) {
			list_del(&result->list);
			__remove_entry(result);
			mutex_unlock(&pid_mutex);
			kfree(result);
			kfree(new_entry);
			return;
		} else if (tsk != result->tsk ||
		    result->start_time != tsk->start_boottime) {
			result->done = false;
		}
		put_task_struct(tsk);
		mutex_unlock(&pid_mutex);
		kfree(new_entry);
	}
}

struct add_pid_seq_context {
	int idx;
	int count;
	int pids[0];
};

/*
 * Note there exists a race condition that we may get inconsistent snapshots
 * of pid array if call add_pid_start() more than one round due to users add
 * or delete the pid. However, I think it's acceptable because the pid may
 * still change even we get a consistent snapshot to show.
 */
static void *add_pid_start(struct seq_file *m, loff_t *pos)
{
	struct add_pid_seq_context *ctx = NULL;
	struct evict_pid_entry *pid_entry;
	struct task_struct *tsk;
	struct evict_pid_entry *tmp;
	pid_t pid;

	mutex_lock(&pid_mutex);
	if (*pos >= proc_pids_count)
		goto done;
	ctx = kvzalloc(sizeof(*ctx) + proc_pids_count * sizeof(int), GFP_KERNEL);
	if (unlikely(!ctx))
		goto done;

	if (proc_pids_count > 0) {
		list_for_each_entry_safe(pid_entry, tmp, &pid_list, list) {
			rcu_read_lock();
			tsk = find_task_by_pid_ns(pid_entry->rootpid,
					&init_pid_ns);
			if (tsk) {
				get_task_struct(tsk);
				pid = __task_pid_nr_ns(tsk, PIDTYPE_PID,
						task_active_pid_ns(current));
				put_task_struct(tsk);
			} else {
				pid = -1;
			}
			rcu_read_unlock();

			if (pid != -1) {
				ctx->pids[ctx->count++] = pid;
			} else {
				list_del(&pid_entry->list);
				__remove_entry(pid_entry);
				kfree(pid_entry);
			}
		}
	}
	if (*pos >= ctx->count)
		goto done;
	mutex_unlock(&pid_mutex);
	ctx->idx = *pos;
	m->private = ctx;
	return ctx;
done:
	mutex_unlock(&pid_mutex);
	kvfree(ctx);
	return NULL;
}

static void *add_pid_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct add_pid_seq_context *ctx = p;

	ctx->idx = ++*pos;
	return (ctx->idx < ctx->count) ? ctx : NULL;
}

static void add_pid_stop(struct seq_file *m, void *p)
{
	kvfree(m->private);
	m->private = NULL;
}

static int add_pid_show(struct seq_file *m, void *p)
{
	struct add_pid_seq_context *ctx = p;

	seq_printf(m, "%d", ctx->pids[ctx->idx]);
	seq_putc(m, (ctx->idx == ctx->count - 1) ? '\n' : ',');
	return 0;
}

static const struct seq_operations seq_add_pid_op = {
	.start = add_pid_start,
	.next  = add_pid_next,
	.stop  = add_pid_stop,
	.show  = add_pid_show,
};

static int proc_open_add_pid(struct inode *inode, struct file *file)
{
	return seq_open(file, &seq_add_pid_op);
}

static void execute_vm_lock(struct work_struct *unused)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct evict_pid_entry *result, *tmp;
	pid_t rootpid;

	if (!mutex_trylock(&pid_mutex)) {
		goto out;
	}

	if (proc_pids_count <= 0) {
		mutex_unlock(&pid_mutex);
		goto out;
	}

	list_for_each_entry_safe(result, tmp, &pid_list, list) {
		rootpid = result->rootpid;
		if (result->done || rootpid <= 0)
			continue;

		rcu_read_lock();
		tsk = find_task_by_pid_ns(rootpid, &init_pid_ns);
		if (tsk)
			get_task_struct(tsk);
		rcu_read_unlock();
		if (!tsk) {
			list_del(&result->list);
			__remove_entry(result);
			kfree(result);
			continue;
		}

		mm = get_task_mm(tsk);
		if (mm && !(mm->def_flags & VM_LOCKED)) {
			struct vm_area_struct *vma, *prev = NULL;
			vm_flags_t flag;

			VMA_ITERATOR(vmi, mm, 0);
			mmap_write_lock(mm);

			for_each_vma(vmi, vma) {
				if (vma->vm_file &&
					(vma->vm_flags & VM_EXEC) &&
					(vma->vm_flags & VM_READ)) {
					flag = vma->vm_flags & VM_LOCKED_CLEAR_MASK;
					flag |= (VM_LOCKED | VM_LOCKONFAULT);
					mlock_fixup(&vmi, vma, &prev,
							 vma->vm_start, vma->vm_end, flag);
				}
			}

			result->tsk = tsk;
			result->start_time = tsk->start_boottime;
			result->done = true;
			mmap_write_unlock(mm);
		} else {
			list_del(&result->list);
			__remove_entry(result);
			kfree(result);
		}

		if (mm)
			mmput(mm);
		if (tsk)
			put_task_struct(tsk);
	}
	mutex_unlock(&pid_mutex);

out:
	return;
}


static ssize_t proc_write_add_pid(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
	char buf[NAME_BUF];
	int err;
	long pid;
	int ret = count;

	if (count > NAME_BUF - 1) {
		ret = -EINVAL;
		goto out;
	}

	memset(buf, 0, sizeof(buf));
	if (copy_from_user(buf, buffer, count)) {
		ret = -EFAULT;
		goto out;
	}

	err = kstrtol(strstrip(buf), 0, &pid);
	if (err || pid <= 0) {
		ret = -EINVAL;
		goto out;
	} else {
		unevict_pid((pid_t)pid);
		schedule_delayed_work(&evict_work, HZ);
	}

out:
	return ret;
}

static ssize_t proc_write_del_pid(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
	char buf[NAME_BUF];
	int err;
	long pid;
	int ret = count;

	memset(buf, 0, sizeof(buf));
	if (count > NAME_BUF - 1) {
		ret = -EINVAL;
		goto out;
	}

	if (copy_from_user(buf, buffer, count)) {
		ret = -EFAULT;
		goto out;
	}

	err = kstrtol(strstrip(buf), 0, &pid);
	if (err || pid <= 0) {
		ret = -EINVAL;
		goto out;
	} else {
		evict_pid(pid);
	}

out:
	return ret;
}

const static struct proc_ops add_proc_fops = {
	.proc_open  = proc_open_add_pid,
	.proc_read  = seq_read,
	.proc_write = proc_write_add_pid,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release,
};

const static struct proc_ops del_proc_fops = {
	.proc_write = proc_write_del_pid,
};

static int __init unevictable_init(void)
{
	struct proc_dir_entry *monitor_dir, *add_pid_file, *del_pid_file;

	monitor_dir = proc_mkdir(PROC_NAME, NULL);
	if (!monitor_dir)
		goto out;

	add_pid_file = proc_create("add_pid", 0600,
			monitor_dir, &add_proc_fops);
	if (!add_pid_file)
		goto out_dir;

	del_pid_file = proc_create("del_pid", 0600,
			monitor_dir, &del_proc_fops);
	if (!del_pid_file)
		goto out_add_pid;

	base_tree = kzalloc(sizeof(*base_tree), GFP_KERNEL);
	if (!base_tree)
		goto out_del_pid;

	INIT_LIST_HEAD(&pid_list);

	return 0;

	pr_err("unevictpid create proc dir failed\n");

out_del_pid:
	remove_proc_entry("del_pid", monitor_dir);
out_add_pid:
	remove_proc_entry("add_pid", monitor_dir);
out_dir:
	remove_proc_entry(PROC_NAME, NULL);
out:
	return -ENOMEM;
}

module_init(unevictable_init);
