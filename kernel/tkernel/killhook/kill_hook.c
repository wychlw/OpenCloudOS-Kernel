// SPDX-License-Identifier: GPL-2.0
/*
 * kill hook
 *
 * Copyright (c) 2024 Tencent. All Rights reserved.
 * Author: Yongliang Gao <leonylgao@tencent.com>
 */

#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/kill_hook.h>

static DEFINE_SPINLOCK(kill_hook_lock);
static LIST_HEAD(kill_hook_list);

int register_kill_hook(struct kill_hook *hook)
{
	struct kill_hook *tmp;

	if (!hook || !hook->fn)
		return -EINVAL;

	if (hook->priority < KILL_HOOK_PRIORITY_LOW ||
		hook->priority > KILL_HOOK_PRIORITY_HIGH)
		return -EINVAL;

	spin_lock(&kill_hook_lock);
	list_for_each_entry(tmp, &kill_hook_list, node) {
		if (hook == tmp) {
			spin_unlock(&kill_hook_lock);
			return -EEXIST;
		}
	}

	list_for_each_entry(tmp, &kill_hook_list, node) {
		if (hook->priority < tmp->priority) {
			list_add_rcu(&hook->node, &tmp->node);
			spin_unlock(&kill_hook_lock);
			return 0;
		}
	}
	list_add_rcu(&hook->node, &kill_hook_list);
	spin_unlock(&kill_hook_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(register_kill_hook);

int unregister_kill_hook(struct kill_hook *hook)
{
	struct kill_hook *tmp;

	if (!hook || !hook->fn)
		return -EINVAL;

	spin_lock(&kill_hook_lock);
	list_for_each_entry(tmp, &kill_hook_list, node) {
		if (hook == tmp) {
			list_del_rcu(&hook->node);
			spin_unlock(&kill_hook_lock);
			synchronize_rcu();
			return 0;
		}
	}
	spin_unlock(&kill_hook_lock);

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(unregister_kill_hook);

int call_kill_hook(int sig, struct kernel_siginfo *info, struct task_struct *t)
{
	int ret = 0;
	struct kill_hook *hook;

	rcu_read_lock();
	list_for_each_entry_rcu(hook, &kill_hook_list, node) {
		if (hook->fn) {
			ret = hook->fn(sig, info, t);
			if (ret) {
				rcu_read_unlock();
				return ret;
			}
		}
	}
	rcu_read_unlock();

	return ret;
}
