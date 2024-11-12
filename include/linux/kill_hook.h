// SPDX-License-Identifier: GPL-2.0
/*
 * kill hook interface
 *
 * Copyright (c) 2024 Tencent. All Rights reserved.
 * Author: Yongliang Gao <leonylgao@tencent.com>
 */
#ifndef _LINUX_KILL_HOOK_H
#define _LINUX_KILL_HOOK_H

#include <linux/list.h>
#include <linux/signal.h>
#include <linux/sched.h>

enum kill_hook_priority {
	KILL_HOOK_PRIORITY_LOW,
	KILL_HOOK_PRIORITY_NORMAL,
	KILL_HOOK_PRIORITY_HIGH,
};

typedef int (*kill_hook_fn)(int sig, struct kernel_siginfo *info, struct task_struct *t);

struct kill_hook {
	int priority;
	kill_hook_fn fn;
	struct list_head node;
};

#ifdef CONFIG_TKERNEL_KILL_HOOK
int register_kill_hook(struct kill_hook *hook);
int unregister_kill_hook(struct kill_hook *hook);
int call_kill_hook(int sig, struct kernel_siginfo *info, struct task_struct *t);
#else
static inline int register_kill_hook(struct kill_hook *hook) { return 0; }
static inline int unregister_kill_hook(struct kill_hook *hook) { return 0; }
static inline int call_kill_hook(int sig, struct kernel_siginfo *info, struct task_struct *t) { return 0; }
#endif

#endif
