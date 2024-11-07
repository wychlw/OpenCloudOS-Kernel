// SPDX-License-Identifier: GPL-2.0
/*
 * linux/kernel/tkernel/killblock/kill_block.c
 *
 * Copyright (C) 2023  Hongbo Li <herberthbli@tencent.com>
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/glob.h>
#include <linux/cgroup.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cgroup.h>
#include <linux/kill_hook.h>
#include "kill_block.h"

int sysctl_sig_kill_block;
static atomic64_t kb_cnt_root = ATOMIC64_INIT(0);
static atomic64_t kb_cnt_child = ATOMIC64_INIT(0);
static atomic_t kb_rule_cnt = ATOMIC_INIT(0);
static struct proc_dir_entry    *kb_proc_dir;
static struct proc_dir_entry *whitelist_entry;
static struct proc_dir_entry *stat_entry;
static struct ctl_table_header *kb_sysctl_header;
static LIST_HEAD(whitelist_list);
static DEFINE_RWLOCK(whitelist_lock);
static struct kill_hook kill_block_hook;

static ssize_t whitelist_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	char cmd[KILL_BLOCK_CMD_LEN], _str[KILL_BLOCK_CMD_LEN];
	char *token[4], *str;
	int cnt, i = 0;
	struct kb_whitelist_rule *rule, *tmp;

	memset(cmd, 0, KILL_BLOCK_CMD_LEN);

	cnt = min_t(size_t, count, KILL_BLOCK_CMD_LEN - 1);
	if (strncpy_from_user(cmd, ubuf, cnt) < 0)
		return -EINVAL;

	if (strlen(cmd) < 1)
		return -EINVAL;

	strcpy(_str, cmd);
	str = _str;
	str[cnt - 1] = '\0';

	i = 0;
	while ((token[i] = strsep(&str, " ")) != NULL) {
		if (!strlen(token[i]))
			break;
		i++;
		if (i == 4)
			break;
	}

	if (i == 1) {
		if (!strcmp(token[0], "flush")) {
			write_lock_bh(&whitelist_lock);
			list_for_each_entry_safe(rule, tmp, &whitelist_list,
						 node) {
				list_del(&rule->node);
				kfree(rule);
			}
			write_unlock_bh(&whitelist_lock);
			atomic_set(&kb_rule_cnt, 0);
			return cnt;
		}
		return -EINVAL;
	} else if (i != 4) {
		return -EINVAL;
	}

	if (!strcmp(token[0], "add")) {
		if (atomic_read(&kb_rule_cnt) >= KILL_BLOCK_RULES_MAX_CNT)
			return -ENOMEM;
		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return -ENOMEM;

		cnt = min_t(size_t, TASK_COMM_LEN - 1, strlen(token[1]));
		strncpy(rule->src_comm, token[1], cnt);
		rule->src_comm[cnt] = '\0';
		cnt = min_t(size_t, TASK_COMM_LEN - 1, strlen(token[2]));
		strncpy(rule->dst_comm, token[2], cnt);
		rule->dst_comm[cnt] = '\0';
		cnt = min_t(size_t, KILL_BLOCK_CGRP_LEN - 1, strlen(token[3]));
		strncpy(rule->dst_cgrp, token[3], cnt);
		rule->dst_cgrp[cnt] = '\0';
		write_lock_bh(&whitelist_lock);
		list_for_each_entry(tmp, &whitelist_list, node) {
			if (!strcasecmp(tmp->src_comm, rule->src_comm) &&
			    !strcasecmp(tmp->dst_comm, rule->dst_comm) &&
			    !strcasecmp(tmp->dst_cgrp, rule->dst_cgrp)) {
				write_unlock_bh(&whitelist_lock);
				kfree(rule);
				return -EEXIST;
			}
		}
		list_add(&rule->node, &whitelist_list);
		write_unlock_bh(&whitelist_lock);
		atomic_inc(&kb_rule_cnt);
	} else if (!strcmp(token[0], "del")) {
		write_lock_bh(&whitelist_lock);
		list_for_each_entry_safe(rule, tmp, &whitelist_list, node) {
			if (!strcasecmp(rule->src_comm, token[1]) &&
			    !strcasecmp(rule->dst_comm, token[2]) &&
			    !strcasecmp(rule->dst_cgrp, token[3])) {
				list_del(&rule->node);
				kfree(rule);
				atomic_dec(&kb_rule_cnt);
				break;
			}
		}
		write_unlock_bh(&whitelist_lock);
	} else {
		return -EINVAL;
	}

	return count;
}

static void *whitelist_seq_start(struct seq_file *m, loff_t *pos)
{
	read_lock_bh(&whitelist_lock);
	return seq_list_start_head(&whitelist_list, *pos);
}

static void *whitelist_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &whitelist_list, pos);
}

static void whitelist_seq_stop(struct seq_file *m, void *v)
{
	read_unlock_bh(&whitelist_lock);
}

static int whitelist_seq_show(struct seq_file *m, void *v)
{
	struct kb_whitelist_rule *rule;

	if (v == &whitelist_list) {
		seq_puts(m, "src_comm\tdst_comm\tdst_cgrp\n");
	} else {
		rule = list_entry(v, struct kb_whitelist_rule, node);
		seq_printf(m, "%s\t%s\t%s\n",
			   rule->src_comm, rule->dst_comm, rule->dst_cgrp);
	}

	return 0;
}

static const struct seq_operations whitelist_seq_ops = {
	.start  = whitelist_seq_start,
	.next   = whitelist_seq_next,
	.stop   = whitelist_seq_stop,
	.show   = whitelist_seq_show,
};

static int whitelist_seq_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &whitelist_seq_ops);
}

static const struct proc_ops whitelist_fops = {
	.proc_open	= whitelist_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= whitelist_write,
	.proc_release	= seq_release,
};

static int stat_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "root %lld\n", atomic64_read(&kb_cnt_root));
	seq_printf(m, "child %lld\n", atomic64_read(&kb_cnt_child));
	atomic64_set(&kb_cnt_root, 0);
	atomic64_set(&kb_cnt_child, 0);
	return 0;
}

static int stat_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stat_proc_show, NULL);
}

static const struct proc_ops stat_fops = {
	.proc_open	= stat_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* get the length of podid, not include '\0' */
static unsigned int kill_block_get_podid_len(char *podid_start)
{
	unsigned int podid_len;
	char *podid_end;

	if (!podid_start)
		return 0;

	podid_end = strchr(podid_start, '/');
	if (podid_end)
		podid_len = podid_end - podid_start;
	else
		podid_len = strlen(podid_start);

	return podid_len;
}

int kill_block_whitelist_match(struct task_struct *p, int sig,
			       char *src_cgrp_path, char *src_cgrp_name,
			       char *dst_cgrp_path, char *dst_cgrp_name)
{
	struct kb_whitelist_rule *rule;
	char *src_podid_start, *dst_podid_start;
	unsigned int src_podid_len, dst_podid_len;
	int match = 1;

	if (!sysctl_sig_kill_block) {
		match = 0;
		goto out;
	}

	/* check whether the src and dst cgrp are pods */
	if (glob_match("*kubepods*", src_cgrp_path) &&
	    glob_match("*kubepods*", dst_cgrp_path)) {
		src_podid_start = strstr(src_cgrp_path, "/pod");
		dst_podid_start = strstr(dst_cgrp_path, "/pod");
		if (!src_podid_start || !dst_podid_start)
			goto check_rule;

		src_podid_start++;
		dst_podid_start++;
		src_podid_len = kill_block_get_podid_len(src_podid_start);
		dst_podid_len = kill_block_get_podid_len(dst_podid_start);
		if (src_podid_len != dst_podid_len)
			goto check_rule;

		/* src and dst are in a same pod */
		if (!strncmp(src_podid_start, dst_podid_start, src_podid_len)) {
			match = 0;
			goto out;
		}
	}

check_rule:
	read_lock_bh(&whitelist_lock);
	if (list_empty(&whitelist_list))
		goto out_unlock;

	list_for_each_entry(rule, &whitelist_list, node) {
		if (glob_match(rule->src_comm, current->comm) &&
		    glob_match(rule->dst_comm, p->comm) &&
		    (glob_match(rule->dst_cgrp, dst_cgrp_name) ||
		     glob_match(rule->dst_cgrp, dst_cgrp_path))) {
			match = 0;
			break;
		}
	}
out_unlock:
	read_unlock_bh(&whitelist_lock);
out:
	if (match) {
		if (glob_match("*kubepods*", dst_cgrp_path))
			atomic64_inc(&kb_cnt_child);
		else
			atomic64_inc(&kb_cnt_root);

		if (sysctl_sig_kill_block == 2)
			pr_info_ratelimited(
				"block signal %d from [%d]%s to [%d]%s; src_cgrp_path %s src_cgrp_name %s -> dst_cgrp_path %s dst_cgrp_name %s\n",
				sig, current->pid, current->comm,
				p->pid, p->comm, src_cgrp_path, src_cgrp_name,
				dst_cgrp_path, dst_cgrp_name);
	}

	return match;
}

static int kill_block_hook_func(int sig, struct kernel_siginfo *info, struct task_struct *t)
{
#define KILL_BLOCK_CGRP_PATH_LEN 256
#define KILL_BLOCK_CGRP_NAME_LEN 128
	struct cgroup *src_cgrp, *dst_cgrp;
	char src_cgrp_path[KILL_BLOCK_CGRP_PATH_LEN];
	char dst_cgrp_path[KILL_BLOCK_CGRP_PATH_LEN];
	char src_cgrp_name[KILL_BLOCK_CGRP_NAME_LEN];
	char dst_cgrp_name[KILL_BLOCK_CGRP_NAME_LEN];
	int ret = 0;
	int block = 0;

	if (sig != SIGKILL && sig != SIGTERM)
		return 0;

	rcu_read_lock();
	src_cgrp = task_cgroup(current, cpu_cgrp_subsys.id);
	dst_cgrp = task_cgroup(t, cpu_cgrp_subsys.id);
	if (src_cgrp && dst_cgrp) {
		cgroup_path(src_cgrp, src_cgrp_path, KILL_BLOCK_CGRP_PATH_LEN);
		cgroup_path(dst_cgrp, dst_cgrp_path, KILL_BLOCK_CGRP_PATH_LEN);
		cgroup_name(src_cgrp, src_cgrp_name, KILL_BLOCK_CGRP_NAME_LEN);
		cgroup_name(dst_cgrp, dst_cgrp_name, KILL_BLOCK_CGRP_NAME_LEN);

		block = kill_block_whitelist_match(
			t, sig, src_cgrp_path, src_cgrp_name,
			dst_cgrp_path, dst_cgrp_name);
		if (block)
			ret = -EPERM;
	}
	rcu_read_unlock();

	return ret;
}

static int register_kill_block_hook(void)
{
	kill_block_hook.fn = kill_block_hook_func;
	kill_block_hook.priority = KILL_HOOK_PRIORITY_LOW;

	return register_kill_hook(&kill_block_hook);
}

static void unregister_kill_block_hook(void)
{
	unregister_kill_hook(&kill_block_hook);
}

static struct ctl_table kb_sysctl_table[] = {
	{
		.procname       = "sig_kill_block",
		.data           = &sysctl_sig_kill_block,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
	},
	{ }
};

static int __init kill_block_mod_init(void)
{
	int ret;

	kb_sysctl_header = register_sysctl("kernel", kb_sysctl_table);
	if (!kb_sysctl_header) {
		pr_err("Couldn't register sysctl table\n");
		goto out;
	}

	kb_proc_dir = proc_mkdir(KILL_BLOCK_DIR, NULL);
	if (!kb_proc_dir) {
		pr_err("Couldn't create kill_block proc dir\n");
		goto out_dir;
	}

	whitelist_entry = proc_create("whitelist",
				      0, kb_proc_dir, &whitelist_fops);
	if (!whitelist_entry) {
		pr_err("Couldn't create whitelist proc entry\n");
		goto out_entry;
	}

	stat_entry = proc_create("stat", 0, kb_proc_dir, &stat_fops);
	if (!stat_entry) {
		pr_err("Couldn't create stat proc entry\n");
		goto out_entry;
	}

	ret = register_kill_block_hook();
	if (ret) {
		pr_err("Couldn't register kill_block hook\n");
		goto out_entry;
	}

	pr_info("signal kill block module init\n");
	return 0;

out_entry:
	remove_proc_subtree(KILL_BLOCK_DIR, NULL);
out_dir:
	unregister_sysctl_table(kb_sysctl_header);
out:
	return -ENOMEM;
}

static void __exit kill_block_mod_exit(void)
{
	struct kb_whitelist_rule *rule, *tmp;

	unregister_kill_block_hook();

	remove_proc_subtree(KILL_BLOCK_DIR, NULL);
	write_lock_bh(&whitelist_lock);
	list_for_each_entry_safe(rule, tmp, &whitelist_list, node) {
		list_del(&rule->node);
		kfree(rule);
	}
	write_unlock_bh(&whitelist_lock);
	unregister_sysctl_table(kb_sysctl_header);

	pr_info("signal kill block module exit\n");
}

module_init(kill_block_mod_init);
module_exit(kill_block_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("herberthbli");
MODULE_DESCRIPTION("kill_block_mod");
MODULE_VERSION("1.3");
