/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KILL_BLOCK_H
#define _LINUX_KILL_BLOCK_H

#include <linux/sched.h>

#define KILL_BLOCK_DIR        "kill_block"
#define KILL_BLOCK_CMD_LEN 128
#define KILL_BLOCK_CGRP_LEN 64
#define KILL_BLOCK_RULES_MAX_CNT 1024

struct kb_whitelist_rule {
	struct list_head node;
	char src_comm[TASK_COMM_LEN];
	char dst_comm[TASK_COMM_LEN];
	char dst_cgrp[KILL_BLOCK_CGRP_LEN];
};

extern int sysctl_sig_kill_block;

#endif /*_LINUX_KILL_BLOCK_H*/
