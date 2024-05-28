/* SPDX-License-Identifier: GPL-2.0-only
 *
 * make mbuf can be used by net namespace
 *
 * Author: mengensun <mengensun@tencent.com>
 * Copyright (C) 2024 Tencent, Inc
 */
#ifndef __NETNS_MBUF
#define __NETNS_MBUF

#include<linux/proc_fs.h>
#include<linux/mbuf.h>

#ifdef CONFIG_NETNS_MBUF
struct net_mbuf {
	struct proc_dir_entry	*twatcher;
	struct proc_dir_entry	*log;
	struct mbuf_slot	*slot;
};

int inet_mbuf_init(void);
void inet_mbuf_exit(void);
ssize_t net_mbuf_print(struct net *net, const char *fmt, ...);
#else
static __always_inline int inet_mbuf_init(void) {return 0; }
static __always_inline void inet_mbuf_exit(void) {}
static __always_inline ssize_t net_mbuf_print(struct net *net, const char *fmt, ...) {return 0; };
#endif
#endif
