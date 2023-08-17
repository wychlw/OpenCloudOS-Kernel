/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * cls_cgroup.h			Control Group Classifier
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 */

#ifndef _NET_CLS_CGROUP_H
#define _NET_CLS_CGROUP_H

#include <linux/cgroup.h>
#include <linux/hardirq.h>
#include <linux/rcupdate.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/gen_stats.h>

#ifdef CONFIG_CGROUP_NET_CLASSID

#define NET_MSCALE          (1000 * 1000)
#define RATE_UNLIMITED      0
#define TOKEN_CHARGE_TIKES  16
#define WND_DIV_SHIFT       10
#define WND_DIVISOR         (1 << WND_DIV_SHIFT)
#define MAX_NIC_SUPPORT     16

enum {
	CLS_TC_PRIO_HIGH,
	CLS_TC_PRIO_NORMAL,
	CLS_TC_PRIO_MAX = CGROUP_PRIORITY_MAX
};

struct dev_bw_config {
	char *name;
	unsigned long rx_bps_min;
	unsigned long rx_bps_max;
	unsigned long tx_bps_min;
	unsigned long tx_bps_max;
};

struct dev_limit_config {
	char *name;
};

struct cls_token_bucket {
	s64 depth;		/* depth in bytes. */
	s64 max_ticks;		/* bound of time diff. */
	atomic64_t tokens;	/* number of tokens in bytes. */
	atomic64_t t_c;		/* last time we touch it. */
	u64 rate;		/* rate of token generation. */
};

struct cls_cgroup_stats {
	struct gnet_stats_basic_sync bstats;
	struct net_rate_estimator __rcu *est;
	spinlock_t lock;
	atomic64_t dropped;
};

struct cgroup_cls_state {
	struct cgroup_subsys_state css;
	struct cls_cgroup_stats rx_stats;
	struct cls_cgroup_stats tx_stats;
	u32 classid;
	u32 prio;
	struct cls_token_bucket rx_bucket;
	struct cls_token_bucket tx_bucket;
	struct cls_token_bucket rx_dev_bucket[MAX_NIC_SUPPORT];
	struct cls_token_bucket tx_dev_bucket[MAX_NIC_SUPPORT];
	u16 rx_scale;
	u16 rx_dev_scale[MAX_NIC_SUPPORT];
	unsigned long *whitelist_lports;
	unsigned long *whitelist_rports;
};

struct net_cls_module_function {
	int (*read_rx_stat)(struct cgroup_subsys_state *css,
			struct seq_file *sf);
	int (*read_tx_stat)(struct cgroup_subsys_state *css,
			struct seq_file *sf);
	void (*dump_rx_tb)(struct seq_file *m);
	void (*dump_tx_tb)(struct seq_file *m);
	void (*dump_rx_bps_limit_tb)(struct cgroup_subsys_state *css,
				struct seq_file *sf);
	void (*dump_tx_bps_limit_tb)(struct cgroup_subsys_state *css,
				struct seq_file *sf);
	void (*cgroup_set_rx_limit)(struct cls_token_bucket *tb, u64 rate);
	void (*cgroup_set_tx_limit)(struct cls_token_bucket *tb, u64 rate);
	int (*write_rx_bps_minmax)(int ifindex, u64 min, u64 max, int all);
	int (*write_tx_bps_minmax)(int ifindex, u64 min, u64 max, int all);
	int (*write_rx_min_rwnd_segs)(struct cgroup_subsys_state *css,
				  struct cftype *cft, u64 value);
	u64 (*read_rx_min_rwnd_segs)(struct cgroup_subsys_state *css,
				 struct cftype *cft);
	u32 (*cls_cgroup_adjust_wnd)(struct sock *sk, u32 wnd,
				 u32 mss, u16 wscale);
	int (*cls_cgroup_factor)(const struct sock *sk);
	bool (*is_low_prio)(struct sock *sk);
};

extern int sysctl_net_qos_enable;
extern int rx_throttle_all_enabled;
extern int tx_throttle_all_enabled;
extern struct net_cls_module_function netcls_modfunc;
extern struct dev_bw_config bw_config[];
extern struct dev_limit_config limit_bw_config[];
extern int netqos_notifier(struct notifier_block *this,
			   unsigned long event, void *ptr);
extern int p_read_rx_stat(struct cgroup_subsys_state *css,
			struct seq_file *sf);
extern int p_read_tx_stat(struct cgroup_subsys_state *css,
			struct seq_file *sf);
extern void p_dump_rx_tb(struct seq_file *m);
extern void p_dump_tx_tb(struct seq_file *m);
extern void p_dump_rx_bps_limit_tb(struct cgroup_subsys_state *css,
				struct seq_file *sf);
extern void p_dump_tx_bps_limit_tb(struct cgroup_subsys_state *css,
				struct seq_file *sf);
extern void p_cgroup_set_rx_limit(struct cls_token_bucket *tb, u64 rate);
extern void p_cgroup_set_tx_limit(struct cls_token_bucket *tb, u64 rate);
extern int p_write_rx_bps_minmax(int ifindex, u64 min, u64 max, int all);
extern int p_write_tx_bps_minmax(int ifindex, u64 min, u64 max, int all);
extern int p_write_rx_min_rwnd_segs(struct cgroup_subsys_state *css,
				  struct cftype *cft, u64 value);
extern u64 p_read_rx_min_rwnd_segs(struct cgroup_subsys_state *css,
				 struct cftype *cft);
extern u32 p_cls_cgroup_adjust_wnd(struct sock *sk, u32 wnd,
				 u32 mss, u16 wscale);
extern int p_cls_cgroup_factor(const struct sock *sk);
extern bool p_is_low_prio(struct sock *sk);

static inline struct
cgroup_cls_state *css_cls_state(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct cgroup_cls_state, css) : NULL;
}

struct cgroup_cls_state *task_cls_state(struct task_struct *p);

static inline u32 task_cls_classid(struct task_struct *p)
{
	u32 classid;

	if (in_interrupt())
		return 0;

	rcu_read_lock();
	classid = container_of(task_css(p, net_cls_cgrp_id),
			       struct cgroup_cls_state, css)->classid;
	rcu_read_unlock();

	return classid;
}

static inline void sock_update_classid(struct sock_cgroup_data *skcd)
{
	u32 classid;

	classid = task_cls_classid(current);
	sock_cgroup_set_classid(skcd, classid);
	rcu_read_lock();
	skcd->cs = task_cls_state(current);
	rcu_read_unlock();
}

static inline u32 __task_get_classid(struct task_struct *task)
{
	return task_cls_state(task)->classid;
}

static inline u32 task_get_classid(const struct sk_buff *skb)
{
	u32 classid = __task_get_classid(current);

	/* Due to the nature of the classifier it is required to ignore all
	 * packets originating from softirq context as accessing `current'
	 * would lead to false results.
	 *
	 * This test assumes that all callers of dev_queue_xmit() explicitly
	 * disable bh. Knowing this, it is possible to detect softirq based
	 * calls by looking at the number of nested bh disable calls because
	 * softirqs always disables bh.
	 */
	if (in_serving_softirq()) {
		struct sock *sk = skb_to_full_sk(skb);

		/* If there is an sock_cgroup_classid we'll use that. */
		if (!sk || !sk_fullsock(sk))
			return 0;

		classid = sock_cgroup_classid(&sk->sk_cgrp_data);
	}

	return classid;
}

static inline s64 ns_to_bytes(u64 rate, s64 diff)
{
	return rate * (u64)diff / NSEC_PER_SEC;
}

static inline s64 bytes_to_ns(u64 rate, u64 bytes)
{
	if (unlikely(!rate))
		return 0;

	return bytes * NSEC_PER_SEC / rate;
}

#else /* !CONFIG_CGROUP_NET_CLASSID */
static inline void sock_update_classid(struct sock_cgroup_data *skcd)
{
}

static inline u32 task_get_classid(const struct sk_buff *skb)
{
	return 0;
}
#endif /* CONFIG_CGROUP_NET_CLASSID */
#endif  /* _NET_CLS_CGROUP_H */
