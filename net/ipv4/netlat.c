// SPDX-License-Identifier: GPL-2.0-only
/* Net Latency Monitor base on Quality Monitor Buffer
 * Aim to provide net latency for a long running system
 *
 *      Author: mengensun <mengensun@tencent.com>
 *      Author: yuehongwu <yuehongwu@tencent.com>
 *      Copyright (C) 2024 Tencent, Inc
 */

#include<net/net_namespace.h>
#include<net/tcp.h>
#include<net/netns/generic.h>
#include<net/netns_mbuf.h>

struct netlat_net_data {
	int ack;
	int pick;
	int queue;
	int enable;
	unsigned long *ports;
	struct ctl_table_header *netlat_hdr;
};

static unsigned int netlat_net_id __read_mostly;
DEFINE_STATIC_KEY_FALSE(enable_netlat);

static inline int get_ack_lat(struct net *net)
{
	struct netlat_net_data *pdata;

	pdata = net_generic(net, netlat_net_id);
	return pdata->ack;
}

static inline int get_pick_lat(struct net *net)
{
	struct netlat_net_data *pdata;

	pdata = net_generic(net, netlat_net_id);
	return pdata->pick;
}

static inline int get_queue_lat(struct net *net)
{
	struct netlat_net_data *pdata;

	pdata = net_generic(net, netlat_net_id);
	return pdata->queue;
}

static inline long *get_net_ports(struct net *net)
{
	struct netlat_net_data *pdata;

	pdata = net_generic(net, netlat_net_id);
	return pdata->ports;
}

/* this function is only can be used with skb on rtx queue
 * because the skb on rtx queue is never be transmit down
 * so the ack_seq is not used for all the skb on trx queue
 * if we add a field in skb, the kapi is changed, we need a
 * delt time from `skb enqueue to rtx queue` to `skb dequeue
 * from rtx queue`, because all the current field about
 * timestamp is reflesh when skb is restransmitted, we can
 * not use thoese field, we borrow the ack_seq to record the
 * time when skb enqueue to rtx queue.
 *
 * !! in next version allow change the kabi, please add a
 * field in skb, and change the follow thress function to
 * using the new added field.
 * borrow the ack_seq is so trick!!
 */
static inline u32 get_rtxq_skb_jiffies(struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->ack_seq;
}

static inline void set_rtxq_skb_jiffies(struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->ack_seq = tcp_jiffies32;
}

/* sk is not used for now, but, may be used in the future
 */
void netlat_copy_rtxq_skb(struct sock *sk, struct sk_buff *dst,
			  struct sk_buff *src)
{
	if (!static_branch_unlikely(&enable_netlat))
		return;
	TCP_SKB_CB(dst)->ack_seq = TCP_SKB_CB(src)->ack_seq;
}
EXPORT_SYMBOL(netlat_copy_rtxq_skb);

static inline u32 tcp_jiffies32_delt(struct sk_buff *skb)
{
	u32 j1, j2;

	j1 = tcp_jiffies32;
	j2 = get_rtxq_skb_jiffies(skb);

	/* here leave a small time windows
	 * when skb is alloced ack_num is inited to 0
	 * if we do not touch the time stamp in ack_num
	 * it is zero
	 */
	if (!j2)
		return 0;

	if (likely(j1 >= j2))
		return j1 - j2;
	/* when u32 is wrap around */
	return U32_MAX - (j2 - j1) + 1;
}

/* sk is not used for now, but, may be used in the future
 */
void netlat_tcp_enrtxqueue(struct sock *sk, struct sk_buff *skb)
{
	if (!static_branch_unlikely(&enable_netlat))
		return;
	set_rtxq_skb_jiffies(skb);
}
EXPORT_SYMBOL(netlat_tcp_enrtxqueue);

/* print msg to per net mbuf when ack latency is
 * watched
 */
void netlat_ack_check(struct sock *sk, struct sk_buff *skb)
{
	struct net *net;
	s64 thresh;
	s64 lat;
	long *ports;

	if (!static_branch_unlikely(&enable_netlat))
		return;

	net = sock_net(sk);

	thresh = get_ack_lat(net);
	if (!thresh)
		return;

	lat = tcp_jiffies32_delt(skb);
	if (lat < thresh)
		return;

	ports = get_net_ports(net);
	if (!test_bit(sk->sk_num, ports))
		return;

	net_mbuf_print(net, "TCP AC %u %pI4 %d %pI4 %d\n",
		       (unsigned int)(jiffies_to_msecs(lat)),
		       &sk->sk_rcv_saddr, (int)sk->sk_num,
		       &sk->sk_daddr, (int)ntohs(sk->sk_dport));
}
EXPORT_SYMBOL(netlat_ack_check);

/* netlat/enable only can be seen in root netns
 *
 * following three function must be called after lock
 * the `lock` above we follow the following rule
 *
 * 1. when disable `enable`: if we have opened the
 *    net_timestamp, closed it
 *
 * 2. when enable `enable`: if `pick/queue` need
 *    net_timestamp, enabled it
 *
 * 3. when `pick/queue` are writing and need enable
 *    net_timestamp and if `enable` disabled, just
 *    say `i need net_timestamp` and do nothing leaveing
 *    it to 2 above
 *
 * 4. when `pick/queue` are writing and need enable
 *    net_timestamp and if `enable` enabled, just
 *    enable net_timestamp by themself
 */
static struct mutex lock = __MUTEX_INITIALIZER(lock);
static unsigned long need_time_stamp;

/* for pick/queue write: see comment above */
static void handle_net_timestamp(bool closed)
{
	/*!0->0*/
	if (closed) {
		need_time_stamp--;
		if (need_time_stamp == 0 &&
		    static_branch_unlikely(&enable_netlat))
			net_disable_timestamp();
		return;
	}

	/*0->!0*/
	need_time_stamp++;
	if (need_time_stamp == 1 &&
	    static_branch_unlikely(&enable_netlat))
		net_enable_timestamp();
}

/* for enable write: see comment above */
static void handle_netlat_enable(bool closed)
{
	/*!0->0*/
	if (closed) {
		if (need_time_stamp)
			net_disable_timestamp();
		static_branch_disable(&enable_netlat);
		return;
	}

	/*0->!0*/
	if (need_time_stamp)
		net_enable_timestamp();
	static_branch_enable(&enable_netlat);
}

/* for netns exits: see comment above */
static void handle_net_timestamp_exit(bool queue, bool pick)
{
	need_time_stamp -= queue;
	need_time_stamp -= pick;

	if (!static_branch_unlikely(&enable_netlat))
		return;
	/* if we dec the counter to zero and netlat enabled
	 * disable the timestamp
	 */
	if (!need_time_stamp && (queue || pick))
		net_disable_timestamp();
}

static int proc_do_netlat_pick(struct ctl_table *table, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int prev;
	int ret;
	struct netlat_net_data *pdata;

	mutex_lock(&lock);

	pdata = container_of(table->data, struct netlat_net_data, pick);
	prev = pdata->pick;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	/* only change timestamp from 0->!0 or !0->0 */
	if (!!prev == !!pdata->pick)
		goto unlock;
	handle_net_timestamp(!!prev);

unlock:
	mutex_unlock(&lock);
	return ret;
}

static int proc_do_netlat_queue(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int prev;
	int ret;
	struct netlat_net_data *pdata;

	mutex_lock(&lock);
	pdata = container_of(table->data, struct netlat_net_data, queue);
	prev = pdata->queue;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	/* only change timestamp from 0->!0 or !0->0 */
	if (!!prev == !!pdata->queue)
		goto unlock;
	handle_net_timestamp(!!prev);

unlock:
	mutex_unlock(&lock);
	return ret;
}

static int proc_do_netlat_enable(struct ctl_table *table, int write,
				 void __user *buffer,
				 size_t *lenp, loff_t *ppos)
{
	int prev;
	int ret;
	struct netlat_net_data *pdata;

	mutex_lock(&lock);

	pdata = container_of(table->data, struct netlat_net_data, enable);
	prev = pdata->enable;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (!!prev == !!pdata->enable)
		goto unlock;
	handle_netlat_enable(!!prev);

unlock:
	mutex_unlock(&lock);
	return ret;
}

static struct ctl_table ipv4_netlat[] = {
	{
		.procname	= "lports",
		.data		= NULL,
		.maxlen		= 65536,
		.mode		= 0644,
		.proc_handler	= proc_do_large_bitmap,
	},
	{
		.procname	= "ack",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname	= "queue",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_do_netlat_queue,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname	= "pick",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_do_netlat_pick,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname	= "enable",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_do_netlat_enable,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{}
};

static int netlat_init_ipv4_ctl_table(struct net *net)
{
	int ret;
	struct netlat_net_data *pdata;
	struct ctl_table *table;

	table = ipv4_netlat;
	pdata = net_generic(net, netlat_net_id);

	ret = 0;
	if (!net_eq(net, &init_net)) {
		table = kmemdup(table, sizeof(ipv4_netlat), GFP_KERNEL);
		if (!table) {
			ret = -ENOMEM;
			goto out;
		}

		/* do not export enable to son netns */
		memset(&table[4], 0, sizeof(struct ctl_table));
	}

	pdata->ports = kzalloc(65536 / 8, GFP_KERNEL);
	if (!pdata->ports) {
		ret = -ENOMEM;
		goto free_table;
	}

	table[0].data = &pdata->ports;
	table[1].data = &pdata->ack;
	table[2].data = &pdata->queue;
	table[3].data = &pdata->pick;

	/* do not export enable to son netns*/
	if (net_eq(net, &init_net))
		table[4].data = &pdata->enable;

	pdata->netlat_hdr = register_net_sysctl_sz(net, "net/ipv4/netlat",
						   table, ARRAY_SIZE(ipv4_netlat));
	if (!pdata->netlat_hdr) {
		ret = -ENOMEM;
		goto free_ports;
	}
	return ret;

free_ports:
	kfree(pdata->ports);
free_table:
	if (!net_eq(net, &init_net))
		kfree(table);
out:
	return ret;
}

static void netlat_exit_ipv4_ctl_table(struct net *net)
{
	struct netlat_net_data *pdata;
	struct ctl_table *table;

	pdata = net_generic(net, netlat_net_id);

	table = pdata->netlat_hdr->ctl_table_arg;
	unregister_net_sysctl_table(pdata->netlat_hdr);

	/* root netns never exit*/
	if (net_eq(net, &init_net))
		return;

	mutex_lock(&lock);
	handle_net_timestamp_exit(!!pdata->queue, !!pdata->pick);
	mutex_unlock(&lock);

	kfree(table);
	kfree(pdata->ports);
}

/* print msg to per net mbuf when latency from
 * netif to queued on tcp receive queue
 */
void netlat_queue_check(struct sock *sk, struct sk_buff *skb)
{
	struct net *net;
	s64 lat;
	int thresh;
	long *ports;

	if (!static_branch_unlikely(&enable_netlat))
		return;

	net = sock_net(sk);
	if (!skb->tstamp)
		return;

	thresh = get_queue_lat(net);
	if (!thresh)
		return;

	ports = get_net_ports(net);
	if (!test_bit(sk->sk_num, ports))
		return;

	if (!skb->tstamp)
		return;

	lat = ktime_to_ms(net_timedelta(skb->tstamp));
	lat = lat < 0 ? 0 : lat;
	if (lat < thresh)
		return;

	net_mbuf_print(net, "TCP QU %u %pI4 %d %pI4 %d\n",
		       (unsigned int)lat,
		       &sk->sk_rcv_saddr, (int)sk->sk_num,
		       &sk->sk_daddr, (int)ntohs(sk->sk_dport));
}
EXPORT_SYMBOL(netlat_queue_check);

/* print msg to per net mbuf when latency from
 * netif to pick by usr app
 */
void netlat_pick_check(struct sock *sk, struct sk_buff *skb)
{
	struct net *net;
	s64 lat;
	int thresh;
	long *ports;

	if (!static_branch_unlikely(&enable_netlat))
		return;

	net = sock_net(sk);
	if (!skb->tstamp)
		return;

	thresh = get_pick_lat(net);
	if (!thresh)
		return;

	ports = get_net_ports(net);
	if (!test_bit(sk->sk_num, ports))
		return;

	if (!skb->tstamp)
		return;

	lat = ktime_to_ms(net_timedelta(skb->tstamp));
	lat = lat < 0 ? 0 : lat;
	if (lat < thresh)
		return;

	net_mbuf_print(net, "TCP PI %u %pI4 %d %pI4 %d\n",
		       (unsigned int)lat, &sk->sk_rcv_saddr, (int)sk->sk_num,
		       &sk->sk_daddr, (int)ntohs(sk->sk_dport));
}
EXPORT_SYMBOL(netlat_pick_check);

static struct pernet_operations netlat_net_ops = {
	.init = netlat_init_ipv4_ctl_table,
	.exit = netlat_exit_ipv4_ctl_table,
	.id   = &netlat_net_id,
	.size = sizeof(struct netlat_net_data),
};

/* add some config file in proc
 */
int  netlat_net_init(void)
{
	return register_pernet_subsys(&netlat_net_ops);
}
EXPORT_SYMBOL(netlat_net_init);

void netlat_net_exit(void)
{
	unregister_pernet_subsys(&netlat_net_ops);
}
EXPORT_SYMBOL(netlat_net_exit);
