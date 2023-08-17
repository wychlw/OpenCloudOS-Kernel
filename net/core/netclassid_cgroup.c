// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/core/netclassid_cgroup.c	Classid Cgroupfs Handling
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 */

#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/fdtable.h>
#include <linux/sched/task.h>

#include <net/cls_cgroup.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/string.h>

int sysctl_net_qos_enable __read_mostly;
EXPORT_SYMBOL_GPL(sysctl_net_qos_enable);

int rx_throttle_all_enabled;
EXPORT_SYMBOL_GPL(rx_throttle_all_enabled);

int tx_throttle_all_enabled;
EXPORT_SYMBOL_GPL(tx_throttle_all_enabled);

struct net_cls_module_function netcls_modfunc;
EXPORT_SYMBOL_GPL(netcls_modfunc);

/* the last one more for all_dev config */
struct dev_bw_config bw_config[MAX_NIC_SUPPORT + 1];
EXPORT_SYMBOL_GPL(bw_config);

int p_read_rx_stat(struct cgroup_subsys_state *css, struct seq_file *sf)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_read_rx_stat);

int p_read_tx_stat(struct cgroup_subsys_state *css, struct seq_file *sf)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_read_tx_stat);

void p_dump_rx_tb(struct seq_file *m)
{
}
EXPORT_SYMBOL_GPL(p_dump_rx_tb);

void p_dump_tx_tb(struct seq_file *m)
{
}
EXPORT_SYMBOL_GPL(p_dump_tx_tb);

void
p_dump_rx_bps_limit_tb(struct cgroup_subsys_state *css, struct seq_file *sf)
{
}
EXPORT_SYMBOL_GPL(p_dump_rx_bps_limit_tb);

void
p_dump_tx_bps_limit_tb(struct cgroup_subsys_state *css, struct seq_file *sf)
{
}
EXPORT_SYMBOL_GPL(p_dump_tx_bps_limit_tb);

void p_cgroup_set_rx_limit(struct cls_token_bucket *tb, u64 rate)
{
}
EXPORT_SYMBOL_GPL(p_cgroup_set_rx_limit);

void p_cgroup_set_tx_limit(struct cls_token_bucket *tb, u64 rate)
{
}
EXPORT_SYMBOL_GPL(p_cgroup_set_tx_limit);

int p_write_rx_bps_minmax(int ifindex, u64 min, u64 max, int all)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_write_rx_bps_minmax);

int p_write_tx_bps_minmax(int ifindex, u64 min, u64 max, int all)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_write_tx_bps_minmax);

int p_write_rx_online_bps_max(int ifindex, u64 max)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_write_rx_online_bps_max);

int p_write_tx_online_bps_max(int ifindex, u64 max)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_write_tx_online_bps_max);

int
p_write_rx_online_bps_min(struct cgroup_cls_state *cs, int ifindex, u64 rate)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_write_rx_online_bps_min);

int
p_write_tx_online_bps_min(struct cgroup_cls_state *cs, int ifindex, u64 rate)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_write_tx_online_bps_min);

int p_rx_online_list_del(struct cgroup_cls_state *cs)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_rx_online_list_del);

int p_tx_online_list_del(struct cgroup_cls_state *cs)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_tx_online_list_del);

int p_write_rx_min_rwnd_segs(struct cgroup_subsys_state *css,
			     struct cftype *cft, u64 value)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_write_rx_min_rwnd_segs);

u64 p_read_rx_min_rwnd_segs(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return 0;
}
EXPORT_SYMBOL_GPL(p_read_rx_min_rwnd_segs);

u32 p_cls_cgroup_adjust_wnd(struct sock *sk, u32 wnd, u32 mss, u16 wscale)
{
	return wnd;
}
EXPORT_SYMBOL_GPL(p_cls_cgroup_adjust_wnd);

int p_cls_cgroup_factor(const struct sock *sk)
{
	return WND_DIVISOR;
}
EXPORT_SYMBOL_GPL(p_cls_cgroup_factor);

bool p_is_low_prio(struct sock *sk)
{
	return false;
}
EXPORT_SYMBOL_GPL(p_is_low_prio);

struct dev_limit_config limit_bw_config[MAX_NIC_SUPPORT];
EXPORT_SYMBOL_GPL(limit_bw_config);

struct dev_bw_config online_max_config[MAX_NIC_SUPPORT];
EXPORT_SYMBOL_GPL(online_max_config);

struct dev_limit_config online_min_config[MAX_NIC_SUPPORT];
EXPORT_SYMBOL_GPL(online_min_config);

struct cgroup_cls_state *task_cls_state(struct task_struct *p)
{
	return css_cls_state(task_css_check(p, net_cls_cgrp_id,
					    rcu_read_lock_bh_held()));
}
EXPORT_SYMBOL_GPL(task_cls_state);

int cls_cgroup_stats_init(struct cls_cgroup_stats *stats)
{
	struct {
		struct nlattr nla;
		struct gnet_estimator params;
	} opt;
	int err;

	opt.nla.nla_len = nla_attr_size(sizeof(opt.params));
	opt.nla.nla_type = TCA_RATE;
	opt.params.interval = 0; /* statistics every 1s. */
	opt.params.ewma_log = 1; /* ewma off. */
	spin_lock_init(&stats->lock);

	rtnl_lock();
	err = gen_new_estimator(&stats->bstats,
				NULL,
				&stats->est,
				&stats->lock,
				NULL,
				&opt.nla);

	if (err)
		pr_err("gen_new_estimator failed(%d)\n", err);
	rtnl_unlock();

	return err;
}

void cls_cgroup_stats_destroy(struct cls_cgroup_stats *stats)
{
	rtnl_lock();
	gen_kill_estimator(&stats->est);
	rtnl_unlock();
}

static struct cgroup_subsys_state *
cgrp_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cgroup_cls_state *cs;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return ERR_PTR(-ENOMEM);

	return &cs->css;
}

static int cgrp_css_online(struct cgroup_subsys_state *css)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct cgroup_cls_state *parent = css_cls_state(css->parent);
	int i;

	if (parent) {
		cs->prio = parent->prio;
		cs->classid = parent->classid;
	}

	cs->whitelist_lports = kzalloc(65536 / 8, GFP_KERNEL);
	if (!cs->whitelist_lports)
		return -ENOMEM;

	cs->whitelist_rports = kzalloc(65536 / 8, GFP_KERNEL);
	if (!cs->whitelist_rports) {
		kfree(cs->whitelist_lports);
		return -ENOMEM;
	}

	cls_cgroup_stats_init(&cs->rx_stats);
	cls_cgroup_stats_init(&cs->tx_stats);
	cs->rx_scale = WND_DIVISOR;
	for (i = 0; i < MAX_NIC_SUPPORT; i++) {
		cs->rx_dev_scale[i] = WND_DIVISOR;
		cs->rx_online_scale[i] = WND_DIVISOR;
	}
	INIT_LIST_HEAD(&cs->rx_list);
	INIT_LIST_HEAD(&cs->tx_list);

	return 0;
}

static void cgrp_css_offline(struct cgroup_subsys_state *css)
{
	struct cgroup_cls_state *cs = css_cls_state(css);

	cls_cgroup_stats_destroy(&cs->rx_stats);
	cls_cgroup_stats_destroy(&cs->tx_stats);
	if (READ_ONCE(netcls_modfunc.rx_online_list_del) &&
	    READ_ONCE(netcls_modfunc.tx_online_list_del)) {
		netcls_modfunc.rx_online_list_del(cs);
		netcls_modfunc.tx_online_list_del(cs);
	}
}

static void cgrp_css_free(struct cgroup_subsys_state *css)
{
	struct cgroup_cls_state *cs = css_cls_state(css);

	kfree(cs->whitelist_lports);
	kfree(cs->whitelist_rports);
	kfree(cs);
}

/*
 * To avoid freezing of sockets creation for tasks with big number of threads
 * and opened sockets lets release file_lock every 1000 iterated descriptors.
 * New sockets will already have been created with new classid.
 */

struct update_classid_context {
	u32 classid;
	unsigned int batch;
	struct task_struct *task;
};

#define UPDATE_CLASSID_BATCH 1000

static int update_classid_sock(const void *v, struct file *file, unsigned int n)
{
	struct update_classid_context *ctx = (void *)v;
	struct socket *sock = sock_from_file(file);

	if (sock) {
		sock_cgroup_set_classid(&sock->sk->sk_cgrp_data, ctx->classid);
		rcu_read_lock();
		sock->sk->sk_cgrp_data.cs = task_cls_state(ctx->task);
		rcu_read_unlock();
	}
	if (--ctx->batch == 0) {
		ctx->batch = UPDATE_CLASSID_BATCH;
		return n + 1;
	}
	return 0;
}

static void update_classid_task(struct task_struct *p, u32 classid)
{
	struct update_classid_context ctx = {
		.classid = classid,
		.batch = UPDATE_CLASSID_BATCH,
		.task = p,
	};
	unsigned int fd = 0;

	do {
		task_lock(p);
		fd = iterate_fd(p->files, fd, update_classid_sock, &ctx);
		task_unlock(p);
		cond_resched();
	} while (fd);
}

static void cgrp_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *p;

	cgroup_taskset_for_each(p, css, tset) {
		update_classid_task(p, css_cls_state(css)->classid);
	}
}

static u64 read_classid(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->classid;
}

static int write_classid(struct cgroup_subsys_state *css, struct cftype *cft,
			 u64 value)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct css_task_iter it;
	struct task_struct *p;

	cs->classid = (u32)value;

	css_task_iter_start(css, 0, &it);
	while ((p = css_task_iter_next(&it)))
		update_classid_task(p, cs->classid);
	css_task_iter_end(&it);

	return 0;
}

static int read_bps_limit(struct seq_file *sf, void *v)
{
	struct cgroup_cls_state *cs = css_cls_state(seq_css(sf));
	u64 tx_rate = (cs->tx_bucket.rate << 3) / NET_MSCALE;
	u64 rx_rate = (cs->rx_bucket.rate << 3) / NET_MSCALE;

	seq_printf(sf, "tx_bps=%llu rx_bps=%llu\n",
		   tx_rate, rx_rate);
	return 0;
}

static ssize_t write_bps_limit(struct kernfs_open_file *of,
			       char *buf, size_t nbytes, loff_t off)
{
	struct cgroup_cls_state *cs = css_cls_state(of_css(of));
	char tok[27] = {0};
	long tx_rate = -1, rx_rate = -1;
	int len;
	int ret = -EINVAL;

	while (true) {
		char *p;
		unsigned long val = 0;

		if (sscanf(buf, "%26s%n", tok, &len) != 1)
			break;
		if (tok[0] == '\0')
			break;
		buf += len;

		p = tok;
		strsep(&p, "=");
		if (!p || kstrtoul(p, 10, &val))
			goto out_finish;

		if (!strcmp(tok, "rx_bps") && val >= 0)
			rx_rate = val;
		else if (!strcmp(tok, "tx_bps") && val >= 0)
			tx_rate = val;
		else
			goto out_finish;
	}

	if (!rx_rate)
		cs->rx_scale = WND_DIVISOR;

	if (rx_rate != -1 && READ_ONCE(netcls_modfunc.cgroup_set_rx_limit))
		netcls_modfunc.cgroup_set_rx_limit(&cs->rx_bucket, rx_rate);

	if (tx_rate != -1 && READ_ONCE(netcls_modfunc.cgroup_set_tx_limit))
		netcls_modfunc.cgroup_set_tx_limit(&cs->tx_bucket, tx_rate);
	ret = nbytes;

out_finish:
	return ret;
}

static int read_bps_dev_limit(struct seq_file *sf, void *v)
{
	struct cgroup_cls_state *cs = css_cls_state(seq_css(sf));
	u64 tx_rate, rx_rate;
	int i;

	for (i = 0; i < MAX_NIC_SUPPORT; i++)
		if ((cs->tx_dev_bucket[i].rate || cs->rx_dev_bucket[i].rate) &&
		    limit_bw_config[i].name) {
			tx_rate = (cs->tx_dev_bucket[i].rate << 3) / NET_MSCALE;
			rx_rate = (cs->rx_dev_bucket[i].rate << 3) / NET_MSCALE;
			seq_printf(sf, "%s tx_bps=%llu rx_bps=%llu\n",
				   limit_bw_config[i].name, tx_rate, rx_rate);
		}
	return 0;
}

static ssize_t write_bps_dev_limit(struct kernfs_open_file *of,
				   char *buf, size_t nbytes, loff_t off)
{
	struct cgroup_cls_state *cs = css_cls_state(of_css(of));
	int len, ifindex = -1;
	struct net_device *dev;
	struct net *net = current->nsproxy->net_ns;
	char tok[27] = {0};
	long rx_rate = -1, tx_rate = -1;
	int ret = -EINVAL;
	char *dev_name = NULL;
	char *name = NULL;

	if (sscanf(buf, "%16s%n", tok, &len) != 1)
		return ret;
	buf += len;

	dev = dev_get_by_name(net, tok);
	if (!dev) {
		pr_err("Netdev name %s not found!\n", tok);
		return -ENODEV;
	}

	if (dev->ifindex >= MAX_NIC_SUPPORT) {
		pr_err("Netdev %s index(%d) too large!\n", tok, dev->ifindex);
		goto out_finish;
	}
	ifindex = dev->ifindex;
	dev_name = dev->name;

	while (true) {
		char *p;
		unsigned long val = 0;

		if (sscanf(buf, "%26s%n", tok, &len) != 1)
			break;
		if (tok[0] == '\0')
			break;
		buf += len;

		p = tok;
		strsep(&p, "=");
		if (!p || kstrtoul(p, 10, &val) || val < 0)
			goto out_finish;

		if (!strcmp(tok, "disable") && val == 1) {
			rx_rate = 0;
			tx_rate = 0;
		} else if (!strcmp(tok, "rx_bps")) {
			rx_rate = val;
		} else if (!strcmp(tok, "tx_bps")) {
			tx_rate = val;
		} else {
			goto out_finish;
		}
	}

	if (rx_rate < -1 || tx_rate < -1 || (rx_rate < 0 && tx_rate < 0))
		goto out_finish;

	len = strlen(dev_name) + 1;
	name = kzalloc(len, GFP_KERNEL);
	if (!name) {
		pr_err("Netdev %s index(%d) alloc name failed!\n",
		       dev_name, ifindex);
		goto out_finish;
	}

	/* release old config info */
	kfree(limit_bw_config[ifindex].name);

	limit_bw_config[ifindex].name = name;
	strncpy(limit_bw_config[ifindex].name, dev_name, strlen(dev_name));

	if (!rx_rate)
		cs->rx_dev_scale[ifindex] = WND_DIVISOR;

	if (rx_rate > -1 && READ_ONCE(netcls_modfunc.cgroup_set_rx_limit))
		netcls_modfunc.cgroup_set_rx_limit(&cs->rx_dev_bucket[ifindex],
						   rx_rate);

	if (tx_rate > -1 && READ_ONCE(netcls_modfunc.cgroup_set_tx_limit))
		netcls_modfunc.cgroup_set_tx_limit(&cs->tx_dev_bucket[ifindex],
						   tx_rate);
	ret = nbytes;

out_finish:
	dev_put(dev);
	return ret;
}

static int read_whitelist_port(struct seq_file *sf, void *v)
{
	loff_t off = 0;
	int ret = 0;
	struct ctl_table table;
	size_t max_len = 4096;
	char *lports_buf, *rports_buf;
	struct cgroup_cls_state *cs = css_cls_state(seq_css(sf));

	lports_buf = kzalloc(max_len, GFP_KERNEL);
	if (!lports_buf)
		return -ENOMEM;

	rports_buf = kzalloc(max_len, GFP_KERNEL);
	if (!rports_buf) {
		ret = -ENOMEM;
		goto out_free_lports;
	}

	table.maxlen = 65536;
	table.data = &cs->whitelist_lports;
	netcls_do_large_bitmap(&table, 0, lports_buf, &max_len, &off);

	off = 0;
	max_len = 4096;
	table.maxlen = 65536;
	table.data = &cs->whitelist_rports;
	netcls_do_large_bitmap(&table, 0, rports_buf, &max_len, &off);

	if (strlen(lports_buf) == 1) {
		lports_buf[0] = '0';
		lports_buf[1] = '\n';
	}

	if (strlen(rports_buf) == 1) {
		rports_buf[0] = '0';
		rports_buf[1] = '\n';
	}
	seq_printf(sf, "lports=%srports=%s", lports_buf, rports_buf);

	kfree(rports_buf);
out_free_lports:
	kfree(lports_buf);
	return ret;
}

static int get_port_config(char *buf, char *lports, char *rports)
{
	int len;
	int ret = -1;
	char *tok = kzalloc(4096, GFP_KERNEL);

	if (!tok)
		return -ENOMEM;

	while (true) {
		char *p;

		if (sscanf(buf, "%4095s%n", tok, &len) != 1)
			break;
		if (tok[0] == '\0')
			break;
		buf += len;
		p = tok;
		strsep(&p, "=");
		if (!p)
			goto out_finish;

		if (!strcmp(tok, "lports"))
			memcpy(lports, p, strlen(p));
		else if (!strcmp(tok, "rports"))
			memcpy(rports, p, strlen(p));
		else
			goto out_finish;
	}
	ret = 0;

out_finish:
	kfree(tok);
	return ret;
}

static ssize_t write_whitelist_port(struct kernfs_open_file *of,
				    char *buf, size_t nbytes, loff_t off)
{
	struct ctl_table table;
	int ret = -EINVAL;
	size_t max_len = 4096;
	size_t buf_len;
	char *lports_buf, *rports_buf;
	struct cgroup_cls_state *cs = css_cls_state(of_css(of));

	lports_buf = kzalloc(max_len, GFP_KERNEL);
	if (!lports_buf)
		return -ENOMEM;

	rports_buf = kzalloc(max_len, GFP_KERNEL);
	if (!rports_buf) {
		ret = -ENOMEM;
		goto out_free_lports;
	}

	table.maxlen = 65536;
	if (nbytes >= max_len)
		goto out_finish;

	if (get_port_config(buf, lports_buf, rports_buf))
		goto out_finish;

	table.data = &cs->whitelist_lports;
	buf_len = strlen(lports_buf);
	if (netcls_do_large_bitmap(&table, 1, lports_buf, &buf_len, &off))
		goto out_finish;

	off = 0;
	table.maxlen = 65536;
	table.data = &cs->whitelist_rports;
	buf_len = strlen(rports_buf);
	if (netcls_do_large_bitmap(&table, 1, rports_buf, &buf_len, &off))
		goto out_finish;

	ret = nbytes;
out_finish:
	kfree(rports_buf);
out_free_lports:
	kfree(lports_buf);
	return ret;
}

int net_cgroup_notify_prio_change(struct cgroup_subsys_state *css,
				  u16 old_prio, u16 new_prio)
{
	if (css)
		css_cls_state(css)->prio = (u32)new_prio;
	return 0;
}

static int read_dev_online_bps_max(struct seq_file *sf, void *v)
{
	int i;

	for (i = 0; i < MAX_NIC_SUPPORT; i++)
		if ((online_max_config[i].rx_bps_max ||
		     online_max_config[i].tx_bps_max) &&
		    online_max_config[i].name)
			seq_printf(sf, "%s rx_bps=%lu tx_bps=%lu\n",
				   online_max_config[i].name,
				   online_max_config[i].rx_bps_max,
				   online_max_config[i].tx_bps_max);
	return 0;
}

static ssize_t write_dev_online_bps_max(struct kernfs_open_file *of,
					char *buf, size_t nbytes, loff_t off)
{
	int len, ifindex = -1;
	struct net_device *dev;
	struct net *net = current->nsproxy->net_ns;
	char tok[27] = {0};
	long rx_rate = -1, tx_rate = -1;
	int ret = -EINVAL;
	char *dev_name = NULL;
	char *name = NULL;

	if (sscanf(buf, "%16s%n", tok, &len) != 1)
		return ret;
	buf += len;

	dev = dev_get_by_name(net, tok);
	if (!dev) {
		pr_err("Netdev name %s not found!\n", tok);
		return -ENODEV;
	}

	if (dev->ifindex >= MAX_NIC_SUPPORT) {
		pr_err("Netdev %s index(%d) too large!\n", tok, dev->ifindex);
		goto out_finish;
	}
	ifindex = dev->ifindex;
	dev_name = dev->name;

	while (true) {
		char *p;
		unsigned long val = 0;

		if (sscanf(buf, "%26s%n", tok, &len) != 1)
			break;
		if (tok[0] == '\0')
			break;
		buf += len;

		p = tok;
		strsep(&p, "=");
		if (!p || kstrtoul(p, 10, &val) || val < 0)
			goto out_finish;

		if (!strcmp(tok, "disable") && val == 1) {
			rx_rate = 0;
			tx_rate = 0;
		} else if (!strcmp(tok, "rx_bps")) {
			rx_rate = val;
		} else if (!strcmp(tok, "tx_bps")) {
			tx_rate = val;
		} else {
			goto out_finish;
		}
	}

	if (rx_rate < -1 || tx_rate < -1 || (rx_rate < 0 && tx_rate < 0))
		goto out_finish;

	len = strlen(dev_name) + 1;
	name = kzalloc(len, GFP_KERNEL);
	if (!name) {
		pr_err("Netdev %s index(%d) alloc name failed!\n",
		       dev_name, ifindex);
		goto out_finish;
	}

	/* release old config info */
	kfree(online_max_config[ifindex].name);

	online_max_config[ifindex].name = name;
	strncpy(online_max_config[ifindex].name, dev_name, strlen(dev_name));

	if (rx_rate > -1 && READ_ONCE(netcls_modfunc.write_rx_online_bps_max)) {
		online_max_config[ifindex].rx_bps_max = rx_rate;
		netcls_modfunc.write_rx_online_bps_max(ifindex,
			online_max_config[ifindex].rx_bps_max);
	}
	if (tx_rate > -1 && READ_ONCE(netcls_modfunc.write_tx_online_bps_max)) {
		online_max_config[ifindex].tx_bps_max = tx_rate;
		netcls_modfunc.write_tx_online_bps_max(ifindex,
			online_max_config[ifindex].tx_bps_max);
	}
	ret = nbytes;

out_finish:
	dev_put(dev);
	return ret;
}

static int read_dev_online_bps_min(struct seq_file *sf, void *v)
{
	int i;
	u64 rx_rate, tx_rate;
	struct cgroup_cls_state *cs = css_cls_state(seq_css(sf));

	for (i = 0; i < MAX_NIC_SUPPORT; i++)
		if ((cs->rx_online_bucket[i].rate ||
		     cs->tx_online_bucket[i].rate) &&
		    online_min_config[i].name) {
			rx_rate = (cs->rx_online_bucket[i].rate << 3)
					/ NET_MSCALE;
			tx_rate = (cs->tx_online_bucket[i].rate << 3)
					/ NET_MSCALE;
			seq_printf(sf, "%s rx_bps=%llu tx_bps=%llu\n",
				   online_min_config[i].name, rx_rate, tx_rate);
		}
	return 0;
}

static ssize_t write_dev_online_bps_min(struct kernfs_open_file *of,
					char *buf, size_t nbytes, loff_t off)
{
	struct cgroup_cls_state *cs = css_cls_state(of_css(of));
	int len, ifindex = -1;
	struct net_device *dev;
	struct net *net = current->nsproxy->net_ns;
	char tok[27] = {0};
	long rx_rate = -1, tx_rate = -1;
	int ret = -EINVAL;
	char *dev_name = NULL;
	char *name = NULL;

	if (sscanf(buf, "%16s%n", tok, &len) != 1)
		return ret;
	buf += len;

	dev = dev_get_by_name(net, tok);
	if (!dev) {
		pr_err("Netdev name %s not found!\n", tok);
		return -ENODEV;
	}

	if (dev->ifindex >= MAX_NIC_SUPPORT) {
		pr_err("Netdev %s index(%d) too large!\n", tok, dev->ifindex);
		goto out_finish;
	}
	ifindex = dev->ifindex;
	dev_name = dev->name;

	while (true) {
		char *p;
		unsigned long val = 0;

		if (sscanf(buf, "%26s%n", tok, &len) != 1)
			break;
		if (tok[0] == '\0')
			break;
		buf += len;

		p = tok;
		strsep(&p, "=");
		if (!p || kstrtoul(p, 10, &val) || val < 0)
			goto out_finish;

		if (!strcmp(tok, "disable") && val == 1) {
			rx_rate = 0;
			tx_rate = 0;
		} else if (!strcmp(tok, "rx_bps")) {
			rx_rate = val;
		} else if (!strcmp(tok, "tx_bps")) {
			tx_rate = val;
		} else {
			goto out_finish;
		}
	}

	if (rx_rate < -1 || tx_rate < -1 || (rx_rate < 0 && tx_rate < 0))
		goto out_finish;

	len = strlen(dev_name) + 1;
	name = kzalloc(len, GFP_KERNEL);
	if (!name) {
		pr_err("Netdev %s index(%d) alloc name failed!\n",
		       dev_name, ifindex);
		goto out_finish;
	}

	/* release old config info */
	kfree(online_min_config[ifindex].name);

	online_min_config[ifindex].name = name;
	strncpy(online_min_config[ifindex].name, dev_name, strlen(dev_name));

	if (rx_rate > -1 && READ_ONCE(netcls_modfunc.write_rx_online_bps_min))
		netcls_modfunc.write_rx_online_bps_min(cs, ifindex, rx_rate);
	if (tx_rate > -1 && READ_ONCE(netcls_modfunc.write_tx_online_bps_min))
		netcls_modfunc.write_tx_online_bps_min(cs, ifindex, tx_rate);
	ret = nbytes;

out_finish:
	dev_put(dev);
	return ret;
}

static ssize_t write_dev_bps_config(struct kernfs_open_file *of,
				    char *buf, size_t nbytes, loff_t off)
{
	int len, ifindex = -1;
	struct net_device *dev;
	struct net *net = current->nsproxy->net_ns;
	char tok[27] = {0};
	long v[4] = {-1, -1, -1, -1};
	int ret = -EINVAL;
	char *dev_name = NULL;
	bool set_all_dev = false;
	char *name = NULL;

	if (sscanf(buf, "%16s%n", tok, &len) != 1)
		return ret;
	buf += len;

	if (strlen(tok) == 3 && !strcmp(tok, "all")) {
		dev_name = "all";
		ifindex = MAX_NIC_SUPPORT;
		set_all_dev = true;
	} else {
		dev = dev_get_by_name(net, tok);
		if (!dev) {
			pr_err("Netdev name %s not found!\n", tok);
			return -ENODEV;
		}

		if (dev->ifindex >= MAX_NIC_SUPPORT) {
			pr_err("Netdev %s index(%d) too large!\n", tok,
			       dev->ifindex);
			goto out_finish;
		}
		ifindex = dev->ifindex;
		dev_name = dev->name;
	}

	while (true) {
		char *p;
		unsigned long val = 0;

		if (sscanf(buf, "%26s%n", tok, &len) != 1)
			break;
		if (tok[0] == '\0')
			break;
		buf += len;

		p = tok;
		strsep(&p, "=");
		if (!p || kstrtoul(p, 10, &val) || val < 0)
			goto out_finish;

		if (!strcmp(tok, "disable") && val == 1) {
			kfree(bw_config[ifindex].name);
			bw_config[ifindex].name = NULL;
			ret = nbytes;
			if (set_all_dev) {
				tx_throttle_all_enabled = 0;
				rx_throttle_all_enabled = 0;
			}
			goto out_finish;
		} else if (!strcmp(tok, "rx_bps_min")) {
			v[0] = val;
		} else if (!strcmp(tok, "rx_bps_max")) {
			v[1] = val;
		} else if (!strcmp(tok, "tx_bps_min")) {
			v[2] = val;
		} else if (!strcmp(tok, "tx_bps_max")) {
			v[3] = val;
		} else {
			goto out_finish;
		}
	}

	if ((v[0] > -1 && v[1] > -1) || (v[2] > -1 && v[3] > -1)) {
		if (v[0] < -1 || v[0] > v[1] || v[2] < -1 || v[2] > v[3])
			goto out_finish;

		if ((v[0] == -1 || v[1] == -1) && (v[0] > -1 || v[1] > -1))
			goto out_finish;

		if ((v[2] == -1 || v[3] == -1) && (v[2] > -1 || v[3] > -1))
			goto out_finish;

		len = strlen(dev_name) + 1;
		name = kzalloc(len, GFP_KERNEL);
		if (!name) {
			pr_err("Netdev %s index(%d) alloc name failed!\n",
			       dev_name, ifindex);
			goto out_finish;
		}

		/* release old config info */
		kfree(bw_config[ifindex].name);

		bw_config[ifindex].name = name;
		strncpy(bw_config[ifindex].name, dev_name, strlen(dev_name));

		if (v[0] > -1 && v[1] > -1 &&
		    READ_ONCE(netcls_modfunc.write_rx_bps_minmax)) {
			bw_config[ifindex].rx_bps_min = v[0];
			bw_config[ifindex].rx_bps_max = v[1];
			netcls_modfunc.write_rx_bps_minmax(ifindex,
					bw_config[ifindex].rx_bps_min,
					bw_config[ifindex].rx_bps_max,
					set_all_dev);
		}

		if (v[2] > -1 && v[3] > -1 &&
		    READ_ONCE(netcls_modfunc.write_tx_bps_minmax)) {
			bw_config[ifindex].tx_bps_min = v[2];
			bw_config[ifindex].tx_bps_max = v[3];
			netcls_modfunc.write_tx_bps_minmax(ifindex,
					bw_config[ifindex].tx_bps_min,
					bw_config[ifindex].tx_bps_max,
					set_all_dev);
		}

		if (set_all_dev) {
			if (bw_config[ifindex].rx_bps_min &&
			    bw_config[ifindex].rx_bps_max)
				rx_throttle_all_enabled = 1;
			if (bw_config[ifindex].tx_bps_min &&
			    bw_config[ifindex].tx_bps_max)
				tx_throttle_all_enabled = 1;
		}
		ret = nbytes;
	}

out_finish:
	if (!set_all_dev)
		dev_put(dev);
	return ret;
}

static int read_dev_bps_config(struct seq_file *sf, void *v)
{
	int i;

	for (i = 0; i <= MAX_NIC_SUPPORT; i++)
		if (bw_config[i].name)
			seq_printf(sf,
				   "%s rx_bps_min=%lu rx_bps_max=%lu tx_bps_min=%lu tx_bps_max=%lu\n",
				   bw_config[i].name,
				   bw_config[i].rx_bps_min,
				   bw_config[i].rx_bps_max,
				   bw_config[i].tx_bps_min,
				   bw_config[i].tx_bps_max);
	return 0;
}

int netqos_notifier(struct notifier_block *this,
		    unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct net *net = dev_net(dev);

	if (!net_eq(net, &init_net))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UNREGISTER:
		if (dev->ifindex >= MAX_NIC_SUPPORT)
			break;

		kfree(bw_config[dev->ifindex].name);
		bw_config[dev->ifindex].name = NULL;

		kfree(limit_bw_config[dev->ifindex].name);
		limit_bw_config[dev->ifindex].name = NULL;

		kfree(online_max_config[dev->ifindex].name);
		online_max_config[dev->ifindex].name = NULL;

		kfree(online_min_config[dev->ifindex].name);
		online_min_config[dev->ifindex].name = NULL;
		break;
	}

	return NOTIFY_DONE;
}
EXPORT_SYMBOL_GPL(netqos_notifier);

static int write_rx_min_rwnd_segs(struct cgroup_subsys_state *css,
				  struct cftype *cft, u64 value)
{
	if (READ_ONCE(netcls_modfunc.write_rx_min_rwnd_segs))
		return netcls_modfunc.write_rx_min_rwnd_segs(css, cft, value);
	return 0;
}

static u64 read_rx_min_rwnd_segs(struct cgroup_subsys_state *css,
				 struct cftype *cft)
{
	if (READ_ONCE(netcls_modfunc.read_rx_min_rwnd_segs))
		return netcls_modfunc.read_rx_min_rwnd_segs(css, cft);
	return 0;
}

int read_class_stat(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);

	if (READ_ONCE(netcls_modfunc.read_rx_stat) &&
	    READ_ONCE(netcls_modfunc.read_tx_stat)) {
		netcls_modfunc.read_rx_stat(css, sf);
		netcls_modfunc.read_tx_stat(css, sf);
	}
	return 0;
}

int rx_dump(struct seq_file *sf, void *v)
{
	if (READ_ONCE(netcls_modfunc.dump_rx_tb))
		netcls_modfunc.dump_rx_tb(sf);
	return 0;
}

int tx_dump(struct seq_file *sf, void *v)
{
	if (READ_ONCE(netcls_modfunc.dump_tx_tb))
		netcls_modfunc.dump_tx_tb(sf);
	return 0;
}

int bps_limit_dump(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);

	if (READ_ONCE(netcls_modfunc.dump_rx_bps_limit_tb) &&
	    READ_ONCE(netcls_modfunc.dump_tx_bps_limit_tb)) {
		netcls_modfunc.dump_rx_bps_limit_tb(css, sf);
		netcls_modfunc.dump_tx_bps_limit_tb(css, sf);
	}
	return 0;
}

static struct cftype ss_files[] = {
	{
		.name		= "classid",
		.read_u64	= read_classid,
		.write_u64	= write_classid,
	},
	{
		.name		= "dev_bps_config",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.seq_show	= read_dev_bps_config,
		.write		= write_dev_bps_config,
	},
	{
		.name		= "dev_online_bps_max",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.seq_show	= read_dev_online_bps_max,
		.write		= write_dev_online_bps_max,
	},
	{
		.name		= "dev_online_bps_min",
		.flags		= CFTYPE_NOT_ON_ROOT,
		.seq_show	= read_dev_online_bps_min,
		.write		= write_dev_online_bps_min,
	},
	{
		.name		= "rx_min_rwnd_segs",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.read_u64	= read_rx_min_rwnd_segs,
		.write_u64	= write_rx_min_rwnd_segs,
	},
	{
		.name		= "stat",
		.flags		= CFTYPE_NOT_ON_ROOT,
		.seq_show	= read_class_stat,
	},
	{
		.name		= "rx_dump",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.seq_show	= rx_dump,
	},
	{
		.name		= "tx_dump",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.seq_show	= tx_dump,
	},
	{
		.name		= "limit_dump",
		.flags		= CFTYPE_NOT_ON_ROOT,
		.seq_show	= bps_limit_dump,
	},
	{
		.name		= "limit",
		.flags		= CFTYPE_NOT_ON_ROOT,
		.seq_show	= read_bps_limit,
		.write		= write_bps_limit,
	},
	{
		.name		= "dev_limit",
		.flags		= CFTYPE_NOT_ON_ROOT,
		.seq_show	= read_bps_dev_limit,
		.write		= write_bps_dev_limit,
	},
	{
		.name		= "whitelist_ports",
		.flags		= CFTYPE_NOT_ON_ROOT,
		.seq_show	= read_whitelist_port,
		.write		= write_whitelist_port,
	},
	{ }	/* terminate */
};

struct cgroup_subsys net_cls_cgrp_subsys = {
	.css_alloc		= cgrp_css_alloc,
	.css_online		= cgrp_css_online,
	.css_offline	= cgrp_css_offline,
	.css_free		= cgrp_css_free,
	.attach			= cgrp_attach,
	.css_priority_change	= net_cgroup_notify_prio_change,
	.dfl_cftypes		= ss_files,
	.legacy_cftypes		= ss_files,
};
