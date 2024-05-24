// SPDX-License-Identifier: GPL-2.0-only
/* make mbuf can be used by net namespace
 *
 * Author: mengensun <mengensun@tencent.com>
 * Author: yuehongwu <yuehongwu@tencent.com>
 * Copyright (C) 2024 Tencent, Inc
 */
#include<linux/cgroup.h>
#include<linux/mbuf.h>
#include<linux/proc_fs.h>

#include<net/net_namespace.h>
#include<net/netns/generic.h>

struct mbuf_seq_data {
	struct seq_net_private snp;
	struct mbuf_user_desc udesc;
	struct mbuf_slot snapshot[];
};

static inline struct mbuf_slot *get_net_mbuf(struct net *net)
{
	return net->mbuf.slot;
}

/* not controlled by sysctl_qos_mbuf_enable because we will
 * have a /proc/net/ipv4/netlat/enable in later patch
 */
ssize_t net_mbuf_print(struct net *net, const char *fmt, ...)
{
	va_list args;
	struct mbuf_slot *slot;

	slot = net->mbuf.slot;
	if (!slot || !__ratelimit(&slot->ratelimit))
		goto out;

	va_start(args, fmt);
	slot->ops->write(slot, fmt, args);
	va_end(args);
out:
	return 0;
}
EXPORT_SYMBOL(net_mbuf_print);

/* udesc is the user side interface, used to get data from mbuf,
 * we can alloc a udesc per user, not to alloc a udesc and bind
 * to mbuf when user accessing mbuf.
 *
 * seq file private data is the ideal place to hold the udesc
 * if we put udesc in seq file private data all things is simple
 */
static void *netns_mbuf_start(struct seq_file *s, loff_t *pos)
{
	u32 index;
	struct mbuf_user_desc *udesc;
	struct mbuf_seq_data *pd;

	pd = s->private;
	udesc = &pd->udesc;
	index = *pos;

	/* why: see seq_mbuf_open */
	if (!pd->snapshot->mring)
		return NULL;

	/* If already reach end, just return */
	if (index && index == pd->snapshot->mring->next_idx)
		return NULL;

	udesc->user_idx = pd->snapshot->mring->first_idx;
	udesc->user_seq = pd->snapshot->mring->first_seq;

	/* Maybe reach end or empty */
	if (udesc->user_idx == pd->snapshot->mring->next_idx)
		return NULL;
	return udesc;
}

static void *netns_mbuf_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct mbuf_seq_data *pd;
	struct mbuf_user_desc *udesc = v;

	pd = s->private;

	/* why: see seq_mbuf_open */
	if (!pd->snapshot->mring)
		return NULL;

	udesc->user_idx = pd->snapshot->ops->next(pd->snapshot->mring,
			udesc->user_idx);
	*pos = udesc->user_idx;
	if (udesc->user_idx == pd->snapshot->mring->next_idx)
		return NULL;

	return udesc;
}

static void netns_mbuf_stop(struct seq_file *s, void *v) { }

static int netns_mbuf_show(struct seq_file *s, void *v)
{
	ssize_t ret;
	struct mbuf_seq_data *pd;
	struct mbuf_user_desc *udesc = (struct mbuf_user_desc *)v;

	pd = s->private;

	/* why: see seq_mbuf_open */
	if (!pd->snapshot->mring)
		return 0;

	memset(udesc->buf, 0, sizeof(udesc->buf));
	ret = pd->snapshot->ops->read(pd->snapshot, udesc);
	if (ret > 0)
		seq_printf(s, "%s", udesc->buf);
	return 0;
}

static int seq_mbuf_open(struct inode *inode, struct file *file)
{
	struct mbuf_seq_data *p;
	struct mbuf_slot *mbuf;

	p = seq_open_net_large_private(inode, file);

	if (IS_ERR(p))
		return PTR_ERR(p);

	mbuf = get_net_mbuf(p->snp.net);
	/* netns may have no mbuf attached, because the mbuf
	 * pool has a max num
	 * here we let file open success, so, seq_ops must
	 * check mring point
	 *
	 * btw: we memzerod the private in
	 * seq_open_net_large_private
	 */
	if (!mbuf)
		return 0;

	snapshot_mbuf(p->snapshot, mbuf, &mbuf->slot_lock);
	return 0;
}

/* this function is token from seq_release_net, all is the
 * same except for using **vfree** to free the private
 */
static int seq_mbuf_release(struct inode *ino, struct file *f)
{
	struct seq_file *seq = f->private_data;

	put_net(seq_file_net(seq));
	vfree(seq->private);
	seq->private = NULL;
	seq_release(ino, f);
	return 0;
}

/* when write clear the data */
ssize_t seq_mbuf_write(struct file *f, const char __user *ubuf,
		       size_t size, loff_t *_pos)
{
	struct seq_file *seq = f->private_data;
	struct mbuf_seq_data *p;
	struct mbuf_slot *mb;

	p = seq->private;
	mb = get_net_mbuf(p->snp.net);

	/* the netns not attached mbuf */
	if (!mb)
		return size;

	mbuf_reset(mb);
	return size;
}

/* seq_read have a mutex lock hold when called thoes function
 * while the mutex lock is bind to struct file, not to inode,
 * that mutex lock can control mutex access to mbuf among tasks
 * which have the same file object (eg: muti-threads of
 * a process)
 *
 * if there are muti-process access the mbuf, there have no
 * mutex accessing.
 */
static const struct seq_operations mbuf_seq_ops = {
	.show = netns_mbuf_show,
	.start = netns_mbuf_start,
	.next = netns_mbuf_next,
	.stop = netns_mbuf_stop,
};

static const struct proc_ops mbuf_seq_fops = {
	.proc_open	= seq_mbuf_open,
	.proc_read	= seq_read,
	.proc_write	= seq_mbuf_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_mbuf_release,
};

static int __net_init net_mbuf_init(struct net *net)
{
	int ret = 0;

	/* if mbuf alloc failed, make the netns create success
	 *
	 * returning error here will put a limit on max netns
	 * can be created on current system
	 *
	 * btw: mbuf_slot has a max num 1024 for now, if mbuf_slot
	 * is all used, more allocing may failed, what we can do
	 * is make usr interface not changed, and make netlat
	 * `speak nothing`
	 * cgroup is used for kabi
	 */
	net->mbuf.slot = mbuf_slot_alloc_v2((void *)net, NULL);
	if (!net->mbuf.slot)
		pr_err("fail alloc mbuf");

	net->mbuf.twatcher = proc_net_mkdir(net, "twatcher", net->proc_net);
	if (!net->mbuf.twatcher) {
		ret = -ENOMEM;
		goto free_mbuf;
	}

	net->mbuf.log = proc_create_net_data_ops("log", S_IFREG | 0644,
						 net->mbuf.twatcher,
						 &mbuf_seq_ops,
						 sizeof(struct mbuf_seq_data) + get_mbuf_slot_len(),
						 NULL, &mbuf_seq_fops);
	if (!net->mbuf.log) {
		ret = -ENOMEM;
		goto remove_watcher;
	}
	return ret;

remove_watcher:
	remove_proc_entry("twatcher", net->proc_net);

free_mbuf:
	if (net->mbuf.slot)
		mbuf_free_slot(net->mbuf.slot);
	return ret;
}

static void __net_exit net_mbuf_exit(struct net *net)
{
	remove_proc_entry("log", net->mbuf.twatcher);
	remove_proc_entry("twatcher", net->proc_net);

	/* if mbuf allocate failed, no need to free */
	if (!net->mbuf.slot)
		return;
	mbuf_free_slot(net->mbuf.slot);
}

static struct pernet_operations net_mbuf_ops = {
	.init = net_mbuf_init,
	.exit = net_mbuf_exit,
};

int  inet_mbuf_init(void)
{
	return register_pernet_subsys(&net_mbuf_ops);
}
EXPORT_SYMBOL(inet_mbuf_init);

void inet_mbuf_exit(void)
{
	unregister_pernet_subsys(&net_mbuf_ops);
}
EXPORT_SYMBOL(inet_mbuf_exit);
