/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2017-2018 Broadcom Limited
 * Copyright (c) 2018-2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/pci.h>
#include "bnxt_hsi.h"
#include "bnxt_compat.h"
#ifdef HAVE_DIM
#include <linux/dim.h>
#else
#include "bnxt_dim.h"
#endif
#include "bnxt.h"
#include "bnxt_debugfs.h"
#include "bnxt_hdbr.h"
#include "bnxt_udcc.h"
#include "cfa_types.h"
#include "bnxt_vfr.h"

#ifdef CONFIG_DEBUG_FS

static struct dentry *bnxt_debug_mnt;
static struct dentry *bnxt_debug_tf;

#if defined(CONFIG_BNXT_FLOWER_OFFLOAD)

static ssize_t debugfs_session_query_read(struct file *filep, char __user *buffer,
					  size_t count, loff_t *ppos)
{
	struct bnxt_udcc_session_entry *entry = filep->private_data;
	struct hwrm_udcc_session_query_output resp;
	int len = 0, size = 4096;
	char *buf;
	int rc;

	rc = bnxt_hwrm_udcc_session_query(entry->bp, entry->session_id, &resp);
	if (rc)
		return rc;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len = scnprintf(buf, size, "min_rtt_ns = %u\n",
			le32_to_cpu(resp.min_rtt_ns));
	len += scnprintf(buf + len, size - len, "max_rtt_ns = %u\n",
			le32_to_cpu(resp.max_rtt_ns));
	len += scnprintf(buf + len, size - len, "cur_rate_mbps = %u\n",
			le32_to_cpu(resp.cur_rate_mbps));
	len += scnprintf(buf + len, size - len, "tx_event_count = %u\n",
			le32_to_cpu(resp.tx_event_count));
	len += scnprintf(buf + len, size - len, "cnp_rx_event_count = %u\n",
			le32_to_cpu(resp.cnp_rx_event_count));
	len += scnprintf(buf + len, size - len, "rtt_req_count = %u\n",
			le32_to_cpu(resp.rtt_req_count));
	len += scnprintf(buf + len, size - len, "rtt_resp_count = %u\n",
			le32_to_cpu(resp.rtt_resp_count));
	len += scnprintf(buf + len, size - len, "tx_bytes_sent = %u\n",
			le32_to_cpu(resp.tx_bytes_count));
	len += scnprintf(buf + len, size - len, "tx_pkts_sent = %u\n",
			le32_to_cpu(resp.tx_packets_count));
	len += scnprintf(buf + len, size - len, "init_probes_sent = %u\n",
			le32_to_cpu(resp.init_probes_sent));
	len += scnprintf(buf + len, size - len, "term_probes_recv = %u\n",
			le32_to_cpu(resp.term_probes_recv));
	len += scnprintf(buf + len, size - len, "cnp_packets_recv = %u\n",
			le32_to_cpu(resp.cnp_packets_recv));
	len += scnprintf(buf + len, size - len, "rto_event_recv = %u\n",
			le32_to_cpu(resp.rto_event_recv));
	len += scnprintf(buf + len, size - len, "seq_err_nak_recv = %u\n",
			le32_to_cpu(resp.seq_err_nak_recv));
	len += scnprintf(buf + len, size - len, "qp_count = %u\n",
			le32_to_cpu(resp.qp_count));

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
	kfree(buf);
	return len;
}

static const struct file_operations session_query_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= debugfs_session_query_read,
};

void bnxt_debugfs_create_udcc_session(struct bnxt *bp, u32 session_id)
{
	struct bnxt_udcc_info *udcc = bp->udcc_info;
	struct bnxt_udcc_session_entry *entry;
	static char sname[16];

	entry = udcc->session_db[session_id];

	if (entry->debugfs_dir || !bp->debugfs_pdev)
		return;

	snprintf(sname, 10, "%d", session_id);

	entry->debugfs_dir = debugfs_create_dir(sname, bp->udcc_info->udcc_debugfs_dir);
	entry->bp = bp;

	debugfs_create_file("session_query", 0644, entry->debugfs_dir, entry, &session_query_fops);
}

void bnxt_debugfs_delete_udcc_session(struct bnxt *bp, u32 session_id)
{
	struct bnxt_udcc_info *udcc = bp->udcc_info;
	struct bnxt_udcc_session_entry *entry;

	entry = udcc->session_db[session_id];
	if (!entry->debugfs_dir || !bp->debugfs_pdev)
		return;

	debugfs_remove_recursive(entry->debugfs_dir);
	entry->debugfs_dir = NULL;
}
#endif

static ssize_t debugfs_dim_read(struct file *filep,
				char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct dim *dim = filep->private_data;
	int len;
	char *buf;

	if (*ppos)
		return 0;
	if (!dim)
		return -ENODEV;
	buf = kasprintf(GFP_KERNEL,
			"state = %d\n" \
			"profile_ix = %d\n" \
			"mode = %d\n" \
			"tune_state = %d\n" \
			"steps_right = %d\n" \
			"steps_left = %d\n" \
			"tired = %d\n",
			dim->state,
			dim->profile_ix,
			dim->mode,
			dim->tune_state,
			dim->steps_right,
			dim->steps_left,
			dim->tired);
	if (!buf)
		return -ENOMEM;
	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}
	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
	kfree(buf);
	return len;
}

static const struct file_operations debugfs_dim_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = debugfs_dim_read,
};

static void debugfs_dim_ring_init(struct dim *dim, int ring_idx,
				  struct dentry *dd)
{
	static char qname[16];

	snprintf(qname, 10, "%d", ring_idx);
	debugfs_create_file(qname, 0600, dd, dim, &debugfs_dim_fops);
}

static int dbr_enable_get(void *data, u64 *val)
{
	struct bnxt *bp = data;

	*val = bp->dbr.enable;
	return 0;
}

static int dbr_enable_set(void *data, u64 val)
{
	struct bnxt *bp = data;
	struct bnxt_dbr *dbr;
	int rc;

	dbr = &bp->dbr;

	if (val) {
		dbr->enable = 1;
		rc = bnxt_dbr_init(bp);
		if (rc) {
			netdev_err(bp->dev,
				   "Failed to initialize DB recovery\n");
			dbr->enable = 0;
			return rc;
		}
	} else {
		dbr->enable = 0;
		bnxt_dbr_exit(bp);
	}

	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(dbr_enable_fops, dbr_enable_get, dbr_enable_set,
			 "%llu\n");

static ssize_t dbr_stats_read(struct file *filep, char __user *buffer,
size_t count, loff_t *ppos)
{
	struct bnxt_dbr_sw_stats *stat = filep->private_data;
	char *buf;
	int len;

	if (*ppos)
		return 0;

	buf = kasprintf(GFP_KERNEL, "nr_dbr = %u\n" "avg_dbr_us = %llu\n" \
			"max_dbr_us = %llu\n" "min_dbr_us = %llu\n",
			stat->nr_dbr, stat->avg_dbr_us, stat->max_dbr_us,
			stat->min_dbr_us);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
	kfree(buf);

	return len;
}

static const struct file_operations dbr_stats_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = dbr_stats_read,
};

static int dbr_test_recover_enable_get(void *data, u64 *val)
{
	struct bnxt *bp = data;

	*val = bp->dbr.debug.recover_enable;
	return 0;
}

static int dbr_test_recover_enable_set(void *data, u64 val)
{
	struct bnxt_dbr_debug *debug;
	struct bnxt *bp = data;
	struct bnxt_dbr *dbr;

	dbr = &bp->dbr;
	debug = &dbr->debug;

	if (!dbr->enable && val) {
		netdev_err(bp->dev,
			   "Unable to run DB recovery test when DBR is disabled\n");
		return -EINVAL;
	}

	if (val) {
		debug->recover_enable = 1;
		if (dbr->wq)
			/* kick start the recovery work */
			if (queue_delayed_work(dbr->wq, &dbr->dwork,
					       msecs_to_jiffies(debug->recover_interval_ms)))
			    atomic_inc(&dbr->event_cnt);
	} else {
		debug->recover_enable = 0;
	}

	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(dbr_test_recover_enable_fops,
			 dbr_test_recover_enable_get,
			 dbr_test_recover_enable_set,
			 "%llu\n");

static ssize_t hdbr_debug_trace_read(struct file *filep, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct bnxt *bp = filep->private_data;
	int len = 2;
	char buf[2];

	if (*ppos)
		return 0;
	if (!bp)
		return -ENODEV;
	if (count < len)
		return -ENOSPC;

	if (bp->hdbr_info.debug_trace)
		buf[0] = '1';
	else
		buf[0] = '0';
	buf[1] = '\n';

	return simple_read_from_buffer(buffer, count, ppos, buf, len);
}

static ssize_t hdbr_debug_trace_write(struct file *file, const char __user *u,
				      size_t size, loff_t *off)
{
	struct bnxt *bp = file->private_data;
	char u_in[2];
	size_t n;

	if (!bp)
		return -ENODEV;
	if (*off || !size || size > 2)
		return -EFAULT;

	n = simple_write_to_buffer(u_in, size, off, u, 2);
	if (n != size)
		return -EFAULT;

	if (u_in[0] == '0')
		bp->hdbr_info.debug_trace = 0;
	else
		bp->hdbr_info.debug_trace = 1;

	return size;
}

static const struct file_operations hdbr_debug_trace_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= hdbr_debug_trace_read,
	.write	= hdbr_debug_trace_write,
};

static ssize_t debugfs_hdbr_kdmp_read(struct file *filep, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	struct bnxt_hdbr_ktbl *ktbl = *((void **)filep->private_data);
	size_t len;
	char *buf;

	if (*ppos)
		return 0;
	if (!ktbl)
		return -ENODEV;

	buf = bnxt_hdbr_ktbl_dump(ktbl);
	if (!buf)
		return -ENOMEM;
	len = strlen(buf);
	if (count < len) {
		kfree(buf);
		return -ENOSPC;
	}
	len = simple_read_from_buffer(buffer, count, ppos, buf, len);
	kfree(buf);
	return len;
}

static const struct file_operations hdbr_kdmp_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= debugfs_hdbr_kdmp_read,
};

static ssize_t debugfs_hdbr_l2dmp_read(struct file *filep, char __user *buffer,
				       size_t count, loff_t *ppos)
{
	struct bnxt_hdbr_l2_pgs *l2pgs = *((void **)filep->private_data);
	size_t len;
	char *buf;

	if (*ppos)
		return 0;
	if (!l2pgs)
		return -ENODEV;

	buf = bnxt_hdbr_l2pg_dump(l2pgs);
	if (!buf)
		return -ENOMEM;
	len = strlen(buf);
	if (count < len) {
		kfree(buf);
		return -ENOSPC;
	}
	len = simple_read_from_buffer(buffer, count, ppos, buf, len);
	kfree(buf);
	return len;
}

static const struct file_operations hdbr_l2dmp_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= debugfs_hdbr_l2dmp_read,
};

static void bnxt_debugfs_hdbr_init(struct bnxt *bp)
{
	const char *pname = pci_name(bp->pdev);
	struct dentry *pdevf, *phdbr, *pktbl, *pl2pgs;
	int i;
	char *names[4] = {"sq", "rq", "srq", "cq"};

	if (!bp->hdbr_info.hdbr_enabled)
		return;

	/* Create top dir */
	phdbr = debugfs_create_dir("hdbr", bp->debugfs_pdev);
	if (!phdbr) {
		pr_err("Failed to create debugfs entry %s/hdbr\n", pname);
		return;
	}

	/* Create debug_trace knob */
	pdevf = debugfs_create_file("debug_trace", 0644, phdbr, bp, &hdbr_debug_trace_fops);
	if (!pdevf) {
		pr_err("Failed to create debugfs entry %s/hdbr/debug_trace\n", pname);
		return;
	}

	/* Create ktbl dir */
	pktbl = debugfs_create_dir("ktbl", phdbr);
	if (!pktbl) {
		pr_err("Failed to create debugfs entry %s/hdbr/ktbl\n", pname);
		return;
	}

	/* Create l2pgs dir */
	pl2pgs = debugfs_create_dir("l2pgs", phdbr);
	if (!pl2pgs) {
		pr_err("Failed to create debugfs entry %s/hdbr/l2pgs\n", pname);
		return;
	}

	/* Create hdbr kernel page and L2 page dumping knobs */
	for (i = 0; i < DBC_GROUP_MAX; i++) {
		pdevf = debugfs_create_file(names[i], 0644, pktbl, &bp->hdbr_info.ktbl[i],
					    &hdbr_kdmp_fops);
		if (!pdevf) {
			pr_err("Failed to create debugfs entry %s/hdbr/ktbl/%s\n",
			       pname, names[i]);
			return;
		}
		if (i == DBC_GROUP_RQ)
			continue;
		pdevf = debugfs_create_file(names[i], 0644, pl2pgs, &bp->hdbr_pgs[i],
					    &hdbr_l2dmp_fops);
		if (!pdevf) {
			pr_err("Failed to create debugfs entry %s/hdbr/l2pgs/%s\n",
			       pname, names[i]);
			return;
		}
	}
}

#define BNXT_DEBUGFS_TRUFLOW "truflow"

int bnxt_debug_tf_create(struct bnxt *bp, u8 tsid)
{
	char name[32];
	struct dentry *port_dir;

	bnxt_debug_tf = debugfs_lookup(BNXT_DEBUGFS_TRUFLOW, bnxt_debug_mnt);

	if (!bnxt_debug_tf)
		return -ENODEV;

	/* If not there create the port # directory */
	sprintf(name, "%d", bp->pf.port_id);
	port_dir = debugfs_lookup(name, bnxt_debug_tf);

	if (!port_dir) {
		port_dir = debugfs_create_dir(name, bnxt_debug_tf);
		if (!port_dir) {
			pr_debug("Failed to create TF debugfs port %d directory.\n",
				 bp->pf.port_id);
			return -ENODEV;
		}
	}
	/* Call TF function to create the table scope debugfs seq files */
	bnxt_tf_debugfs_create_files(bp, tsid, port_dir);

	return 0;
}

void bnxt_debug_tf_delete(struct bnxt *bp)
{
	char name[32];
	struct dentry *port_dir;

	if (!bnxt_debug_tf)
		return;

	sprintf(name, "%d", bp->pf.port_id);
	port_dir = debugfs_lookup(name, bnxt_debug_tf);
	if (port_dir)
		debugfs_remove_recursive(port_dir);
}

void bnxt_debug_dev_init(struct bnxt *bp)
{
	const char *pname = pci_name(bp->pdev);
	struct bnxt_dbr_debug *debug;
	struct bnxt_dbr *dbr;
	struct dentry *dir;
	int i;

	bp->debugfs_pdev = debugfs_create_dir(pname, bnxt_debug_mnt);
	dir = debugfs_create_dir("dim", bp->debugfs_pdev);

	/* Create files for each rx ring */
	for (i = 0; i < bp->cp_nr_rings; i++) {
		struct bnxt_cp_ring_info *cpr = &bp->bnapi[i]->cp_ring;

		if (cpr && bp->bnapi[i]->rx_ring)
			debugfs_dim_ring_init(&cpr->dim, i, dir);
	}

#define DBR_TEST_RECOVER_INTERVAL_MS 1000
#define DBR_TEST_DROP_RATIO          10
	dbr = &bp->dbr;
	debug = &bp->dbr.debug;

	debug->recover_interval_ms = DBR_TEST_RECOVER_INTERVAL_MS;
	debug->drop_ratio = DBR_TEST_DROP_RATIO;

	dir = debugfs_create_dir("dbr", bp->debugfs_pdev);
	debugfs_create_file("dbr_enable", 0644, dir, bp, &dbr_enable_fops);
	debugfs_create_file("dbr_stats", 0444, dir, &dbr->sw_stats,
			    &dbr_stats_fops);
#ifdef DBR_DBG_DROP_ENABLE
	debugfs_create_u8("dbr_test_drop_enable", 0644, dir,
			  &debug->drop_enable);
	debugfs_create_u32("dbr_test_drop_ratio", 0644, dir,
			   &debug->drop_ratio);
#endif
	debugfs_create_file("dbr_test_recover_enable", 0644, dir, bp,
			    &dbr_test_recover_enable_fops);
	debugfs_create_u32("dbr_test_recover_interval_ms", 0644, dir,
			   &debug->recover_interval_ms);

	bnxt_debugfs_hdbr_init(bp);

#if defined(CONFIG_BNXT_FLOWER_OFFLOAD)
	if (bp->udcc_info)
		bp->udcc_info->udcc_debugfs_dir = debugfs_create_dir("udcc", bp->debugfs_pdev);
#endif
}

void bnxt_debug_dev_exit(struct bnxt *bp)
{
	struct bnxt_dbr_debug *debug = &bp->dbr.debug;

	if (!bp)
		return;

	memset(debug, 0, sizeof(*debug));

	debugfs_remove_recursive(bp->debugfs_pdev);
	bp->debugfs_pdev = NULL;
}

void bnxt_debug_init(void)
{
	bnxt_debug_mnt = debugfs_create_dir("bnxt_en", NULL);
	if (!bnxt_debug_mnt) {
		pr_err("failed to init bnxt_en debugfs\n");
		return;
	}

	bnxt_debug_tf = debugfs_create_dir(BNXT_DEBUGFS_TRUFLOW,
					   bnxt_debug_mnt);

	if (!bnxt_debug_tf)
		pr_err("Failed to create TF debugfs backingstore directory.\n");
}

void bnxt_debug_exit(void)
{
	/* Remove subdirectories.  Older kernels have bug in remove for 2 level
	 * directories.
	 */
	debugfs_remove_recursive(bnxt_debug_tf);
	debugfs_remove_recursive(bnxt_debug_mnt);
}

#endif /* CONFIG_DEBUG_FS */
