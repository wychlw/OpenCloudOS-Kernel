// SPDX-License-Identifier: GPL-2.0-only
/*
 * sysctl.c: General linux system control interface
 *
 * Begun 24 March 1995, Stephen Tweedie
 * Added /proc support, Dec 1995
 * Added bdflush entry and intvec min/max checking, 2/23/96, Tom Dyas.
 * Added hooks for /proc/sys/net (minor, minor patch), 96/4/1, Mike Shaver.
 * Added kernel/java-{interpreter,appletviewer}, 96/5/10, Mike Shaver.
 * Dynamic registration fixes, Stephen Tweedie.
 * Added kswapd-interval, ctrl-alt-del, printk stuff, 1/8/97, Chris Horn.
 * Made sysctl support optional via CONFIG_SYSCTL, 1/10/97, Chris
 *  Horn.
 * Added proc_doulongvec_ms_jiffies_minmax, 09/08/99, Carlos H. Bauer.
 * Added proc_doulongvec_minmax, 09/08/99, Carlos H. Bauer.
 * Changed linked lists to use list.h instead of lists.h, 02/24/00, Bill
 *  Wendling.
 * The list_for_each() macro wasn't appropriate for the sysctl loop.
 *  Removed it and replaced it with older style, 03/23/00, Bill Wendling
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/bitmap.h>
#include <linux/signal.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/ctype.h>
#include <linux/kmemleak.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/net.h>
#include <linux/sysrq.h>
#include <linux/highuid.h>
#include <linux/writeback.h>
#include <linux/ratelimit.h>
#include <linux/hugetlb.h>
#include <linux/initrd.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>
#include <linux/vmstat.h>
#include <linux/nfs_fs.h>
#include <linux/acpi.h>
#include <linux/reboot.h>
#include <linux/ftrace.h>
#include <linux/perf_event.h>
#include <linux/oom.h>
#include <linux/kmod.h>
#include <linux/capability.h>
#include <linux/binfmts.h>
#include <linux/sched/sysctl.h>
#include <linux/mount.h>
#include <linux/userfaultfd_k.h>
#include <linux/pid.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>

#ifdef CONFIG_BLK_DEV_THROTTLING_CGROUP_V1
#include <linux/blk-cgroup.h>
#endif

#include "../lib/kstrtox.h"

#include <linux/uaccess.h>
#include <asm/processor.h>
#include <linux/memcontrol.h>
#include <linux/rue.h>

#ifdef CONFIG_X86
#include <asm/nmi.h>
#include <asm/stacktrace.h>
#include <asm/io.h>
#endif
#ifdef CONFIG_SPARC
#include <asm/setup.h>
#endif
#ifdef CONFIG_RT_MUTEXES
#include <linux/rtmutex.h>
#endif

/* shared constants to be used in various sysctls */
const int sysctl_vals[] = { 0, 1, 2, 3, 4, 100, 200, 1000, 3000, INT_MAX, 65535, -1 };
EXPORT_SYMBOL(sysctl_vals);

const unsigned long sysctl_long_vals[] = { 0, 1, LONG_MAX };
EXPORT_SYMBOL_GPL(sysctl_long_vals);

#if defined(CONFIG_SYSCTL)

#ifdef CONFIG_RQM
extern int sysctl_qos_mbuf_enable;
#endif

#ifdef CONFIG_MEMCG
extern int sysctl_vm_memory_qos;
extern int sysctl_vm_use_priority_oom;
extern int sysctl_vm_qos_highest_reclaim_prio;
extern unsigned int sysctl_vm_qos_prio_reclaim_ratio;
extern unsigned int sysctl_clean_dying_memcg_async;
static int vm_lowest_prio = CGROUP_PRIORITY_MAX;
static int twenty = 20;
#endif

extern unsigned long sysctl_async_mem_free_pages;

/* Constants used for minimum and maximum */

#ifdef CONFIG_PERF_EVENTS
static const int six_hundred_forty_kb = 640 * 1024;
#endif


static const int ngroups_max = NGROUPS_MAX;
static const int cap_last_cap = CAP_LAST_CAP;

#ifdef CONFIG_PROC_SYSCTL

/**
 * enum sysctl_writes_mode - supported sysctl write modes
 *
 * @SYSCTL_WRITES_LEGACY: each write syscall must fully contain the sysctl value
 *	to be written, and multiple writes on the same sysctl file descriptor
 *	will rewrite the sysctl value, regardless of file position. No warning
 *	is issued when the initial position is not 0.
 * @SYSCTL_WRITES_WARN: same as above but warn when the initial file position is
 *	not 0.
 * @SYSCTL_WRITES_STRICT: writes to numeric sysctl entries must always be at
 *	file position 0 and the value must be fully contained in the buffer
 *	sent to the write syscall. If dealing with strings respect the file
 *	position, but restrict this to the max length of the buffer, anything
 *	passed the max length will be ignored. Multiple writes will append
 *	to the buffer.
 *
 * These write modes control how current file position affects the behavior of
 * updating sysctl values through the proc interface on each write.
 */
enum sysctl_writes_mode {
	SYSCTL_WRITES_LEGACY		= -1,
	SYSCTL_WRITES_WARN		= 0,
	SYSCTL_WRITES_STRICT		= 1,
};

static enum sysctl_writes_mode sysctl_writes_strict = SYSCTL_WRITES_STRICT;
#endif /* CONFIG_PROC_SYSCTL */

#if defined(HAVE_ARCH_PICK_MMAP_LAYOUT) || \
    defined(CONFIG_ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT)
int sysctl_legacy_va_layout;
#endif

#ifdef CONFIG_CGROUPFS
extern int container_cpuquota_aware;
extern int cgroupfs_stat_show_cpuacct_info;
int cgroupfs_mounted;
#endif

#ifdef CONFIG_EMM_FORCE_SWAPPINESS
extern int sysctl_vm_force_swappiness;
#endif

#ifdef CONFIG_EMM_RAMDISK_SWAP
extern int sysctl_vm_ramdisk_swaptune;
extern int sysctl_vm_swapcache_fastfree;
#endif

#if defined(CONFIG_MEMCG) && defined(CONFIG_BLK_CGROUP)
extern unsigned int sysctl_allow_memcg_migrate_ignore_blkio_bind __read_mostly;
#endif

#ifdef CONFIG_TKERNEL_SECURITY_MONITOR
unsigned long connect_info_flag;
unsigned long accept_info_flag;
unsigned long sendto_info_flag;
unsigned long recvfrom_info_flag;
unsigned long execve_info_flag;
unsigned long sock_info_flag;
unsigned long fork_info_flag;
unsigned long exit_info_flag;
#endif

#endif /* CONFIG_SYSCTL */

/*
 * /proc/sys support
 */

#ifdef CONFIG_PROC_SYSCTL

static int _proc_do_string(char *data, int maxlen, int write,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	size_t len;
	char c, *p;

	if (!data || !maxlen || !*lenp) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		if (sysctl_writes_strict == SYSCTL_WRITES_STRICT) {
			/* Only continue writes not past the end of buffer. */
			len = strlen(data);
			if (len > maxlen - 1)
				len = maxlen - 1;

			if (*ppos > len)
				return 0;
			len = *ppos;
		} else {
			/* Start writing from beginning of buffer. */
			len = 0;
		}

		*ppos += *lenp;
		p = buffer;
		while ((p - buffer) < *lenp && len < maxlen - 1) {
			c = *(p++);
			if (c == 0 || c == '\n')
				break;
			data[len++] = c;
		}
		data[len] = 0;
	} else {
		len = strlen(data);
		if (len > maxlen)
			len = maxlen;

		if (*ppos > len) {
			*lenp = 0;
			return 0;
		}

		data += *ppos;
		len  -= *ppos;

		if (len > *lenp)
			len = *lenp;
		if (len)
			memcpy(buffer, data, len);
		if (len < *lenp) {
			buffer[len] = '\n';
			len++;
		}
		*lenp = len;
		*ppos += len;
	}
	return 0;
}

static void warn_sysctl_write(struct ctl_table *table)
{
	pr_warn_once("%s wrote to %s when file position was not 0!\n"
		"This will not be supported in the future. To silence this\n"
		"warning, set kernel.sysctl_writes_strict = -1\n",
		current->comm, table->procname);
}

/**
 * proc_first_pos_non_zero_ignore - check if first position is allowed
 * @ppos: file position
 * @table: the sysctl table
 *
 * Returns true if the first position is non-zero and the sysctl_writes_strict
 * mode indicates this is not allowed for numeric input types. String proc
 * handlers can ignore the return value.
 */
static bool proc_first_pos_non_zero_ignore(loff_t *ppos,
					   struct ctl_table *table)
{
	if (!*ppos)
		return false;

	switch (sysctl_writes_strict) {
	case SYSCTL_WRITES_STRICT:
		return true;
	case SYSCTL_WRITES_WARN:
		warn_sysctl_write(table);
		return false;
	default:
		return false;
	}
}

/**
 * proc_dostring - read a string sysctl
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes a string from/to the user buffer. If the kernel
 * buffer provided is not large enough to hold the string, the
 * string is truncated. The copied string is %NULL-terminated.
 * If the string is being read by the user process, it is copied
 * and a newline '\n' is added. It is truncated if the buffer is
 * not large enough.
 *
 * Returns 0 on success.
 */
int proc_dostring(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	if (write)
		proc_first_pos_non_zero_ignore(ppos, table);

	return _proc_do_string(table->data, table->maxlen, write, buffer, lenp,
			ppos);
}

static void proc_skip_spaces(char **buf, size_t *size)
{
	while (*size) {
		if (!isspace(**buf))
			break;
		(*size)--;
		(*buf)++;
	}
}

static void proc_skip_char(char **buf, size_t *size, const char v)
{
	while (*size) {
		if (**buf != v)
			break;
		(*size)--;
		(*buf)++;
	}
}

/**
 * strtoul_lenient - parse an ASCII formatted integer from a buffer and only
 *                   fail on overflow
 *
 * @cp: kernel buffer containing the string to parse
 * @endp: pointer to store the trailing characters
 * @base: the base to use
 * @res: where the parsed integer will be stored
 *
 * In case of success 0 is returned and @res will contain the parsed integer,
 * @endp will hold any trailing characters.
 * This function will fail the parse on overflow. If there wasn't an overflow
 * the function will defer the decision what characters count as invalid to the
 * caller.
 */
static int strtoul_lenient(const char *cp, char **endp, unsigned int base,
			   unsigned long *res)
{
	unsigned long long result;
	unsigned int rv;

	cp = _parse_integer_fixup_radix(cp, &base);
	rv = _parse_integer(cp, base, &result);
	if ((rv & KSTRTOX_OVERFLOW) || (result != (unsigned long)result))
		return -ERANGE;

	cp += rv;

	if (endp)
		*endp = (char *)cp;

	*res = (unsigned long)result;
	return 0;
}

#define TMPBUFLEN 22
/**
 * proc_get_long - reads an ASCII formatted integer from a user buffer
 *
 * @buf: a kernel buffer
 * @size: size of the kernel buffer
 * @val: this is where the number will be stored
 * @neg: set to %TRUE if number is negative
 * @perm_tr: a vector which contains the allowed trailers
 * @perm_tr_len: size of the perm_tr vector
 * @tr: pointer to store the trailer character
 *
 * In case of success %0 is returned and @buf and @size are updated with
 * the amount of bytes read. If @tr is non-NULL and a trailing
 * character exists (size is non-zero after returning from this
 * function), @tr is updated with the trailing character.
 */
static int proc_get_long(char **buf, size_t *size,
			  unsigned long *val, bool *neg,
			  const char *perm_tr, unsigned perm_tr_len, char *tr)
{
	char *p, tmp[TMPBUFLEN];
	ssize_t len = *size;

	if (len <= 0)
		return -EINVAL;

	if (len > TMPBUFLEN - 1)
		len = TMPBUFLEN - 1;

	memcpy(tmp, *buf, len);

	tmp[len] = 0;
	p = tmp;
	if (*p == '-' && *size > 1) {
		*neg = true;
		p++;
	} else
		*neg = false;
	if (!isdigit(*p))
		return -EINVAL;

	if (strtoul_lenient(p, &p, 0, val))
		return -EINVAL;

	len = p - tmp;

	/* We don't know if the next char is whitespace thus we may accept
	 * invalid integers (e.g. 1234...a) or two integers instead of one
	 * (e.g. 123...1). So lets not allow such large numbers. */
	if (len == TMPBUFLEN - 1)
		return -EINVAL;

	if (len < *size && perm_tr_len && !memchr(perm_tr, *p, perm_tr_len))
		return -EINVAL;

	if (tr && (len < *size))
		*tr = *p;

	*buf += len;
	*size -= len;

	return 0;
}

/**
 * proc_put_long - converts an integer to a decimal ASCII formatted string
 *
 * @buf: the user buffer
 * @size: the size of the user buffer
 * @val: the integer to be converted
 * @neg: sign of the number, %TRUE for negative
 *
 * In case of success @buf and @size are updated with the amount of bytes
 * written.
 */
static void proc_put_long(void **buf, size_t *size, unsigned long val, bool neg)
{
	int len;
	char tmp[TMPBUFLEN], *p = tmp;

	sprintf(p, "%s%lu", neg ? "-" : "", val);
	len = strlen(tmp);
	if (len > *size)
		len = *size;
	memcpy(*buf, tmp, len);
	*size -= len;
	*buf += len;
}
#undef TMPBUFLEN

static void proc_put_char(void **buf, size_t *size, char c)
{
	if (*size) {
		char **buffer = (char **)buf;
		**buffer = c;

		(*size)--;
		(*buffer)++;
		*buf = *buffer;
	}
}

static int do_proc_dointvec_conv(bool *negp, unsigned long *lvalp,
				 int *valp,
				 int write, void *data)
{
	if (write) {
		if (*negp) {
			if (*lvalp > (unsigned long) INT_MAX + 1)
				return -EINVAL;
			WRITE_ONCE(*valp, -*lvalp);
		} else {
			if (*lvalp > (unsigned long) INT_MAX)
				return -EINVAL;
			WRITE_ONCE(*valp, *lvalp);
		}
	} else {
		int val = READ_ONCE(*valp);
		if (val < 0) {
			*negp = true;
			*lvalp = -(unsigned long)val;
		} else {
			*negp = false;
			*lvalp = (unsigned long)val;
		}
	}
	return 0;
}

static int do_proc_douintvec_conv(unsigned long *lvalp,
				  unsigned int *valp,
				  int write, void *data)
{
	if (write) {
		if (*lvalp > UINT_MAX)
			return -EINVAL;
		WRITE_ONCE(*valp, *lvalp);
	} else {
		unsigned int val = READ_ONCE(*valp);
		*lvalp = (unsigned long)val;
	}
	return 0;
}

static const char proc_wspace_sep[] = { ' ', '\t', '\n' };

static int __do_proc_dointvec(void *tbl_data, struct ctl_table *table,
		  int write, void *buffer,
		  size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	int *i, vleft, first = 1, err = 0;
	size_t left;
	char *p;

	if (!tbl_data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = (int *) tbl_data;
	vleft = table->maxlen / sizeof(*i);
	left = *lenp;

	if (!conv)
		conv = do_proc_dointvec_conv;

	if (write) {
		if (proc_first_pos_non_zero_ignore(ppos, table))
			goto out;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;
		p = buffer;
	}

	for (; left && vleft--; i++, first=0) {
		unsigned long lval;
		bool neg;

		if (write) {
			proc_skip_spaces(&p, &left);

			if (!left)
				break;
			err = proc_get_long(&p, &left, &lval, &neg,
					     proc_wspace_sep,
					     sizeof(proc_wspace_sep), NULL);
			if (err)
				break;
			if (conv(&neg, &lval, i, 1, data)) {
				err = -EINVAL;
				break;
			}
		} else {
			if (conv(&neg, &lval, i, 0, data)) {
				err = -EINVAL;
				break;
			}
			if (!first)
				proc_put_char(&buffer, &left, '\t');
			proc_put_long(&buffer, &left, lval, neg);
		}
	}

	if (!write && !first && left && !err)
		proc_put_char(&buffer, &left, '\n');
	if (write && !err && left)
		proc_skip_spaces(&p, &left);
	if (write && first)
		return err ? : -EINVAL;
	*lenp -= left;
out:
	*ppos += *lenp;
	return err;
}

static int do_proc_dointvec(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	return __do_proc_dointvec(table->data, table, write,
			buffer, lenp, ppos, conv, data);
}

static int setup_pagecache_limit(void)
{
	/* reclaim ADDITIONAL_RECLAIM_PAGES more than limit. */
	vm_pagecache_limit_reclaim_ratio = vm_pagecache_limit_ratio + ADDITIONAL_RECLAIM_RATIO;

	if (vm_pagecache_limit_reclaim_ratio > 100)
		vm_pagecache_limit_reclaim_ratio = 100;
	if (vm_pagecache_limit_ratio == 0)
		vm_pagecache_limit_reclaim_ratio = 0;

	vm_pagecache_limit_pages = vm_pagecache_limit_ratio * totalram_pages() / 100;
	vm_pagecache_limit_reclaim_pages = vm_pagecache_limit_reclaim_ratio * totalram_pages() / 100;

	return 0;
}

static int pc_limit_proc_dointvec(struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && !ret)
		ret = setup_pagecache_limit();

	return ret;
}

static int pc_reclaim_limit_proc_dointvec(struct ctl_table *table, int write,
					  void *buffer, size_t *lenp, loff_t *ppos)
{
	int pre_reclaim_ratio = vm_pagecache_limit_reclaim_ratio;
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && vm_pagecache_limit_ratio == 0)
		return -EINVAL;

	if (write && !ret) {
		if (vm_pagecache_limit_reclaim_ratio - vm_pagecache_limit_ratio < ADDITIONAL_RECLAIM_RATIO) {
			vm_pagecache_limit_reclaim_ratio = pre_reclaim_ratio;
			return -EINVAL;
		}
		vm_pagecache_limit_reclaim_pages = vm_pagecache_limit_reclaim_ratio * totalram_pages() / 100;
	}
	return ret;
}

static int pc_limit_async_handler(struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && vm_pagecache_limit_ratio == 0)
		return -EINVAL;

	if (write && !ret) {
		if (vm_pagecache_limit_async > 0) {
			if (kpagecache_limitd_run()) {
				vm_pagecache_limit_async = 0;
				return -EINVAL;
			}
		} else {
			kpagecache_limitd_stop();
		}
	}

	return ret;
}

static int do_proc_douintvec_w(unsigned int *tbl_data,
			       struct ctl_table *table,
			       void *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned long lval;
	int err = 0;
	size_t left;
	bool neg;
	char *p = buffer;

	left = *lenp;

	if (proc_first_pos_non_zero_ignore(ppos, table))
		goto bail_early;

	if (left > PAGE_SIZE - 1)
		left = PAGE_SIZE - 1;

	proc_skip_spaces(&p, &left);
	if (!left) {
		err = -EINVAL;
		goto out_free;
	}

	err = proc_get_long(&p, &left, &lval, &neg,
			     proc_wspace_sep,
			     sizeof(proc_wspace_sep), NULL);
	if (err || neg) {
		err = -EINVAL;
		goto out_free;
	}

	if (conv(&lval, tbl_data, 1, data)) {
		err = -EINVAL;
		goto out_free;
	}

	if (!err && left)
		proc_skip_spaces(&p, &left);

out_free:
	if (err)
		return -EINVAL;

	return 0;

	/* This is in keeping with old __do_proc_dointvec() */
bail_early:
	*ppos += *lenp;
	return err;
}

static int do_proc_douintvec_r(unsigned int *tbl_data, void *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned long lval;
	int err = 0;
	size_t left;

	left = *lenp;

	if (conv(&lval, tbl_data, 0, data)) {
		err = -EINVAL;
		goto out;
	}

	proc_put_long(&buffer, &left, lval, false);
	if (!left)
		goto out;

	proc_put_char(&buffer, &left, '\n');

out:
	*lenp -= left;
	*ppos += *lenp;

	return err;
}

static int __do_proc_douintvec(void *tbl_data, struct ctl_table *table,
			       int write, void *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned int *i, vleft;

	if (!tbl_data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = (unsigned int *) tbl_data;
	vleft = table->maxlen / sizeof(*i);

	/*
	 * Arrays are not supported, keep this simple. *Do not* add
	 * support for them.
	 */
	if (vleft != 1) {
		*lenp = 0;
		return -EINVAL;
	}

	if (!conv)
		conv = do_proc_douintvec_conv;

	if (write)
		return do_proc_douintvec_w(i, table, buffer, lenp, ppos,
					   conv, data);
	return do_proc_douintvec_r(i, buffer, lenp, ppos, conv, data);
}

int do_proc_douintvec(struct ctl_table *table, int write,
		      void *buffer, size_t *lenp, loff_t *ppos,
		      int (*conv)(unsigned long *lvalp,
				  unsigned int *valp,
				  int write, void *data),
		      void *data)
{
	return __do_proc_douintvec(table->data, table, write,
				   buffer, lenp, ppos, conv, data);
}

/**
 * proc_dobool - read/write a bool
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes one integer value from/to the user buffer,
 * treated as an ASCII string.
 *
 * table->data must point to a bool variable and table->maxlen must
 * be sizeof(bool).
 *
 * Returns 0 on success.
 */
int proc_dobool(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp;
	bool *data = table->data;
	int res, val;

	/* Do not support arrays yet. */
	if (table->maxlen != sizeof(bool))
		return -EINVAL;

	tmp = *table;
	tmp.maxlen = sizeof(val);
	tmp.data = &val;

	val = READ_ONCE(*data);
	res = proc_dointvec(&tmp, write, buffer, lenp, ppos);
	if (res)
		return res;
	if (write)
		WRITE_ONCE(*data, val);
	return 0;
}

/**
 * proc_dointvec - read a vector of integers
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string.
 *
 * Returns 0 on success.
 */
int proc_dointvec(struct ctl_table *table, int write, void *buffer,
		  size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, buffer, lenp, ppos, NULL, NULL);
}

/**
 * proc_douintvec - read a vector of unsigned integers
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) unsigned integer
 * values from/to the user buffer, treated as an ASCII string.
 *
 * Returns 0 on success.
 */
int proc_douintvec(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	return do_proc_douintvec(table, write, buffer, lenp, ppos,
				 do_proc_douintvec_conv, NULL);
}

/*
 * Taint values can only be increased
 * This means we can safely use a temporary.
 */
static int proc_taint(struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	unsigned long tmptaint = get_taint();
	int err;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &tmptaint;
	err = proc_doulongvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	if (write) {
		int i;

		/*
		 * If we are relying on panic_on_taint not producing
		 * false positives due to userspace input, bail out
		 * before setting the requested taint flags.
		 */
		if (panic_on_taint_nousertaint && (tmptaint & panic_on_taint))
			return -EINVAL;

		/*
		 * Poor man's atomic or. Not worth adding a primitive
		 * to everyone's atomic.h for this
		 */
		for (i = 0; i < TAINT_FLAGS_COUNT; i++)
			if ((1UL << i) & tmptaint)
				add_taint(i, LOCKDEP_STILL_OK);
	}

	return err;
}

/**
 * struct do_proc_dointvec_minmax_conv_param - proc_dointvec_minmax() range checking structure
 * @min: pointer to minimum allowable value
 * @max: pointer to maximum allowable value
 *
 * The do_proc_dointvec_minmax_conv_param structure provides the
 * minimum and maximum values for doing range checking for those sysctl
 * parameters that use the proc_dointvec_minmax() handler.
 */
struct do_proc_dointvec_minmax_conv_param {
	int *min;
	int *max;
};

static int do_proc_dointvec_minmax_conv(bool *negp, unsigned long *lvalp,
					int *valp,
					int write, void *data)
{
	int tmp, ret;
	struct do_proc_dointvec_minmax_conv_param *param = data;
	/*
	 * If writing, first do so via a temporary local int so we can
	 * bounds-check it before touching *valp.
	 */
	int *ip = write ? &tmp : valp;

	ret = do_proc_dointvec_conv(negp, lvalp, ip, write, data);
	if (ret)
		return ret;

	if (write) {
		if ((param->min && *param->min > tmp) ||
		    (param->max && *param->max < tmp))
			return -EINVAL;
		WRITE_ONCE(*valp, tmp);
	}

	return 0;
}

/**
 * proc_dointvec_minmax - read a vector of integers with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max).
 *
 * Returns 0 on success or -EINVAL on write when the range check fails.
 */
int proc_dointvec_minmax(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct do_proc_dointvec_minmax_conv_param param = {
		.min = (int *) table->extra1,
		.max = (int *) table->extra2,
	};
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
				do_proc_dointvec_minmax_conv, &param);
}

int proc_dointvec_max_map_count(struct ctl_table *table, int write,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{

	struct do_proc_dointvec_minmax_conv_param param = {
		.min = (int *) table->extra1,
		.max = (int *) table->extra2,
	};

#ifdef CONFIG_PID_NS
	table->data = &task_active_pid_ns(current)->max_map_count;
#endif

	return do_proc_dointvec(table, write, buffer, lenp, ppos,
			do_proc_dointvec_minmax_conv, &param);
}


/**
 * struct do_proc_douintvec_minmax_conv_param - proc_douintvec_minmax() range checking structure
 * @min: pointer to minimum allowable value
 * @max: pointer to maximum allowable value
 *
 * The do_proc_douintvec_minmax_conv_param structure provides the
 * minimum and maximum values for doing range checking for those sysctl
 * parameters that use the proc_douintvec_minmax() handler.
 */
struct do_proc_douintvec_minmax_conv_param {
	unsigned int *min;
	unsigned int *max;
};

static int do_proc_douintvec_minmax_conv(unsigned long *lvalp,
					 unsigned int *valp,
					 int write, void *data)
{
	int ret;
	unsigned int tmp;
	struct do_proc_douintvec_minmax_conv_param *param = data;
	/* write via temporary local uint for bounds-checking */
	unsigned int *up = write ? &tmp : valp;

	ret = do_proc_douintvec_conv(lvalp, up, write, data);
	if (ret)
		return ret;

	if (write) {
		if ((param->min && *param->min > tmp) ||
		    (param->max && *param->max < tmp))
			return -ERANGE;

		WRITE_ONCE(*valp, tmp);
	}

	return 0;
}

/**
 * proc_douintvec_minmax - read a vector of unsigned ints with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) unsigned integer
 * values from/to the user buffer, treated as an ASCII string. Negative
 * strings are not allowed.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max). There is a final sanity
 * check for UINT_MAX to avoid having to support wrap around uses from
 * userspace.
 *
 * Returns 0 on success or -ERANGE on write when the range check fails.
 */
int proc_douintvec_minmax(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct do_proc_douintvec_minmax_conv_param param = {
		.min = (unsigned int *) table->extra1,
		.max = (unsigned int *) table->extra2,
	};
	return do_proc_douintvec(table, write, buffer, lenp, ppos,
				 do_proc_douintvec_minmax_conv, &param);
}

/**
 * proc_dou8vec_minmax - read a vector of unsigned chars with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(u8) unsigned chars
 * values from/to the user buffer, treated as an ASCII string. Negative
 * strings are not allowed.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max).
 *
 * Returns 0 on success or an error on write when the range check fails.
 */
int proc_dou8vec_minmax(struct ctl_table *table, int write,
			void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp;
	unsigned int min = 0, max = 255U, val;
	u8 *data = table->data;
	struct do_proc_douintvec_minmax_conv_param param = {
		.min = &min,
		.max = &max,
	};
	int res;

	/* Do not support arrays yet. */
	if (table->maxlen != sizeof(u8))
		return -EINVAL;

	if (table->extra1) {
		min = *(unsigned int *) table->extra1;
		if (min > 255U)
			return -EINVAL;
	}
	if (table->extra2) {
		max = *(unsigned int *) table->extra2;
		if (max > 255U)
			return -EINVAL;
	}

	tmp = *table;

	tmp.maxlen = sizeof(val);
	tmp.data = &val;
	val = READ_ONCE(*data);
	res = do_proc_douintvec(&tmp, write, buffer, lenp, ppos,
				do_proc_douintvec_minmax_conv, &param);
	if (res)
		return res;
	if (write)
		WRITE_ONCE(*data, val);
	return 0;
}
EXPORT_SYMBOL_GPL(proc_dou8vec_minmax);

#ifdef CONFIG_MAGIC_SYSRQ
static int __sysrq_use_leftctrl = 1;

static int sysrq_sysctl_handler(struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	int tmp, ret;

	tmp = sysrq_mask();

	ret = __do_proc_dointvec(&tmp, table, write, buffer,
			       lenp, ppos, NULL, NULL);
	if (ret || !write)
		return ret;

	if (write)
		sysrq_toggle_support(tmp);

	return 0;
}

static int sysrq_use_leftctrl_sysctl_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int error;

	error = proc_dointvec(table, write, buffer, lenp, ppos);
	if (error)
		return error;

	if (write)
		sysrq_toggle_sysrq_key(__sysrq_use_leftctrl);

	return 0;
}
#endif

static int __do_proc_doulongvec_minmax(void *data, struct ctl_table *table,
		int write, void *buffer, size_t *lenp, loff_t *ppos,
		unsigned long convmul, unsigned long convdiv)
{
	unsigned long *i, *min, *max;
	int vleft, first = 1, err = 0;
	size_t left;
	char *p;

	if (!data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = data;
	min = table->extra1;
	max = table->extra2;
	vleft = table->maxlen / sizeof(unsigned long);
	left = *lenp;

	if (write) {
		if (proc_first_pos_non_zero_ignore(ppos, table))
			goto out;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;
		p = buffer;
	}

	for (; left && vleft--; i++, first = 0) {
		unsigned long val;

		if (write) {
			bool neg;

			proc_skip_spaces(&p, &left);
			if (!left)
				break;

			err = proc_get_long(&p, &left, &val, &neg,
					     proc_wspace_sep,
					     sizeof(proc_wspace_sep), NULL);
			if (err || neg) {
				err = -EINVAL;
				break;
			}

			val = convmul * val / convdiv;
			if ((min && val < *min) || (max && val > *max)) {
				err = -EINVAL;
				break;
			}
			WRITE_ONCE(*i, val);
		} else {
			val = convdiv * READ_ONCE(*i) / convmul;
			if (!first)
				proc_put_char(&buffer, &left, '\t');
			proc_put_long(&buffer, &left, val, false);
		}
	}

	if (!write && !first && left && !err)
		proc_put_char(&buffer, &left, '\n');
	if (write && !err)
		proc_skip_spaces(&p, &left);
	if (write && first)
		return err ? : -EINVAL;
	*lenp -= left;
out:
	*ppos += *lenp;
	return err;
}

static int do_proc_doulongvec_minmax(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos, unsigned long convmul,
		unsigned long convdiv)
{
	return __do_proc_doulongvec_minmax(table->data, table, write,
			buffer, lenp, ppos, convmul, convdiv);
}

/**
 * proc_doulongvec_minmax - read a vector of long integers with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned long) unsigned long
 * values from/to the user buffer, treated as an ASCII string.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max).
 *
 * Returns 0 on success.
 */
int proc_doulongvec_minmax(struct ctl_table *table, int write,
			   void *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_doulongvec_minmax(table, write, buffer, lenp, ppos, 1l, 1l);
}

/**
 * proc_doulongvec_ms_jiffies_minmax - read a vector of millisecond values with min/max values
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned long) unsigned long
 * values from/to the user buffer, treated as an ASCII string. The values
 * are treated as milliseconds, and converted to jiffies when they are stored.
 *
 * This routine will ensure the values are within the range specified by
 * table->extra1 (min) and table->extra2 (max).
 *
 * Returns 0 on success.
 */
int proc_doulongvec_ms_jiffies_minmax(struct ctl_table *table, int write,
				      void *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_doulongvec_minmax(table, write, buffer,
				     lenp, ppos, HZ, 1000l);
}


static int do_proc_dointvec_jiffies_conv(bool *negp, unsigned long *lvalp,
					 int *valp,
					 int write, void *data)
{
	if (write) {
		if (*lvalp > INT_MAX / HZ)
			return 1;
		if (*negp)
			WRITE_ONCE(*valp, -*lvalp * HZ);
		else
			WRITE_ONCE(*valp, *lvalp * HZ);
	} else {
		int val = READ_ONCE(*valp);
		unsigned long lval;
		if (val < 0) {
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = lval / HZ;
	}
	return 0;
}

static int do_proc_dointvec_userhz_jiffies_conv(bool *negp, unsigned long *lvalp,
						int *valp,
						int write, void *data)
{
	if (write) {
		if (USER_HZ < HZ && *lvalp > (LONG_MAX / HZ) * USER_HZ)
			return 1;
		*valp = clock_t_to_jiffies(*negp ? -*lvalp : *lvalp);
	} else {
		int val = *valp;
		unsigned long lval;
		if (val < 0) {
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = jiffies_to_clock_t(lval);
	}
	return 0;
}

static int do_proc_dointvec_ms_jiffies_conv(bool *negp, unsigned long *lvalp,
					    int *valp,
					    int write, void *data)
{
	if (write) {
		unsigned long jif = msecs_to_jiffies(*negp ? -*lvalp : *lvalp);

		if (jif > INT_MAX)
			return 1;
		WRITE_ONCE(*valp, (int)jif);
	} else {
		int val = READ_ONCE(*valp);
		unsigned long lval;
		if (val < 0) {
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = jiffies_to_msecs(lval);
	}
	return 0;
}

static int do_proc_dointvec_ms_jiffies_minmax_conv(bool *negp, unsigned long *lvalp,
						int *valp, int write, void *data)
{
	int tmp, ret;
	struct do_proc_dointvec_minmax_conv_param *param = data;
	/*
	 * If writing, first do so via a temporary local int so we can
	 * bounds-check it before touching *valp.
	 */
	int *ip = write ? &tmp : valp;

	ret = do_proc_dointvec_ms_jiffies_conv(negp, lvalp, ip, write, data);
	if (ret)
		return ret;

	if (write) {
		if ((param->min && *param->min > tmp) ||
				(param->max && *param->max < tmp))
			return -EINVAL;
		*valp = tmp;
	}
	return 0;
}

/**
 * proc_dointvec_jiffies - read a vector of integers as seconds
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string.
 * The values read are assumed to be in seconds, and are converted into
 * jiffies.
 *
 * Returns 0 on success.
 */
int proc_dointvec_jiffies(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_dointvec(table,write,buffer,lenp,ppos,
		    	    do_proc_dointvec_jiffies_conv,NULL);
}

int proc_dointvec_ms_jiffies_minmax(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct do_proc_dointvec_minmax_conv_param param = {
		.min = (int *) table->extra1,
		.max = (int *) table->extra2,
	};
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
			do_proc_dointvec_ms_jiffies_minmax_conv, &param);
}

/**
 * proc_dointvec_userhz_jiffies - read a vector of integers as 1/USER_HZ seconds
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: pointer to the file position
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string.
 * The values read are assumed to be in 1/USER_HZ seconds, and
 * are converted into jiffies.
 *
 * Returns 0 on success.
 */
int proc_dointvec_userhz_jiffies(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
				do_proc_dointvec_userhz_jiffies_conv, NULL);
}

/**
 * proc_dointvec_ms_jiffies - read a vector of integers as 1 milliseconds
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 * @ppos: the current position in the file
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string.
 * The values read are assumed to be in 1/1000 seconds, and
 * are converted into jiffies.
 *
 * Returns 0 on success.
 */
int proc_dointvec_ms_jiffies(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
				do_proc_dointvec_ms_jiffies_conv, NULL);
}

static int proc_do_cad_pid(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	struct pid *new_pid;
	pid_t tmp;
	int r;

	tmp = pid_vnr(cad_pid);

	r = __do_proc_dointvec(&tmp, table, write, buffer,
			       lenp, ppos, NULL, NULL);
	if (r || !write)
		return r;

	new_pid = find_get_pid(tmp);
	if (!new_pid)
		return -ESRCH;

	put_pid(xchg(&cad_pid, new_pid));
	return 0;
}

/**
 * proc_do_large_bitmap - read/write from/to a large bitmap
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 * @ppos: file position
 *
 * The bitmap is stored at table->data and the bitmap length (in bits)
 * in table->maxlen.
 *
 * We use a range comma separated format (e.g. 1,3-4,10-10) so that
 * large bitmaps may be represented in a compact manner. Writing into
 * the file will clear the bitmap then update it with the given input.
 *
 * Returns 0 on success.
 */
int proc_do_large_bitmap(struct ctl_table *table, int write,
			 void *buffer, size_t *lenp, loff_t *ppos)
{
	int err = 0;
	size_t left = *lenp;
	unsigned long bitmap_len = table->maxlen;
	unsigned long *bitmap = *(unsigned long **) table->data;
	unsigned long *tmp_bitmap = NULL;
	char tr_a[] = { '-', ',', '\n' }, tr_b[] = { ',', '\n', 0 }, c;

	if (!bitmap || !bitmap_len || !left || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		char *p = buffer;
		size_t skipped = 0;

		if (left > PAGE_SIZE - 1) {
			left = PAGE_SIZE - 1;
			/* How much of the buffer we'll skip this pass */
			skipped = *lenp - left;
		}

		tmp_bitmap = bitmap_zalloc(bitmap_len, GFP_KERNEL);
		if (!tmp_bitmap)
			return -ENOMEM;
		proc_skip_char(&p, &left, '\n');
		while (!err && left) {
			unsigned long val_a, val_b;
			bool neg;
			size_t saved_left;

			/* In case we stop parsing mid-number, we can reset */
			saved_left = left;
			err = proc_get_long(&p, &left, &val_a, &neg, tr_a,
					     sizeof(tr_a), &c);
			/*
			 * If we consumed the entirety of a truncated buffer or
			 * only one char is left (may be a "-"), then stop here,
			 * reset, & come back for more.
			 */
			if ((left <= 1) && skipped) {
				left = saved_left;
				break;
			}

			if (err)
				break;
			if (val_a >= bitmap_len || neg) {
				err = -EINVAL;
				break;
			}

			val_b = val_a;
			if (left) {
				p++;
				left--;
			}

			if (c == '-') {
				err = proc_get_long(&p, &left, &val_b,
						     &neg, tr_b, sizeof(tr_b),
						     &c);
				/*
				 * If we consumed all of a truncated buffer or
				 * then stop here, reset, & come back for more.
				 */
				if (!left && skipped) {
					left = saved_left;
					break;
				}

				if (err)
					break;
				if (val_b >= bitmap_len || neg ||
				    val_a > val_b) {
					err = -EINVAL;
					break;
				}
				if (left) {
					p++;
					left--;
				}
			}

			bitmap_set(tmp_bitmap, val_a, val_b - val_a + 1);
			proc_skip_char(&p, &left, '\n');
		}
		left += skipped;
	} else {
		unsigned long bit_a, bit_b = 0;
		bool first = 1;

		while (left) {
			bit_a = find_next_bit(bitmap, bitmap_len, bit_b);
			if (bit_a >= bitmap_len)
				break;
			bit_b = find_next_zero_bit(bitmap, bitmap_len,
						   bit_a + 1) - 1;

			if (!first)
				proc_put_char(&buffer, &left, ',');
			proc_put_long(&buffer, &left, bit_a, false);
			if (bit_a != bit_b) {
				proc_put_char(&buffer, &left, '-');
				proc_put_long(&buffer, &left, bit_b, false);
			}

			first = 0; bit_b++;
		}
		proc_put_char(&buffer, &left, '\n');
	}

	if (!err) {
		if (write) {
			if (*ppos)
				bitmap_or(bitmap, bitmap, tmp_bitmap, bitmap_len);
			else
				bitmap_copy(bitmap, tmp_bitmap, bitmap_len);
		}
		*lenp -= left;
		*ppos += *lenp;
	}

	bitmap_free(tmp_bitmap);
	return err;
}

static int netcls_put_char(void **buf, size_t *size, char c)
{
	if (*size) {
		char **buffer = (char **)buf;

		memcpy(*buffer, &c, 1);
		(*size)--, (*buffer)++;
		*buf = *buffer;
	}
	return 0;
}

static int netcls_put_long(void **buf, size_t *size, unsigned long val,
			  bool neg)
{
	int len;
	char tmp[22], *p = tmp;

	sprintf(p, "%s%lu", neg ? "-" : "", val);
	len = strlen(tmp);
	if (len > *size)
		len = *size;
	memcpy(*buf, tmp, len);
	*size -= len;
	*buf += len;
	return 0;
}

int netcls_do_large_bitmap(struct ctl_table *table, int write,
			 void *buffer, size_t *lenp, loff_t *ppos)
{
	int err = 0;
	bool first = 1;
	size_t left = *lenp;
	unsigned long bitmap_len = table->maxlen;
	unsigned long *bitmap = *(unsigned long **) table->data;
	unsigned long *tmp_bitmap = NULL;
	char tr_a[] = { '-', ',', '\n' }, tr_b[] = { ',', '\n', 0 }, c;

	if (!bitmap || !bitmap_len || !left || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		char *kbuf, *p;
		size_t skipped = 0;

		if (left > PAGE_SIZE - 1) {
			left = PAGE_SIZE - 1;
			/* How much of the buffer we'll skip this pass */
			skipped = *lenp - left;
		}

		p = kbuf = buffer;
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);

		tmp_bitmap = bitmap_zalloc(bitmap_len, GFP_KERNEL);
		if (!tmp_bitmap)
			return -ENOMEM;

		proc_skip_char(&p, &left, '\n');
		while (!err && left) {
			unsigned long val_a, val_b;
			bool neg;
			size_t saved_left;

			/* In case we stop parsing mid-number, we can reset */
			saved_left = left;
			err = proc_get_long(&p, &left, &val_a, &neg, tr_a,
					     sizeof(tr_a), &c);
			/*
			 * If we consumed the entirety of a truncated buffer or
			 * only one char is left (may be a "-"), then stop here,
			 * reset, & come back for more.
			 */
			if ((left <= 1) && skipped) {
				left = saved_left;
				break;
			}

			if (err)
				break;
			if (val_a >= bitmap_len || neg) {
				err = -EINVAL;
				break;
			}

			val_b = val_a;
			if (left) {
				p++;
				left--;
			}

			if (c == '-') {
				err = proc_get_long(&p, &left, &val_b,
						     &neg, tr_b, sizeof(tr_b),
						     &c);
				/*
				 * If we consumed all of a truncated buffer or
				 * then stop here, reset, & come back for more.
				 */
				if (!left && skipped) {
					left = saved_left;
					break;
				}

				if (err)
					break;
				if (val_b >= bitmap_len || neg ||
				    val_a > val_b) {
					err = -EINVAL;
					break;
				}
				if (left) {
					p++;
					left--;
				}
			}

			bitmap_set(tmp_bitmap, val_a, val_b - val_a + 1);
			first = 0;
			proc_skip_char(&p, &left, '\n');
		}
		left += skipped;
	} else {
		unsigned long bit_a, bit_b = 0;

		while (left) {
			bit_a = find_next_bit(bitmap, bitmap_len, bit_b);
			if (bit_a >= bitmap_len)
				break;
			bit_b = find_next_zero_bit(bitmap, bitmap_len,
						   bit_a + 1) - 1;

			if (!first) {
				err = netcls_put_char(&buffer, &left, ',');
				if (err)
					break;
			}
			err = netcls_put_long(&buffer, &left, bit_a, false);
			if (err)
				break;
			if (bit_a != bit_b) {
				err = netcls_put_char(&buffer, &left, '-');
				if (err)
					break;
				err = netcls_put_long(&buffer, &left,
							bit_b, false);
				if (err)
					break;
			}

			first = 0; bit_b++;
		}
		if (!err)
			err = netcls_put_char(&buffer, &left, '\n');
	}

	if (!err) {
		if (write) {
			if (*ppos)
				bitmap_or(bitmap, bitmap, tmp_bitmap,
						bitmap_len);
			else
				bitmap_copy(bitmap, tmp_bitmap, bitmap_len);
		}
		*lenp -= left;
		*ppos += *lenp;
	}

	bitmap_free(tmp_bitmap);
	return err;
}

#else /* CONFIG_PROC_SYSCTL */

int proc_dostring(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dobool(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_douintvec(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_minmax(struct ctl_table *table, int write,
		    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_douintvec_minmax(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dou8vec_minmax(struct ctl_table *table, int write,
			void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_jiffies(struct ctl_table *table, int write,
		    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_ms_jiffies_minmax(struct ctl_table *table, int write,
				    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_userhz_jiffies(struct ctl_table *table, int write,
		    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_ms_jiffies(struct ctl_table *table, int write,
			     void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_doulongvec_minmax(struct ctl_table *table, int write,
		    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_doulongvec_ms_jiffies_minmax(struct ctl_table *table, int write,
				      void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_do_large_bitmap(struct ctl_table *table, int write,
			 void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

#endif /* CONFIG_PROC_SYSCTL */

#if defined(CONFIG_SYSCTL)

#ifdef CONFIG_TKERNEL_SECURITY_MONITOR
#include <linux/hook_frame.h>
unsigned long security_switch_min = 0x0 | SYSCTL_SET_MAGIC;
unsigned long security_switch_max = 0xffffffff | SYSCTL_SET_MAGIC;

int security_switch_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		return ret;
	if (write)
		*(unsigned long *)(table->data) = (*(unsigned long *)(table->data)) & 0xffffffff;
	return ret;
}
#endif

int proc_do_static_key(struct ctl_table *table, int write,
		       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct static_key *key = (struct static_key *)table->data;
	static DEFINE_MUTEX(static_key_mutex);
	int val, ret;
	struct ctl_table tmp = {
		.data   = &val,
		.maxlen = sizeof(val),
		.mode   = table->mode,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	};

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&static_key_mutex);
	val = static_key_enabled(key);
	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && !ret) {
		if (val)
			static_key_enable(key);
		else
			static_key_disable(key);
	}
	mutex_unlock(&static_key_mutex);
	return ret;
}

#ifdef CONFIG_MEMCG
static int memory_qos_sysctl_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	int error;

	mutex_lock(&rue_mutex);
	if (write && !READ_ONCE(rue_installed)) {
		error = -EBUSY;
		pr_info("RUE: rue kernel module is not enabled or installed.");
		goto out;
	}

	error = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (error)
		goto out;

	if (write)
		memory_qos_update();

	mutex_unlock(&rue_mutex);
	return 0;

out:
	mutex_unlock(&rue_mutex);
	return error;
}

static int memory_qos_sysctl_highest_reclaim_prio_handler(struct ctl_table *table,
				int write, void *buffer,
				size_t *lenp, loff_t *ppos)
{
	int error;

	error = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (error)
		return error;

	if (write)
		memory_qos_update();

	return 0;
}

static int memory_qos_sysctl_prio_reclaim_ratio_handler(struct ctl_table *table,
				int write, void *buffer,
				size_t *lenp, loff_t *ppos)
{
	int error;
	unsigned int old;

	old = sysctl_vm_qos_prio_reclaim_ratio;
	error = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (error)
		return error;

	if (old == sysctl_vm_qos_prio_reclaim_ratio)
		return 0;

	if (write) {
		error = memory_qos_prio_reclaim_ratio_update();
		if (error) {
			sysctl_vm_qos_prio_reclaim_ratio = old;
			return -EINVAL;
		}
	}

	return 0;
}

static int clean_dying_memcg_async_handler(struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_douintvec_minmax(table, write, buffer, lenp, ppos);

	if (write && (sysctl_vm_memory_qos == 0 ||
			 sysctl_clean_dying_memcg_threshold == 0))
		return -EINVAL;

	if (write && !ret) {
		if (sysctl_clean_dying_memcg_async > 0) {
			if (kclean_dying_memcg_run()) {
				sysctl_clean_dying_memcg_async = 0;
				return -EINVAL;
			}
		} else
			kclean_dying_memcg_stop();
	}

	return ret;
}

static int clean_dying_memcg_threshold_handler(struct ctl_table *table,
		int write, void *buffer, size_t *lenp, loff_t *ppos)
{
	unsigned int old_val = sysctl_clean_dying_memcg_threshold;
	int ret = proc_douintvec_minmax(table, write, buffer, lenp, ppos);

	if (write && (sysctl_vm_memory_qos == 0))
		return -EINVAL;

	if (write && !ret) {
		if (old_val != sysctl_clean_dying_memcg_threshold) {
			if (atomic_long_read(&dying_memcgs_count) >=
					sysctl_clean_dying_memcg_threshold) {
				atomic_long_set(&dying_memcgs_count, 0);
				wakeup_kclean_dying_memcg();
			}
		}
	}

	return ret;
}
#endif

#ifdef CONFIG_RPS
DECLARE_STATIC_KEY_TRUE(rps_using_pvipi);
#endif

static struct ctl_table kern_table[] = {
#ifdef CONFIG_TKERNEL_SECURITY_MONITOR
	{
		.procname	= "connect_info_switch",
		.data		= &connect_info_flag,
		.maxlen		= sizeof(connect_info_flag),
		.mode		= 0644,
		.proc_handler	= &security_switch_handler,
		.extra1         = &security_switch_min,
		.extra2         = &security_switch_max,
	},
	{
		.procname	= "accept_info_switch",
		.data		= &accept_info_flag,
		.maxlen		= sizeof(accept_info_flag),
		.mode		= 0644,
		.proc_handler	= &security_switch_handler,
		.extra1         = &security_switch_min,
		.extra2         = &security_switch_max,
	},
	{
		.procname	= "sendto_info_switch",
		.data		= &sendto_info_flag,
		.maxlen		= sizeof(sendto_info_flag),
		.mode		= 0644,
		.proc_handler	= &security_switch_handler,
		.extra1         = &security_switch_min,
		.extra2         = &security_switch_max,
	},
	{
		.procname	= "recvfrom_info_switch",
		.data		= &recvfrom_info_flag,
		.maxlen		= sizeof(recvfrom_info_flag),
		.mode		= 0644,
		.proc_handler	= &security_switch_handler,
		.extra1         = &security_switch_min,
		.extra2         = &security_switch_max,
	},
	{
		.procname	= "execve_info_switch",
		.data		= &execve_info_flag,
		.maxlen		= sizeof(execve_info_flag),
		.mode		= 0644,
		.proc_handler	= &security_switch_handler,
		.extra1         = &security_switch_min,
		.extra2         = &security_switch_max,
	},
	{
		.procname	= "sock_info_switch",
		.data		= &sock_info_flag,
		.maxlen		= sizeof(sock_info_flag),
		.mode		= 0644,
		.proc_handler	= &security_switch_handler,
		.extra1         = &security_switch_min,
		.extra2         = &security_switch_max,
	},
	{
		.procname	= "fork_info_switch",
		.data		= &fork_info_flag,
		.maxlen		= sizeof(fork_info_flag),
		.mode		= 0644,
		.proc_handler	= &security_switch_handler,
		.extra1         = &security_switch_min,
		.extra2         = &security_switch_max,
	},
	{
		.procname	= "exit_info_switch",
		.data		= &exit_info_flag,
		.maxlen		= sizeof(exit_info_flag),
		.mode		= 0644,
		.proc_handler	= &security_switch_handler,
		.extra1         = &security_switch_min,
		.extra2         = &security_switch_max,
	},
#endif
	{
		.procname	= "panic",
		.data		= &panic_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_PROC_SYSCTL
	{
		.procname	= "tainted",
		.maxlen 	= sizeof(long),
		.mode		= 0644,
		.proc_handler	= proc_taint,
	},
	{
		.procname	= "sysctl_writes_strict",
		.data		= &sysctl_writes_strict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_NEG_ONE,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "print-fatal-signals",
		.data		= &print_fatal_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_SPARC
	{
		.procname	= "reboot-cmd",
		.data		= reboot_command,
		.maxlen		= 256,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "stop-a",
		.data		= &stop_a_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "scons-poweroff",
		.data		= &scons_pwroff,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_SPARC64
	{
		.procname	= "tsb-ratio",
		.data		= &sysctl_tsb_ratio,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_PARISC
	{
		.procname	= "soft-power",
		.data		= &pwrsw_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_ALLOW
	{
		.procname	= "unaligned-trap",
		.data		= &unaligned_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_STACK_TRACER
	{
		.procname	= "stack_tracer_enabled",
		.data		= &stack_tracer_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= stack_trace_sysctl,
	},
#endif
#ifdef CONFIG_TRACING
	{
		.procname	= "ftrace_dump_on_oops",
		.data		= &ftrace_dump_on_oops,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "traceoff_on_warning",
		.data		= &__disable_trace_on_warning,
		.maxlen		= sizeof(__disable_trace_on_warning),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tracepoint_printk",
		.data		= &tracepoint_printk,
		.maxlen		= sizeof(tracepoint_printk),
		.mode		= 0644,
		.proc_handler	= tracepoint_printk_sysctl,
	},
#endif
#ifdef CONFIG_MODULES
	{
		.procname	= "modprobe",
		.data		= &modprobe_path,
		.maxlen		= KMOD_PATH_LEN,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "modules_disabled",
		.data		= &modules_disabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		/* only handle a transition from default "0" to "1" */
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_ONE,
	},
#endif
#ifdef CONFIG_UEVENT_HELPER
	{
		.procname	= "hotplug",
		.data		= &uevent_helper,
		.maxlen		= UEVENT_HELPER_PATH_LEN,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
#endif
#ifdef CONFIG_MAGIC_SYSRQ
	{
		.procname	= "sysrq",
		.data		= NULL,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= sysrq_sysctl_handler,
	},
	{
		.procname       = "sysrq_use_leftctrl",
		.data           = &__sysrq_use_leftctrl,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = sysrq_use_leftctrl_sysctl_handler,

	},
#endif
#ifdef CONFIG_PROC_SYSCTL
	{
		.procname	= "cad_pid",
		.data		= NULL,
		.maxlen		= sizeof (int),
		.mode		= 0600,
		.proc_handler	= proc_do_cad_pid,
	},
#endif
	{
		.procname	= "threads-max",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sysctl_max_threads,
	},
	{
		.procname	= "overflowuid",
		.data		= &overflowuid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
	{
		.procname	= "overflowgid",
		.data		= &overflowgid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
#ifdef CONFIG_S390
	{
		.procname	= "userprocess_debug",
		.data		= &show_unhandled_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "pid_max",
		.data		= &pid_max,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &pid_max_min,
		.extra2		= &pid_max_max,
	},
	{
		.procname	= "panic_on_oops",
		.data		= &panic_on_oops,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "panic_print",
		.data		= &panic_print,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "ngroups_max",
		.data		= (void *)&ngroups_max,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cap_last_cap",
		.data		= (void *)&cap_last_cap,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
#if defined(CONFIG_X86_LOCAL_APIC) && defined(CONFIG_X86)
	{
		.procname       = "unknown_nmi_panic",
		.data           = &unknown_nmi_panic,
		.maxlen         = sizeof (int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
#endif

#if (defined(CONFIG_X86_32) || defined(CONFIG_PARISC)) && \
	defined(CONFIG_DEBUG_STACKOVERFLOW)
	{
		.procname	= "panic_on_stackoverflow",
		.data		= &sysctl_panic_on_stackoverflow,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#if defined(CONFIG_X86)
	{
		.procname	= "panic_on_unrecovered_nmi",
		.data		= &panic_on_unrecovered_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "panic_on_io_nmi",
		.data		= &panic_on_io_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "bootloader_type",
		.data		= &bootloader_type,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "bootloader_version",
		.data		= &bootloader_version,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "io_delay_type",
		.data		= &io_delay_type,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#if defined(CONFIG_MMU)
	{
		.procname	= "randomize_va_space",
		.data		= &randomize_va_space,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#if defined(CONFIG_S390) && defined(CONFIG_SMP)
	{
		.procname	= "spin_retry",
		.data		= &spin_retry,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#if	defined(CONFIG_ACPI_SLEEP) && defined(CONFIG_X86)
	{
		.procname	= "acpi_video_flags",
		.data		= &acpi_realmode_flags,
		.maxlen		= sizeof (unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
#endif
#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_NO_WARN
	{
		.procname	= "ignore-unaligned-usertrap",
		.data		= &no_unaligned_warning,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_IA64
	{
		.procname	= "unaligned-dump-stack",
		.data		= &unaligned_dump_stack,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_RT_MUTEXES
	{
		.procname	= "max_lock_depth",
		.data		= &max_lock_depth,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_PERF_EVENTS
	/*
	 * User-space scripts rely on the existence of this file
	 * as a feature check for perf_events being enabled.
	 *
	 * So it's an ABI, do not remove!
	 */
	{
		.procname	= "perf_event_paranoid",
		.data		= &sysctl_perf_event_paranoid,
		.maxlen		= sizeof(sysctl_perf_event_paranoid),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "perf_event_mlock_kb",
		.data		= &sysctl_perf_event_mlock,
		.maxlen		= sizeof(sysctl_perf_event_mlock),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "perf_event_max_sample_rate",
		.data		= &sysctl_perf_event_sample_rate,
		.maxlen		= sizeof(sysctl_perf_event_sample_rate),
		.mode		= 0644,
		.proc_handler	= perf_proc_update_handler,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "perf_cpu_time_max_percent",
		.data		= &sysctl_perf_cpu_time_max_percent,
		.maxlen		= sizeof(sysctl_perf_cpu_time_max_percent),
		.mode		= 0644,
		.proc_handler	= perf_cpu_time_max_percent_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
	{
		.procname	= "perf_event_max_stack",
		.data		= &sysctl_perf_event_max_stack,
		.maxlen		= sizeof(sysctl_perf_event_max_stack),
		.mode		= 0644,
		.proc_handler	= perf_event_max_stack_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= (void *)&six_hundred_forty_kb,
	},
	{
		.procname	= "perf_event_max_contexts_per_stack",
		.data		= &sysctl_perf_event_max_contexts_per_stack,
		.maxlen		= sizeof(sysctl_perf_event_max_contexts_per_stack),
		.mode		= 0644,
		.proc_handler	= perf_event_max_stack_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_THOUSAND,
	},
#endif
	{
		.procname	= "panic_on_warn",
		.data		= &panic_on_warn,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#ifdef CONFIG_TREE_RCU
	{
		.procname	= "panic_on_rcu_stall",
		.data		= &sysctl_panic_on_rcu_stall,
		.maxlen		= sizeof(sysctl_panic_on_rcu_stall),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "max_rcu_stall_to_panic",
		.data		= &sysctl_max_rcu_stall_to_panic,
		.maxlen		= sizeof(sysctl_max_rcu_stall_to_panic),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_INT_MAX,
	},
#endif
#ifdef CONFIG_PID_NS
	{
		.procname	= "watch_host_pid",
		.data		= &sysctl_watch_host_pid,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_RPS
	{
		.procname       = "rps_using_pvipi",
		.data           = &rps_using_pvipi.key,
		.maxlen         = sizeof(rps_using_pvipi),
		.mode           = 0644,
		.proc_handler   = proc_do_static_key,
	},
#endif
#ifdef CONFIG_CPUSETS
	{
		.procname	= "cpuset_cpuinfo_show_realinfo",
		.data		= &cpuset_cpuinfo_show_realinfo,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_CGROUPFS
	{
		.procname       = "container_cpuquota_aware",
		.data           = &container_cpuquota_aware,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "cgroupfs_stat_show_cpuacct_info",
		.data           = &cgroupfs_stat_show_cpuacct_info,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "cgroupfs_mounted",
		.data           = &cgroupfs_mounted,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0444,
		.proc_handler   = proc_dointvec,
	},
#endif
#ifdef CONFIG_BLK_DEV_THROTTLING_CGROUP_V1
	{
		.procname	= "io_buffered_write_bps_hierarchy",
		.data		= &sysctl_buffered_write_bps_hierarchy,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "skip_throttle_prio_req",
		.data		= &sysctl_skip_throttle_prio_req,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
#ifdef CONFIG_RQM
	{
		.procname	= "qos_mbuf_enable",
		.data		= &sysctl_qos_mbuf_enable,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "async_mem_free_pages",
		.data		= &sysctl_async_mem_free_pages,
		.maxlen		= sizeof(sysctl_async_mem_free_pages),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname		= "io_qos",
		.data			= &sysctl_io_qos_enabled,
		.maxlen			= sizeof(unsigned int),
		.mode			= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1			= SYSCTL_ZERO,
		.extra2			= SYSCTL_ONE,
	},
#if defined(CONFIG_MEMCG) && defined(CONFIG_BLK_CGROUP)
	{
		.procname	= "allow_memcg_migrate_ignore_blkio_bind",
		.data		= &sysctl_allow_memcg_migrate_ignore_blkio_bind,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
#ifdef CONFIG_CGROUP_WRITEBACK
	{
		.procname	= "io_cgv1_buff_wb",
		.data		= &sysctl_io_cgv1_buff_wb_enabled,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{ }
};

unsigned int vm_memcg_latency_histogram;
unsigned int vm_memcg_page_cache_hit;
unsigned long vm_pagecache_system_usage;

static struct ctl_table vm_table[] = {
	{
		.procname	= "overcommit_memory",
		.data		= &sysctl_overcommit_memory,
		.maxlen		= sizeof(sysctl_overcommit_memory),
		.mode		= 0644,
		.proc_handler	= overcommit_policy_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO,
	},
	{
		.procname	= "overcommit_ratio",
		.data		= &sysctl_overcommit_ratio,
		.maxlen		= sizeof(sysctl_overcommit_ratio),
		.mode		= 0644,
		.proc_handler	= overcommit_ratio_handler,
	},
	{
		.procname	= "overcommit_kbytes",
		.data		= &sysctl_overcommit_kbytes,
		.maxlen		= sizeof(sysctl_overcommit_kbytes),
		.mode		= 0644,
		.proc_handler	= overcommit_kbytes_handler,
	},
	{
		.procname	= "oom_kill_largest_task",
		.data		= &sysctl_oom_kill_largest_task,
		.maxlen		= sizeof(sysctl_oom_kill_largest_task),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "page-cluster",
		.data		= &page_cluster,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= (void *)&page_cluster_max,
	},
	{
		.procname	= "dirtytime_expire_seconds",
		.data		= &dirtytime_expire_interval,
		.maxlen		= sizeof(dirtytime_expire_interval),
		.mode		= 0644,
		.proc_handler	= dirtytime_interval_handler,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "swappiness",
		.data		= &vm_swappiness,
		.maxlen		= sizeof(vm_swappiness),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO_HUNDRED,
	},
#ifdef CONFIG_EMM_FORCE_SWAPPINESS
	{
		.procname       = "force_swappiness",
		.data           = &sysctl_vm_force_swappiness,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
#endif
#ifdef CONFIG_EMM_RAMDISK_SWAP
	{
		.procname       = "ramdisk_swaptune",
		.data           = &sysctl_vm_ramdisk_swaptune,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "swapcache_fastfree",
		.data           = &sysctl_vm_swapcache_fastfree,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
#endif
#ifdef CONFIG_NUMA
	{
		.procname	= "numa_stat",
		.data		= &sysctl_vm_numa_stat,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sysctl_vm_numa_stat_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "drop_caches",
		.data		= &sysctl_drop_caches,
		.maxlen		= sizeof(int),
		.mode		= 0200,
		.proc_handler	= drop_caches_sysctl_handler,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_FOUR,
	},
	{
		.procname	= "page_lock_unfairness",
		.data		= &sysctl_page_lock_unfairness,
		.maxlen		= sizeof(sysctl_page_lock_unfairness),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#ifdef CONFIG_MMU
	{
		.procname	= "max_map_count",
		.data		= &sysctl_max_map_count,
		.maxlen		= sizeof(sysctl_max_map_count),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_max_map_count,
		.extra1		= SYSCTL_ZERO,
	},
#else
	{
		.procname	= "nr_trim_pages",
		.data		= &sysctl_nr_trim_pages,
		.maxlen		= sizeof(sysctl_nr_trim_pages),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#endif
	{
		.procname	= "vfs_cache_pressure",
		.data		= &sysctl_vfs_cache_pressure,
		.maxlen		= sizeof(sysctl_vfs_cache_pressure),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#if defined(HAVE_ARCH_PICK_MMAP_LAYOUT) || \
    defined(CONFIG_ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT)
	{
		.procname	= "legacy_va_layout",
		.data		= &sysctl_legacy_va_layout,
		.maxlen		= sizeof(sysctl_legacy_va_layout),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#endif
#ifdef CONFIG_NUMA
	{
		.procname	= "zone_reclaim_mode",
		.data		= &node_reclaim_mode,
		.maxlen		= sizeof(node_reclaim_mode),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#endif
#ifdef CONFIG_SMP
	{
		.procname	= "stat_interval",
		.data		= &sysctl_stat_interval,
		.maxlen		= sizeof(sysctl_stat_interval),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "stat_refresh",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0600,
		.proc_handler	= vmstat_refresh,
	},
#endif
#ifdef CONFIG_MMU
	{
		.procname	= "mmap_min_addr",
		.data		= &dac_mmap_min_addr,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= mmap_min_addr_handler,
	},
#endif
#if (defined(CONFIG_X86_32) && !defined(CONFIG_UML))|| \
   (defined(CONFIG_SUPERH) && defined(CONFIG_VSYSCALL))
	{
		.procname	= "vdso_enabled",
#ifdef CONFIG_X86_32
		.data		= &vdso32_enabled,
		.maxlen		= sizeof(vdso32_enabled),
#else
		.data		= &vdso_enabled,
		.maxlen		= sizeof(vdso_enabled),
#endif
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= SYSCTL_ZERO,
	},
#endif
	{
		.procname	= "user_reserve_kbytes",
		.data		= &sysctl_user_reserve_kbytes,
		.maxlen		= sizeof(sysctl_user_reserve_kbytes),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "admin_reserve_kbytes",
		.data		= &sysctl_admin_reserve_kbytes,
		.maxlen		= sizeof(sysctl_admin_reserve_kbytes),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
	{
		.procname	= "mmap_rnd_bits",
		.data		= &mmap_rnd_bits,
		.maxlen		= sizeof(mmap_rnd_bits),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (void *)&mmap_rnd_bits_min,
		.extra2		= (void *)&mmap_rnd_bits_max,
	},
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
	{
		.procname	= "mmap_rnd_compat_bits",
		.data		= &mmap_rnd_compat_bits,
		.maxlen		= sizeof(mmap_rnd_compat_bits),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (void *)&mmap_rnd_compat_bits_min,
		.extra2		= (void *)&mmap_rnd_compat_bits_max,
	},
#endif
	{
		.procname	= "pagecache_limit_ratio",
		.data		= &vm_pagecache_limit_ratio,
		.maxlen		= sizeof(vm_pagecache_limit_ratio),
		.mode		= 0644,
		.proc_handler	= &pc_limit_proc_dointvec,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
	{
		.procname	= "pagecache_limit_reclaim_ratio",
		.data		= &vm_pagecache_limit_reclaim_ratio,
		.maxlen		= sizeof(vm_pagecache_limit_reclaim_ratio),
		.mode		= 0644,
		.proc_handler	= &pc_reclaim_limit_proc_dointvec,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
	{
		.procname	= "pagecache_limit_ignore_dirty",
		.data		= &vm_pagecache_ignore_dirty,
		.maxlen		= sizeof(vm_pagecache_ignore_dirty),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "pagecache_limit_async",
		.data		= &vm_pagecache_limit_async,
		.maxlen		= sizeof(vm_pagecache_limit_async),
		.mode		= 0644,
		.proc_handler	= &pc_limit_async_handler,
	},
	{
		.procname	= "pagecache_limit_ignore_slab",
		.data		= &vm_pagecache_ignore_slab,
		.maxlen		= sizeof(vm_pagecache_ignore_slab),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef CONFIG_MEMCG
	{
		.procname	= "pagecache_limit_global",
		.data		= &vm_pagecache_limit_global,
		.maxlen		= sizeof(vm_pagecache_limit_global),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "pagecache_limit_retry_times",
		.data		= &vm_pagecache_limit_retry_times,
		.maxlen		= sizeof(vm_pagecache_limit_retry_times),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
	{
		.procname	= "pagecache_system_usage",
		.data		= &vm_pagecache_system_usage,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0444,
		.proc_handler	= proc_pagecache_system_usage,
	},
	{
		.procname	= "memcg_latency_histogram",
		.data		= &vm_memcg_latency_histogram,
		.maxlen		= sizeof(vm_memcg_latency_histogram),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "memcg_page_cache_hit",
		.data		= &vm_memcg_page_cache_hit,
		.maxlen		= sizeof(vm_memcg_page_cache_hit),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname		= "memory_qos",
		.data			= &sysctl_vm_memory_qos,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= memory_qos_sysctl_handler,
		.extra1			= SYSCTL_ZERO,
		.extra2			= SYSCTL_ONE,
	},
	{
		.procname		= "use_priority_oom",
		.data			= &sysctl_vm_use_priority_oom,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1			= SYSCTL_ZERO,
		.extra2			= SYSCTL_ONE,
	},
	{
		.procname		= "qos_highest_reclaim_prio",
		.data			= &sysctl_vm_qos_highest_reclaim_prio,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= memory_qos_sysctl_highest_reclaim_prio_handler,
		.extra1			= SYSCTL_ONE,
		.extra2			= &vm_lowest_prio,
	},
	{
		.procname		= "qos_prio_reclaim_ratio",
		.data			= &sysctl_vm_qos_prio_reclaim_ratio,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= memory_qos_sysctl_prio_reclaim_ratio_handler,
		.extra1			= SYSCTL_ONE,
		.extra2			= &twenty,
	},
	{
		.procname		= "clean_dying_memcg_async",
		.data			= &sysctl_clean_dying_memcg_async,
		.maxlen			= sizeof(sysctl_clean_dying_memcg_async),
		.mode			= 0644,
		.proc_handler	= clean_dying_memcg_async_handler,
		.extra1			= SYSCTL_ZERO,
		.extra2			= SYSCTL_ONE,
	},
	{
		.procname		= "clean_dying_memcg_threshold",
		.data			= &sysctl_clean_dying_memcg_threshold,
		.maxlen			= sizeof(sysctl_clean_dying_memcg_threshold),
		.mode			= 0644,
		.proc_handler	= clean_dying_memcg_threshold_handler,
	},
#endif
	{ }
};

int __init sysctl_init_bases(void)
{
	register_sysctl_init("kernel", kern_table);
	register_sysctl_init("vm", vm_table);

	return 0;
}
#endif /* CONFIG_SYSCTL */
/*
 * No sense putting this after each symbol definition, twice,
 * exception granted :-)
 */
EXPORT_SYMBOL(proc_dobool);
EXPORT_SYMBOL(proc_dointvec);
EXPORT_SYMBOL(proc_douintvec);
EXPORT_SYMBOL(proc_dointvec_jiffies);
EXPORT_SYMBOL(proc_dointvec_minmax);
EXPORT_SYMBOL_GPL(proc_douintvec_minmax);
EXPORT_SYMBOL(proc_dointvec_userhz_jiffies);
EXPORT_SYMBOL(proc_dointvec_ms_jiffies);
EXPORT_SYMBOL(proc_dostring);
EXPORT_SYMBOL(proc_doulongvec_minmax);
EXPORT_SYMBOL(proc_doulongvec_ms_jiffies_minmax);
EXPORT_SYMBOL(proc_do_large_bitmap);
