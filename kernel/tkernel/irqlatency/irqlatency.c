// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Trace Irqs latency
 *
 * Copyright (C) 2022 tencent, Inc., liu hua
 *
 * shookliu <shookliu@tencent.com>
 */
#define pr_fmt(fmt) "irqlatency: " fmt

#include <linux/hrtimer.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>
#include <linux/stacktrace.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <asm/irq_regs.h>
#include <linux/sched/clock.h>

#define MAX_STACK_ENTRIES           (PAGE_SIZE / sizeof(unsigned long))
#define PER_STACK_ENTRIES_AVERAGE   (8 + 8)
#define MAX_STACK_ENTRIES_INDEX     (MAX_STACK_ENTRIES / PER_STACK_ENTRIES_AVERAGE)

#define MAX_LATENCY_RECORD          10

#define NS_TO_MS(ns) ((ns) / 1000000)

#define MIN_FREQ_MS  (5)
#define MAX_FREQ_MS  (5000)

struct per_stack {
	unsigned int nr_entries;
	unsigned long *perstack;
};

struct latency_data {
	u64 last_timestamp;
	unsigned long stack_index;
	struct per_stack stacks[MAX_STACK_ENTRIES];
	unsigned long total_entries;
	unsigned long entries[MAX_STACK_ENTRIES];
	unsigned long latency_count[MAX_LATENCY_RECORD];

	/* Task command names */
	char comms[MAX_STACK_ENTRIES_INDEX][TASK_COMM_LEN];

	/* Task pids */
	pid_t pids[MAX_STACK_ENTRIES_INDEX];

	struct {
		u64 msecs:63;
		u64 plus:1;
	} latency[MAX_STACK_ENTRIES_INDEX];
};

struct per_cpu_detect_data {
	unsigned int soft_in_irq;
	struct timer_list softirq_timer;
	struct hrtimer irq_timer;
	struct latency_data irq_data;
	struct latency_data softirq_data;
};

static u64 freq_ms = 10;
static u64 irq_latency_ms = 30;
static unsigned int check_enable;

static struct per_cpu_detect_data __percpu *detect_data;

/*
 * Note: Must be called with irq disabled.
 */
static bool save_stack(u64 latency, unsigned int isirq, unsigned int soft_in_irq)
{
	unsigned long nr_entries, stack_index;
	struct per_stack *pstack;
	struct latency_data *lat_data;

	lat_data = isirq ? this_cpu_ptr(&detect_data->irq_data) :
		      this_cpu_ptr(&detect_data->softirq_data);

	stack_index = lat_data->stack_index;
	if (unlikely(stack_index >= MAX_STACK_ENTRIES_INDEX - 1))
		return false;

	nr_entries = lat_data->total_entries;
	if (unlikely(nr_entries >= MAX_STACK_ENTRIES - 1))
		return false;

	strlcpy(lat_data->comms[stack_index], current->comm, TASK_COMM_LEN);
	lat_data->pids[stack_index] = current->pid;
	lat_data->latency[stack_index].msecs = latency;
	lat_data->latency[stack_index].plus = !isirq && soft_in_irq;

	pstack = lat_data->stacks + stack_index;
	pstack->perstack = lat_data->entries + nr_entries;
	pstack->nr_entries = stack_trace_save(pstack->perstack,
				MAX_STACK_ENTRIES - nr_entries, 0);
	lat_data->total_entries += pstack->nr_entries;

	/*
	 * Ensure that the initialisation of @stacks is complete before we
	 * update the @index.
	 */
	smp_store_release(&lat_data->stack_index, stack_index + 1);

	if (unlikely(lat_data->total_entries >= MAX_STACK_ENTRIES - 1)) {
		pr_info("BUG: MAX_STACK_ENTRIES too low!");

		return false;
	}

	return true;
}

static bool record_latency(u64 delta, unsigned int isirq, unsigned int soft_in_irq)
{
	int index = 0;
	u64 throttle = freq_ms << 1;

	if (delta < throttle)
		return false;

	if (unlikely(delta >= irq_latency_ms))
		save_stack(delta, isirq, soft_in_irq);

	delta -= freq_ms;
	delta >>= 1;
	while (delta >= freq_ms) {
		index++;
		delta >>= 1;
	}

	if (unlikely(index >= MAX_LATENCY_RECORD))
		index = MAX_LATENCY_RECORD - 1;

	if (isirq)
		__this_cpu_inc(detect_data->irq_data.latency_count[index]);
	else if (!soft_in_irq)
		__this_cpu_inc(detect_data->softirq_data.latency_count[index]);

	return true;
}

static void reset_latency_trace(void *data)
{
	int i;
	struct per_cpu_detect_data *detect_data = data;

	detect_data->irq_data.total_entries = 0;
	detect_data->irq_data.stack_index = 0;
	detect_data->softirq_data.total_entries = 0;
	detect_data->softirq_data.stack_index = 0;

	for (i = 0; i < MAX_LATENCY_RECORD; i++) {
		detect_data->irq_data.latency_count[i] = 0;
		detect_data->softirq_data.latency_count[i] = 0;
	}
}

static void softirq_timer_func(struct timer_list *softirq_timer)
{
	u64 now = local_clock(), delta;

	delta = now - __this_cpu_read(detect_data->softirq_data.last_timestamp);
	__this_cpu_write(detect_data->softirq_data.last_timestamp, now);
	__this_cpu_write(detect_data->soft_in_irq, 0);

	record_latency(NS_TO_MS(delta), 0, 0);

	mod_timer(softirq_timer, jiffies + msecs_to_jiffies(freq_ms));
}

static enum hrtimer_restart irq_hrtimer_func(struct hrtimer *irq_timer)
{
	u64 now = local_clock(), delta;

	delta = now - __this_cpu_read(detect_data->irq_data.last_timestamp);
	__this_cpu_write(detect_data->irq_data.last_timestamp, now);

	if (record_latency(NS_TO_MS(delta), 1, 0))
		__this_cpu_write(detect_data->softirq_data.last_timestamp, now);
	else if (check_enable == 2 &&
		 !__this_cpu_read(detect_data->soft_in_irq)) {
		delta = now - __this_cpu_read(
				detect_data->softirq_data.last_timestamp);
		if (unlikely(NS_TO_MS(delta) >= irq_latency_ms + freq_ms)) {
			record_latency(NS_TO_MS(delta), 0, 1);
			__this_cpu_write(detect_data->soft_in_irq, 1);
		}
	}

	hrtimer_forward_now(irq_timer, ms_to_ktime(freq_ms));

	return HRTIMER_RESTART;
}

static void percpu_timers_start(void *data)
{
	u64 now = local_clock();
	struct per_cpu_detect_data *detect_data = data;
	struct timer_list *softirq_timer = &detect_data->softirq_timer;
	struct hrtimer *irq_timer = &detect_data->irq_timer;

	detect_data->irq_data.last_timestamp = now;
	detect_data->softirq_data.last_timestamp = now;

	hrtimer_start_range_ns(irq_timer, ms_to_ktime(freq_ms),
			       0, HRTIMER_MODE_REL_PINNED);

	softirq_timer->expires = jiffies + msecs_to_jiffies(freq_ms);
	add_timer_on(softirq_timer, smp_processor_id());
}

static void latency_timers_start(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct timer_list *softirq_timer;
		struct hrtimer *irq_timer;

		softirq_timer = per_cpu_ptr(&detect_data->softirq_timer, cpu);
		timer_setup(softirq_timer, softirq_timer_func,
			    TIMER_PINNED | TIMER_IRQSAFE);

		irq_timer = per_cpu_ptr(&detect_data->irq_timer, cpu);
		hrtimer_init(irq_timer, CLOCK_MONOTONIC, HRTIMER_MODE_PINNED);
		irq_timer->function = irq_hrtimer_func;

		smp_call_function_single(cpu, percpu_timers_start,
				per_cpu_ptr(detect_data, cpu), true);
	}
}

static void latency_timers_stop(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct timer_list *softirq_timer;
		struct hrtimer *irq_timer;

		softirq_timer = per_cpu_ptr(&detect_data->softirq_timer, cpu);
		del_timer_sync(softirq_timer);

		irq_timer = per_cpu_ptr(&detect_data->irq_timer, cpu);
		hrtimer_cancel(irq_timer);
	}
}

static int enable_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "%d\n", check_enable);

	return 0;
}

static int enable_open(struct inode *inode, struct file *file)
{
	return single_open(file, enable_show, inode->i_private);
}

static ssize_t enable_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	unsigned int enable;

	if (kstrtouint_from_user(buf, count, 0, &enable))
		return -EINVAL;

	if (enable > 2)
		return -EINVAL;

	if (enable == check_enable)
		return count;

	if (!enable)
		latency_timers_stop();
	else if (!!enable != !!check_enable)
		latency_timers_start();

	check_enable = enable;

	return count;
}

static const struct proc_ops enable_fops = {
	.proc_open	= enable_open,
	.proc_read	= seq_read,
	.proc_write	= enable_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int freq_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "%llu\n", freq_ms);

	return 0;
}

static int freq_open(struct inode *inode, struct file *file)
{
	return single_open(file, freq_show, inode->i_private);
}

static ssize_t freq_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	unsigned long freq;

	if (check_enable)
		return -EINVAL;

	if (kstrtoul_from_user(buf, count, 0, &freq))
		return -EINVAL;

	if (freq == freq_ms)
		return count;

	if (freq < MIN_FREQ_MS)
		freq = MIN_FREQ_MS;
	else if (freq > MAX_FREQ_MS)
		freq = MAX_FREQ_MS;

	if (freq > (irq_latency_ms >> 1))
		freq = irq_latency_ms >> 1;

	freq_ms = freq;

	return count;
}

static const struct proc_ops freq_fops = {
	.proc_open	= freq_open,
	.proc_read	= seq_read,
	.proc_write	= freq_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int lat_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "%llu\n", irq_latency_ms);

	return 0;
}

static int lat_open(struct inode *inode, struct file *file)
{
	return single_open(file, lat_show, inode->i_private);
}

static ssize_t lat_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	unsigned long lat_ms;

	if (check_enable)
		return -EINVAL;

	if (kstrtoul_from_user(buf, count, 0, &lat_ms))
		return -EINVAL;

	if (lat_ms == irq_latency_ms)
		return count;

	if (lat_ms < (MIN_FREQ_MS >> 1))
		lat_ms = MIN_FREQ_MS >> 1;
	else if (lat_ms > (MAX_FREQ_MS >> 1))
		lat_ms = MAX_FREQ_MS >> 1;

	if (lat_ms < (freq_ms << 1))
		lat_ms = freq_ms << 1;

	irq_latency_ms = lat_ms;

	return count;
}

static const struct proc_ops lat_fops = {
	.proc_open	= lat_open,
	.proc_read	= seq_read,
	.proc_write	= lat_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static ssize_t trace_stack_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	unsigned long lat;

	if (kstrtoul_from_user(buf, count, 0, &lat))
		return -EINVAL;

	if (!lat) {
		int cpu;

		for_each_online_cpu(cpu)
			smp_call_function_single(cpu, reset_latency_trace,
				per_cpu_ptr(detect_data, cpu), true);
		return count;
	}

	return -EINVAL;
}

static void trace_stack_print(struct seq_file *m, struct per_stack *stack)
{
	int i;

	if (WARN_ON(!stack->perstack))
		return;

	for (i = 0; i < stack->nr_entries; i++)
		seq_printf(m, "%*c%pS\n", 5, ' ', (void *)stack->perstack[i]);
}

static void trace_stack_irq_show(struct seq_file *m, void *v, unsigned int isirq)
{
	int cpu;

	for_each_online_cpu(cpu) {
		int i;
		u64 stack_index;
		struct latency_data *lat_data;

		lat_data = isirq ? per_cpu_ptr(&detect_data->irq_data, cpu) :
			per_cpu_ptr(&detect_data->softirq_data, cpu);

		/*
		 * Paired with smp_store_release() in the save_trace().
		 */
		stack_index = smp_load_acquire(&lat_data->stack_index);
		if (!stack_index)
			continue;

		seq_printf(m, " cpu: %d\n", cpu);

		for (i = 0; i < stack_index; i++) {
			u64 msecs, plus;

			msecs = lat_data->latency[i].msecs;
			plus = lat_data->latency[i].plus;
			seq_printf(m, "%*cCOMMAND: %s PID: %d LATENCY: %llu%s\n",
				5, ' ', lat_data->comms[i], lat_data->pids[i],
				msecs, plus ? "+ms" : "ms");
			trace_stack_print(m, lat_data->stacks + i);
			seq_putc(m, '\n');

			cond_resched();
		}
	}
}

static int trace_stack_show(struct seq_file *m, void *v)
{
	seq_printf(m, "irq_latency_ms: %llu\n\n", irq_latency_ms);

	seq_puts(m, " irq:\n");
	trace_stack_irq_show(m, v, true);

	seq_putc(m, '\n');

	seq_puts(m, " softirq:\n");
	trace_stack_irq_show(m, v, false);

	return 0;
}

static int trace_stack_open(struct inode *inode, struct file *file)
{
	return single_open(file, trace_stack_show, inode->i_private);
}

static const struct proc_ops trace_stack_fops = {
	.proc_open	= trace_stack_open,
	.proc_read	= seq_read,
	.proc_write	= trace_stack_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

#define NUMBER_CHARACTER	40

static bool trace_histogram_show(struct seq_file *m, const char *header,
			   const unsigned long *hist, unsigned long size,
			   unsigned int factor)
{
	int i, zero_index = 0;
	unsigned long count_max = 0;

	for (i = 0; i < size; i++) {
		unsigned long count = hist[i];

		if (count > count_max)
			count_max = count;

		if (count)
			zero_index = i + 1;
	}
	if (count_max == 0)
		return false;

	/* print header */
	if (header)
		seq_printf(m, "%s\n", header);
	seq_printf(m, "%*c%s%*c : %-9s %s\n", 9, ' ', "msecs", 10, ' ', "count",
		   "latency distribution");

	for (i = 0; i < zero_index; i++) {
		int num;
		int scale_min, scale_max;
		char str[NUMBER_CHARACTER + 1];

		scale_max = 2 << i;
		scale_min = unlikely(i == 0) ? 1 : scale_max / 2;

		num = hist[i] * NUMBER_CHARACTER / count_max;
		memset(str, '*', num);
		memset(str + num, ' ', NUMBER_CHARACTER - num);
		str[NUMBER_CHARACTER] = '\0';

		seq_printf(m, "%10d -> %-10d : %-8lu |%s|\n",
			   scale_min * factor, scale_max * factor - 1,
			   hist[i], str);
	}

	return true;
}

static void trace_dist_show_irq(struct seq_file *m, void *v, unsigned int isirq)
{
	int cpu;
	unsigned long latency_count[MAX_LATENCY_RECORD] = { 0 };

	for_each_online_cpu(cpu) {
		int i;
		unsigned long *count;

		count = isirq ?
			per_cpu_ptr(detect_data->irq_data.latency_count, cpu) :
			per_cpu_ptr(detect_data->softirq_data.latency_count,
				    cpu);

		for (i = 0; i < MAX_LATENCY_RECORD; i++)
			latency_count[i] += count[i];
	}

	trace_histogram_show(m, isirq ? "irq-disable:" : "softirq-disable:",
		       latency_count, MAX_LATENCY_RECORD, freq_ms);
}

static int trace_dist_show(struct seq_file *m, void *v)
{
	trace_dist_show_irq(m, v, 1);
	trace_dist_show_irq(m, v, 0);

	return 0;
}

static int trace_dist_open(struct inode *inode, struct file *file)
{
	return single_open(file, trace_dist_show, inode->i_private);
}

static const struct proc_ops trace_dist_fops = {
	.proc_open	= trace_dist_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init trace_latency_init(void)
{
	struct proc_dir_entry *latency_dir;

	detect_data = alloc_percpu(struct per_cpu_detect_data);
	if (!detect_data)
		return -ENOMEM;

	latency_dir = proc_mkdir("irq_latency", NULL);
	if (!latency_dir)
		goto free_data;

	if (!proc_create("enable", 0600, latency_dir, &enable_fops))
		goto remove_proc;

	if (!proc_create("freq_ms", 0600, latency_dir, &freq_fops))
		goto remove_proc;

	if (!proc_create("latency_thresh_ms", 0600, latency_dir, &lat_fops))
		goto remove_proc;

	if (!proc_create("trace_stack", 0600, latency_dir, &trace_stack_fops))
		goto remove_proc;

	if (!proc_create("trace_dist", 0400, latency_dir, &trace_dist_fops))
		goto remove_proc;

	pr_info("Load irq latency check module!\n");
	return 0;

remove_proc:
	remove_proc_subtree("irq_latency", NULL);
free_data:
	free_percpu(detect_data);

	return -ENOMEM;
}

static void __exit trace_latency_exit(void)
{
	if (check_enable)
		latency_timers_stop();
	remove_proc_subtree("irq_latency", NULL);
	free_percpu(detect_data);
	pr_info("Unload irq latency check module!\n");
}

module_init(trace_latency_init);
module_exit(trace_latency_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("shookliu <shookliu@tencent.com>");
