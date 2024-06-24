#include <linux/file.h>
#include <net/sock.h>
#include <uapi/linux/binfmts.h>
#include <linux/un.h>
#include <linux/kref.h>
#include <net/sock.h>
#include <linux/cpu.h>
#include <net/inet_sock.h>
#include <linux/pid_namespace.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/fs_struct.h>
#include <linux/hook_frame.h>

#include "hook_info.h"
#include "list.h"
#include "module.h"

char ssh_info_head[SSH_INFO_LEN] = "SSH_GLOBAL_ONION_INFOMATION";
char ssh_tty_head[SSH_TTY_LEN] = "SSH_TTY";



enum PWD_FLAG_TYPE {
	PWD_INIT,
	PWD_CORR,
	PWD_TOOLARGE,
	PWD_GETERR
};

struct hook_info hook_info_array[] = {
	{ "execve_info", EXECVE_INFO, (unsigned long)get_execve_info, execinfo_to_user, extra_execinfo_free},
	{ "sock_info",   SOCK_INFO,   (unsigned long)get_sock_info,   sockinfo_to_user, NULL},
	{}
};

unsigned int para_len_current = PARA_LEN_DEFAULT;
unsigned int para_sum_current = PARA_SUM_DEFAULT;
unsigned long min_para_len = 2 | SYSCTL_SET_MAGIC;
unsigned long max_para_len = 4096 | SYSCTL_SET_MAGIC;

unsigned long sysctl_para_len = PARA_LEN_DEFAULT;
unsigned long sysctl_para_sum = PARA_SUM_DEFAULT;
unsigned long sysctl_info_num = INFO_NUM_DEFAULT;
unsigned long sysctl_poll_wakeup_length = WAKEUP_LENGTH_DEFAULT;

unsigned long sysctl_set_min = 0x0 | SYSCTL_SET_MAGIC;
unsigned long sysctl_set_max = 0xffffffff | SYSCTL_SET_MAGIC;
static struct ctl_table_header *sysctl_header;
static struct ctl_table_header *sysctl_tbl;

#if IS_MODULE(CONFIG_TKERNEL_AEGIS_MODULE)
u64 nsec_to_clock_t(u64 x)
{
#if (NSEC_PER_SEC % USER_HZ) == 0
	return div_u64(x, NSEC_PER_SEC / USER_HZ);
#elif (USER_HZ % 512) == 0
	return div_u64(x * USER_HZ / 512, NSEC_PER_SEC / 512);
#else
	return div_u64(x * 9, (9ull * NSEC_PER_SEC + (USER_HZ / 2)) / USER_HZ);
#endif
}
#endif


static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

void hookinfo_total_numb(int type)
{
	this_cpu_inc(*hook_info_array[type].total_numb);
}

void hookinfo_drop_stats(int type)
{
	this_cpu_inc(*hook_info_array[type].drop_stats);
}

void clear_task_environ(struct exec_info *exec_info)
{
	if (exec_info->env_info) {
		kfree(exec_info->env_info);
		exec_info->env_info = NULL;
		exec_info->size -= exec_info->inf_size;
		exec_info->inf_size = 0;
	}

	if (exec_info->env_tty) {
		kfree(exec_info->env_tty);
		exec_info->env_tty = NULL;
		exec_info->size -= exec_info->tty_size;
		exec_info->tty_size = 0;
	}
}

int get_task_environ(struct exec_info *exec_info,
			int envc, struct user_arg_ptr *envp)
{
	int i = 0, ret = 0;
	long len, max_len = SSH_INFO_LEN;
	const char __user *str;
	char src_envhead[SSH_INFO_LEN] = "";

	while (i < envc) {
		cond_resched();

		str = get_user_arg_ptr(*envp, i);
		if (IS_ERR(str)) {
			ret = -EFAULT;
			goto err;
		}

		len = strnlen_user(str, MAX_ARG_STRLEN);
		if (!len) {
			ret = -EFAULT;
			goto err;
		}

		if (copy_from_user(src_envhead, str,  min(max_len, len))) {
			ret = -EFAULT;
			goto err;
		}

		src_envhead[SSH_INFO_LEN - 1] = '\0';
		if (!exec_info->env_info &&
				strcmp(ssh_info_head, src_envhead) == 0) {
			exec_info->env_info = kzalloc(len, GFP_KERNEL);
			if (!exec_info->env_info) {
				ret = -ENOMEM;
				goto err;
			}
			if (copy_from_user(exec_info->env_info, str, len)) {
				ret = -EFAULT;
				goto err;
			}
			exec_info->inf_size = len;
			exec_info->size += len;
			goto check;
		}

		src_envhead[SSH_TTY_LEN - 1] = '\0';
		if (!exec_info->env_tty &&
			strcmp(ssh_tty_head, src_envhead) == 0) {
			exec_info->env_tty = kzalloc(len, GFP_KERNEL);
			if (!exec_info->env_tty) {
				ret = -ENOMEM;
				goto err;
			}
			if (copy_from_user(exec_info->env_tty, str, len)) {
				ret = -EFAULT;
				goto err;
			}
			exec_info->tty_size = len;
			exec_info->size += len;
		}
check:
		if (exec_info->env_info && exec_info->env_tty)
			goto out;
		i++;
	}

	return 0;

err:
	if (exec_info->env_info) {
		kfree(exec_info->env_info);
		exec_info->env_info = NULL;
		exec_info->size -= exec_info->inf_size;
		exec_info->inf_size = 0;
	}

	if (exec_info->env_tty) {
		kfree(exec_info->env_tty);
		exec_info->env_tty = NULL;
		exec_info->size -= exec_info->tty_size;
		exec_info->tty_size = 0;
	}
out:
	return ret;
}

int get_task_para(int argc, struct user_arg_ptr *argv)
{
	int i = 0, ret = 0;
	long len, sum = 0, point = 0;
	const char __user *str;
	unsigned int para_len = para_len_current;
	unsigned int para_sum = para_sum_current;

	para_sum = para_sum > para_len ? para_sum : para_len;

	while (i < argc) {
		str = get_user_arg_ptr(*argv, i);
		if (IS_ERR(str)) {
			ret = -EFAULT;
			goto out;
		}
		len = strnlen_user(str, MAX_ARG_STRLEN);
		if (!len) {
			ret = -EFAULT;
			goto out;
		}

		if (len > para_len)
			len = para_len;

		sum += len;

		if (sum > para_sum) {
			sum = para_sum;
			break;
		}
		i++;
	}

	if (current->my_moni_info)
		kref_put(&current->my_moni_info->refcount, data_release);

	current->my_moni_info = kzalloc(sizeof(struct security_moni_info)
						+ sum, GFP_KERNEL);
	if (!current->my_moni_info) {
		ret = -ENOMEM;
		goto out;
	}
	kref_init(&current->my_moni_info->refcount);

	current->my_moni_info->size = sum;

	para_sum = sum;
	i = 0;
	sum = 0;
	while (i < argc) {
		str = get_user_arg_ptr(*argv, i);
		if (IS_ERR(str)) {
			ret = -EFAULT;
			goto error;
		}

		len = strnlen_user(str, MAX_ARG_STRLEN);
		if (!len) {
			ret = -EFAULT;
			goto error;
		}
		if (len > para_len)
			len = para_len;
		if (sum + len > para_sum)
			len = para_sum - sum;

		if (copy_from_user(current->my_moni_info->buffer + point,
					str, len)) {
			ret = -EFAULT;
			goto error;
		}

		point += len;
		current->my_moni_info->buffer[point - 1] = '\0';
		sum += len;
		if (sum >= para_sum)
			goto out;
		i++;
	}

	return 0;

error:
	kref_put(&current->my_moni_info->refcount, data_release);
	current->my_moni_info = NULL;
out:
	return ret;

}

void get_pidns_inum(struct exec_info *exec_info)
{
	struct pid_namespace *ns = NULL;

	rcu_read_lock();
	ns = task_active_pid_ns(current);
	if (ns) {
		get_pid_ns(ns);
		exec_info->inum = ns->ns.inum;
		put_pid_ns(ns);
	}
	rcu_read_unlock();
}

void get_task_ids(struct exec_info *exec_info)
{
	exec_info->init_pid = task_pid_nr_ns(current, &init_pid_ns);
	exec_info->acti_pid = task_pid_nr_ns(current, NULL);
	exec_info->init_ppid = task_ppid_nr_ns(current, &init_pid_ns);
	exec_info->acti_ppid = task_ppid_nr_ns(current, NULL);
	exec_info->acti_uid = from_kuid_munged(current_user_ns(), current_uid());
	exec_info->acti_gid = from_kgid_munged(current_user_ns(), current_gid());
	exec_info->acti_euid = from_kuid_munged(current_user_ns(), current_euid());
	exec_info->acti_egid = from_kgid_munged(current_user_ns(), current_egid());
}

void get_task_pwd(struct exec_info *exec_info)
{
	struct path pwdpath;
	char path[PWD_LEN] = "\0";
	char *ppath = path;

	if (current->fs) {
		get_fs_pwd(current->fs, &pwdpath);
		ppath = d_path(&pwdpath, path, PWD_LEN);
		if (!IS_ERR(ppath)) {
			exec_info->pwd_flag = PWD_CORR;
			memcpy(exec_info->pwd, ppath, path + PWD_LEN - ppath);
		} else {
			exec_info->pwd_flag = PWD_GETERR;
			if (PTR_ERR(ppath) == -ENAMETOOLONG) {
				exec_info->pwd_flag = PWD_TOOLARGE;
				memcpy(exec_info->pwd, path, PWD_LEN);
			}
		}
		path_put(&pwdpath);
	}
}

void get_task_start_time(struct exec_info *exec_info)
{
	exec_info->start_time = nsec_to_clock_t(current->start_boottime);
}

void info_ptr_hold_ref(struct exec_info *exec_info)
{

	exec_info->parent = current->par_moni_info;
	if (exec_info->parent) {
		kref_get(&exec_info->parent->refcount);
		exec_info->size += exec_info->parent->size;
		exec_info->pa_size = exec_info->parent->size;
	}

	exec_info->my = current->my_moni_info;
	if (exec_info->my) {
		kref_get(&exec_info->my->refcount);
		exec_info->size += exec_info->my->size;
		exec_info->my_size = exec_info->my->size;
	}
}

void get_execve_info(int argc, struct user_arg_ptr *argv, int envc, struct user_arg_ptr *envp, const char *filename)
{
	struct exec_info *exec_info;

	hookinfo_total_numb(EXECVE_INFO);

	if (atomic64_read(this_cpu_ptr(hook_info_array[EXECVE_INFO].info_num)) > (sysctl_info_num & SYSCTL_VALID_MASK))
		goto drop;

	exec_info = kzalloc(sizeof(struct exec_info), GFP_KERNEL);

	if (!exec_info)
		goto drop;

	exec_info->size += sizeof(struct exec_info) - 4 * sizeof(void *) - sizeof(struct list_head);
	exec_info->type = EXECVE_INFO;
	exec_info->magic = INFO_MAGIC;

	if (get_task_environ(exec_info, envc, envp))
		goto err;

	if (get_task_para(argc, argv))
		goto para_err;

	get_pidns_inum(exec_info);

	get_task_ids(exec_info);

	get_task_pwd(exec_info);

	get_task_start_time(exec_info);

	info_ptr_hold_ref(exec_info);

	hookinfo_list_in(&exec_info->head, (int)EXECVE_INFO);

	return;

para_err:
	clear_task_environ(exec_info);
err:
	kfree(exec_info);
drop:
	hookinfo_drop_stats(EXECVE_INFO);
}

void extra_execinfo_free(struct list_head *info_head)
{
	struct exec_info *exec_info = (struct exec_info *)info_head;

	if (exec_info->parent) {
		kref_put(&exec_info->parent->refcount, data_release);
		exec_info->parent = 0;
	}
	if (exec_info->my) {
		kref_put(&exec_info->my->refcount, data_release);
		exec_info->my = 0;
	}
	if (exec_info->env_info) {
		kfree(exec_info->env_info);
		exec_info->env_info = 0;
	}
	if (exec_info->env_tty) {
		kfree(exec_info->env_tty);
		exec_info->env_tty = 0;
	}
}

int execinfo_to_user(struct list_head *info_head, char __user **buf, size_t count, int cpu)
{

	int readsize = 0, ret, headlen;
	struct exec_info *exec_info = (struct exec_info *)info_head;
	int size = exec_info->size;

	if (size > count) {
		ret = -EFBIG;
		goto out;
	}

	headlen = sizeof(struct exec_info) - 4 * sizeof(void *) - sizeof(struct list_head);

	if (copy_to_user(*buf, (void *)&exec_info->magic, headlen)) {
		return -EFAULT;
		goto out;
	}

	*buf += headlen;
	readsize += headlen;

	if (exec_info->parent) {
		if (copy_to_user(*buf, exec_info->parent->buffer, exec_info->parent->size)) {
			ret = -EFAULT;
			goto par_err;
		}
		*buf += exec_info->parent->size;
		readsize += exec_info->parent->size;
	}

	if (exec_info->my) {
		if (copy_to_user(*buf, exec_info->my->buffer, exec_info->my->size)) {
			ret = -EFAULT;
			goto my_err;
		}
		*buf += exec_info->my->size;
		readsize += exec_info->my->size;
	}

	if (exec_info->env_info) {
		if (copy_to_user(*buf, exec_info->env_info, exec_info->inf_size)) {
			ret = -EFAULT;
			goto info_err;
		}
		*buf += exec_info->inf_size;
		readsize += exec_info->inf_size;
	}

	if (exec_info->env_tty) {
		if (copy_to_user(*buf, exec_info->env_tty, exec_info->tty_size)) {
			ret = -EFAULT;
			goto tty_err;
		}
		*buf += exec_info->tty_size;
		readsize += exec_info->tty_size;
	}

	extra_execinfo_free(info_head);

	return readsize;

tty_err:
	*buf -= exec_info->inf_size;
	readsize -= exec_info->inf_size;
info_err:
	*buf -= exec_info->my->size;
	readsize -= exec_info->my->size;
my_err:
	*buf -= exec_info->parent->size;
	readsize -= exec_info->parent->size;
par_err:
	*buf -= headlen;
	readsize -= headlen;
out:
	return ret;
}

ssize_t hook_info_read(struct hook_info *info,
		struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int cpu;
	bool try;
	struct list_head *list, *info_head, *tmp;
	int len = 0, ret;
	raw_spinlock_t *plock;

	get_online_cpus();
	for_each_cpu((cpu), hook_cpu_mask) {
		try = true;
retry:
		list = &info->list;
		list_for_each_safe(info_head, tmp, list) {
			ret = info->to_user_func(info_head, &buf, count, cpu);
			if (ret < 0) {
				put_online_cpus();
				return len;
			}
			count -= ret;
			len += ret;
			list_del(info_head);
			kfree(info_head);
			atomic64_dec(per_cpu_ptr(hook_info_array[info->type].info_num,
							hook_info_array[info->type].last_cpu));
		}

		plock = per_cpu_ptr(info->lock, cpu);
		hook_info_array[info->type].last_cpu = cpu;
		raw_spin_lock_bh(plock);
		list_replace_init(per_cpu_ptr(info->lists, cpu), &info->list);
		raw_spin_unlock_bh(plock);
		if (try) {
			try = false;
			goto retry;
		}
	}
	put_online_cpus();

	return len;
}

int sockinfo_to_user(struct list_head *info_head, char __user **buf, size_t count, int cpu)
{
	struct sock_info *node = (struct sock_info *)info_head;
	unsigned int hookinfo_len = node->size;

	if (hookinfo_len > count)
		return -EFBIG;

	if (copy_to_user(*buf, (void *)&node->magic, hookinfo_len))
		return -EFAULT;

	*buf += hookinfo_len;

	return hookinfo_len;
}

void get_sock_info(struct sock *sk)
{
	struct sock_info *node;
	const struct inet_sock *inet;

	hookinfo_total_numb(SOCK_INFO);

	if (atomic64_read(this_cpu_ptr(hook_info_array[SOCK_INFO].info_num)) > (sysctl_info_num & SYSCTL_VALID_MASK))
		goto drop;

	node = kzalloc(sizeof(struct sock_info), GFP_NOWAIT);

	if (!node)
		goto drop;

	node->magic = INFO_MAGIC;
	node->info_type = SOCK_INFO;
	node->size = sizeof(struct sock_info) - sizeof(node->head);

	inet = inet_sk(sk);
	node->dest = inet->inet_daddr;
	node->src = inet->inet_rcv_saddr;
	node->destp = ntohs(inet->inet_dport);
	node->srcp = ntohs(inet->inet_sport);
	node->state = sk->sk_state;
	node->type = sk->sk_type;
	node->family = sk->sk_family;
	node->pid = sk->pid;
#if IS_ENABLED(CONFIG_IPV6)
	node->daddr6 = sk->sk_v6_daddr;
	node->saddr6 = sk->sk_v6_rcv_saddr;
#endif

	hookinfo_list_in(&node->head, (int)SOCK_INFO);
	return;
drop:
	hookinfo_drop_stats(SOCK_INFO);
}

int para_len_sum_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int ret;
	unsigned int old_len, old_sum;

	static DEFINE_MUTEX(mutex);

	mutex_lock(&mutex);
	old_len = sysctl_para_len;
	old_sum = sysctl_para_sum;
	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto err;

	if (write) {
		*(unsigned long *)(table->data) = (*(unsigned long *)(table->data)) & 0xffffffff;
		if (sysctl_para_len > sysctl_para_sum) {
			sysctl_para_len = old_len;
			sysctl_para_sum = old_sum;
			ret = -EINVAL;
			goto err;
		}
		para_len_current = (unsigned int)sysctl_para_len;
		para_sum_current = (unsigned int)sysctl_para_sum;
	}

err:
	mutex_unlock(&mutex);
	return ret;
}

int secur_sysctl_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int ret;
	static DEFINE_MUTEX(info_num_mutex);

	mutex_lock(&info_num_mutex);
	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto err;

	if (write)
		*(unsigned long *)(table->data) = (*(unsigned long *)(table->data)) & 0xffffffff;

err:
	mutex_unlock(&info_num_mutex);
	return ret;
}

static struct ctl_table security_control_table[] = {
	{
		.procname	= "secur_para_len",
		.data		= &sysctl_para_len,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= para_len_sum_handler,
		.extra1		= &min_para_len,
		.extra2		= &max_para_len,
	},
	{
		.procname	= "secur_para_sum",
		.data		= &sysctl_para_sum,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= para_len_sum_handler,
		.extra1		= &min_para_len,
		.extra2		= &max_para_len,
	},
	{
		.procname	= "secur_info_num",
		.data		= &sysctl_info_num,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= secur_sysctl_handler,
		.extra1		= &sysctl_set_min,
		.extra2		= &sysctl_set_max,
	},
	{
		.procname	= "secur_poll_wakeup_length",
		.data		= &sysctl_poll_wakeup_length,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= secur_sysctl_handler,
		.extra1		= &sysctl_set_min,
		.extra2		= &sysctl_set_max,
	},
	{ }
};

static struct ctl_table security_table[] = {
	{
		//.procname	= "security_sysctl",
		.procname	= NULL,
		.maxlen		= 0,
		.mode		= 0555,
	},
	{ }
};

int mod_sysctl_add(void)
{
	sysctl_header = register_sysctl("security_sysctl", security_table);
	if (!sysctl_header)
		return -ENOMEM;

	sysctl_tbl = register_sysctl("security_sysctl", security_control_table);
	if (!sysctl_tbl) {
		unregister_sysctl_table(sysctl_header);
		return -ENOMEM;
	}

	return 0;
}

void mod_sysctl_del(void)
{
	if (sysctl_tbl)
		unregister_sysctl_table(sysctl_tbl);

	if (sysctl_header)
		unregister_sysctl_table(sysctl_header);
}
