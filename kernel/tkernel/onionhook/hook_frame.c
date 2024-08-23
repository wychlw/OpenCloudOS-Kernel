#include<net/sock.h>
#include<linux/hook_frame.h>
#include<linux/fs.h>

#ifdef CONFIG_TKERNEL_SECURITY_MONITOR
int hook_info_flag;
EXPORT_SYMBOL(hook_info_flag);

unsigned long hook_func_array[INFO_MAX];
EXPORT_SYMBOL(hook_func_array);

void (*get_execve_info_func)(int argc, void *argv, int envc, void *envp, const char *filename);
EXPORT_SYMBOL(get_execve_info_func);

void (*get_connect_info_func)(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err);
EXPORT_SYMBOL(get_connect_info_func);

void (*get_accept_info_func)(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err);
EXPORT_SYMBOL(get_accept_info_func);

void (*get_sendto_info_func)(struct socket *sock, int fd, struct sockaddr_storage *address, int err);
EXPORT_SYMBOL(get_sendto_info_func);

void (*get_recvfrom_info_func)(struct socket *sock, int fd, struct sockaddr_storage *address, int err);
EXPORT_SYMBOL(get_recvfrom_info_func);

void (*get_sock_info_func)(struct sock *sk);
EXPORT_SYMBOL(get_sock_info_func);

void (*get_fork_info_func)(struct task_struct *p, unsigned long clone_flags);
EXPORT_SYMBOL(get_fork_info_func);

void (*get_exit_info_func)(struct task_struct *tsk, long code);
EXPORT_SYMBOL(get_exit_info_func);

static DEFINE_PER_CPU(long, hook_info_count) __aligned(64);
long hookinfo_nr(void)
{
	int cpu;
	long total = 0;

	for_each_possible_cpu(cpu) {
		total += per_cpu(hook_info_count, cpu);
	}
	return total;
}
EXPORT_SYMBOL(hookinfo_nr);

void data_release(struct kref *ref)
{
	struct security_moni_info *data = container_of(ref, struct security_moni_info, refcount);

	kfree(data);
}
EXPORT_SYMBOL(data_release);

void execve_hook_check(int argc, void *argv, int envc, void *envp, const char *filename)
{
	if (execve_info_flag && hook_info_flag) {
		__this_cpu_inc(hook_info_count);
		smp_rmb();
		get_execve_info_func = (typeof(get_execve_info_func))hook_func_array[EXECVE_INFO];
		if (get_execve_info_func) {
			get_execve_info_func(argc, argv, envc, envp, filename);
		}

		__this_cpu_dec(hook_info_count);
	}
}

void accept_hook_check(struct socket *newsock, struct file *newfile, struct sockaddr_storage *address, int err)
{
	if (accept_info_flag && hook_info_flag) {
		__this_cpu_inc(hook_info_count);
		smp_rmb();
		get_accept_info_func = (typeof(get_accept_info_func))hook_func_array[ACCEPT_INFO];
		if (get_accept_info_func) {
			get_accept_info_func(newsock, newfile, NULL, err);
		}

		__this_cpu_dec(hook_info_count);
	}
}

void connect_hook_check(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err)
{
	if (connect_info_flag && hook_info_flag) {
		__this_cpu_inc(hook_info_count);
		smp_rmb();
		get_connect_info_func = (typeof(get_connect_info_func))hook_func_array[CONNECT_INFO];
		if (get_connect_info_func) {
			get_connect_info_func(sock, newfile, address, err);
		}
		__this_cpu_dec(hook_info_count);
	}
}

void sendto_hook_check(struct socket *sock, int fd, struct sockaddr_storage *address, int err)
{
	if (sendto_info_flag && hook_info_flag && err >= 0) {
		__this_cpu_inc(hook_info_count);
		smp_rmb();
		get_sendto_info_func = (typeof(get_sendto_info_func))hook_func_array[SENDTO_INFO];
		if (get_sendto_info_func) {
			get_sendto_info_func(sock, fd, address, err);
		}

		__this_cpu_dec(hook_info_count);
	}
}

void recvfrom_hook_check(struct socket *sock, int fd, struct sockaddr_storage *address, int err)
{
	if (recvfrom_info_flag && hook_info_flag && err >= 0) {
		__this_cpu_inc(hook_info_count);
		smp_rmb();
		get_recvfrom_info_func = (typeof(get_recvfrom_info_func))hook_func_array[RECVFROM_INFO];
		if (get_recvfrom_info_func) {
			get_recvfrom_info_func(sock, fd, address, err);
		}

		__this_cpu_dec(hook_info_count);
	}
}

void sock_hook_check(void *sock)
{
	struct sock *sk = sock;

	if (sock_info_flag && hook_info_flag) {
		__this_cpu_inc(hook_info_count);
		smp_rmb();
		get_sock_info_func = (typeof(get_sock_info_func))hook_func_array[SOCK_INFO];
		if (get_sock_info_func) {
			get_sock_info_func(sk);
		}
		__this_cpu_dec(hook_info_count);
	}
}
EXPORT_SYMBOL(sock_hook_check);

void fork_hook_check(struct task_struct *p, unsigned long clone_flags)
{
	if (fork_info_flag && hook_info_flag) {
		__this_cpu_inc(hook_info_count);
		smp_rmb();
		get_fork_info_func = (typeof(get_fork_info_func))hook_func_array[FORK_INFO];
		if (get_fork_info_func) {
			get_fork_info_func(p, clone_flags);
		}

		__this_cpu_dec(hook_info_count);
	}
}

void exit_hook_check(struct task_struct *tsk, long code)
{
	if (exit_info_flag && hook_info_flag) {
		__this_cpu_inc(hook_info_count);
		smp_rmb();
		get_exit_info_func = (typeof(get_exit_info_func))hook_func_array[EXIT_INFO];
		if (get_exit_info_func) {
			get_exit_info_func(tsk, code);
		}

		__this_cpu_dec(hook_info_count);
	}
}

#else

void sock_hook_check(void *sock)
{
}
void recvfrom_hook_check(struct socket *sock, int fd, struct sockaddr_storage *address, int err)
{
}
void sendto_hook_check(struct socket *sock, int fd, struct sockaddr_storage *address, int err)
{
}
void connect_hook_check(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err)
{
}
void accept_hook_check(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err)
{
}
void execve_hook_check(int argc, void *argv, int envc, void *envp, const char *filename)
{
}
void fork_hook_check(struct task_struct *p, unsigned long clone_flags)
{
}
void exit_hook_check(struct task_struct *tsk, long code)
{
}
#endif
