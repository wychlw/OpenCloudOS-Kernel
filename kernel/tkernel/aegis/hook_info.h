#ifndef AEGIS_MODULE_HOOK_INFO_H_
#define AEGIS_MODULE_HOOK_INFO_H_

#include <linux/compat.h>
#include <linux/in6.h>

#define SYSCTL_SET_MAGIC (0x5a5a5a5aUL << 32)
#define SYSCTL_VALID_MASK (0xffffffffUL)
#define PARA_LEN_DEFAULT 100
#define PARA_SUM_DEFAULT 1024
#define INFO_NUM_DEFAULT 2048
#define WAKEUP_LENGTH_DEFAULT 1

/* The last byte indicates the version of the captured information. */
#define INFO_MAGIC 0x12345601

#define SSH_INFO_LEN 28
#define SSH_TTY_LEN 8
#define PWD_LEN 64
#define STATISTIC_NUM 2
#define STATISTIC_VERSION 10001



/* Wrappers which go away once all code is converted */
static inline void cpu_hotplug_begin(void) { cpus_write_lock(); }
static inline void cpu_hotplug_done(void) { cpus_write_unlock(); }
static inline void get_online_cpus(void) { cpus_read_lock(); }
static inline void put_online_cpus(void) { cpus_read_unlock(); }

struct exec_info {
	struct list_head head;
	unsigned long magic;
	int type;
	int size;
	int pa_size;
	int my_size;
	int inf_size;
	int tty_size;
	pid_t init_pid;
	pid_t acti_pid;
	pid_t init_ppid;
	pid_t acti_ppid;
	uid_t acti_uid;
	gid_t acti_gid;
	uid_t acti_euid;
	gid_t acti_egid;
	int pwd_flag;
	unsigned int inum;
	unsigned long long start_time;
	char pwd[64];
	struct security_moni_info *parent;
	struct security_moni_info *my;
	char *env_info;
	char *env_tty;
};

struct sock_info {
	struct list_head head;
	unsigned long magic;
	int info_type;
	int size;
	__be32 dest;
	__be32 src;
	__u16 destp;
	__u16 srcp;
	int state;
	__u16 type;
	__u16 family;
	pid_t pid;
	struct in6_addr	daddr6;
	struct in6_addr saddr6;
};

typedef void (*extra_free_func_t)(struct list_head *info_head);
typedef int (*to_user_func_t)(struct list_head *info_head, char __user **buf, size_t count, int cpu);

struct hook_info {
	const char *dir;
	int type;
	unsigned long hook_func_addr;
	to_user_func_t to_user_func;
	extra_free_func_t extra_free_func;
	struct list_head list;
	struct list_head __percpu *lists;
	raw_spinlock_t __percpu *lock;
	atomic64_t __percpu *info_num;
	wait_queue_head_t wait_queue;
	struct mutex readlock;
	unsigned long __percpu *drop_stats;
	unsigned long __percpu *total_numb;
	int last_cpu;
};

struct info_entry {
	int type;
	char padding[4];
	unsigned long long total;
	unsigned long long discard;
};

struct statistics_info {
	int version;
	char padding[4];
	struct info_entry info_entry[STATISTIC_NUM];
};

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

extern struct hook_info hook_info_array[];
extern unsigned long sysctl_poll_wakeup_length;
extern ssize_t hook_info_read(struct hook_info *info, struct file *file,
			    char __user *buf, size_t count, loff_t *ppos);

extern void get_execve_info(int argc, struct user_arg_ptr *argv, int envc,
			    struct user_arg_ptr *envp, const char *filename);
extern void get_sock_info(struct sock *sk);

extern int execinfo_to_user(struct list_head *info_head, char __user **buf,
			    size_t count, int cpu);
extern int sockinfo_to_user(struct list_head *info_head, char __user **buf,
			    size_t count, int cpu);
extern void extra_execinfo_free(struct list_head *exec_info);

#endif  // AEGIS_MODULE_HOOK_INFO_H_
