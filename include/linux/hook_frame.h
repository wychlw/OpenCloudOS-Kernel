#ifndef __HOOK_FRAME_H__
#define  __HOOK_FRAME_H__

#include<linux/net.h>
#include<linux/socket.h>
#include<linux/fs.h>

#define SYSCTL_SET_MAGIC        (0x5a5a5a5aUL << 32)

/* attention!!!
 * this emum value must be equal hook_info_array index
 */
enum {
	EXECVE_INFO,
	SOCK_INFO,
	CONNECT_INFO,
	ACCEPT_INFO,
	SENDTO_INFO,
	RECVFROM_INFO,
	FORK_INFO,
	EXIT_INFO,
	INFO_MAX
};

extern unsigned long hook_func_array[INFO_MAX];

extern int hook_info_flag;
extern unsigned long execve_info_flag;
extern unsigned long connect_info_flag;
extern unsigned long accept_info_flag;
extern unsigned long sendto_info_flag;
extern unsigned long recvfrom_info_flag;
extern unsigned long sock_info_flag;
extern unsigned long fork_info_flag;
extern unsigned long exit_info_flag;

extern void (*get_execve_info_func)(int argc, void *argv, int envc, void *envp, const char *filename);
extern void (*get_connect_info_func)(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err);
extern void (*get_accept_info_func)(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err);
extern void (*get_sendto_info_func)(struct socket *sock, int fd, struct sockaddr_storage *address, int err);
extern void (*get_recvfrom_info_func)(struct socket *sock, int fd, struct sockaddr_storage *address, int err);
extern void (*get_sock_info_func)(struct sock *sk);
extern void (*get_fork_info_func)(struct task_struct *p, unsigned long clone_flags);
extern void (*get_exit_info_func)(struct task_struct *tsk, long code);

extern long hookinfo_nr(void);

extern void sock_hook_check(void *sk);
extern void recvfrom_hook_check(struct socket *sock, int fd, struct sockaddr_storage *address, int err);
extern void sendto_hook_check(struct socket *sock, int fd, struct sockaddr_storage *address, int err);
extern void connect_hook_check(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err);
extern void accept_hook_check(struct socket *sock, struct file *newfile, struct sockaddr_storage *address, int err);
extern void execve_hook_check(int argc, void *argv, int envc, void *envp, const char *filename);
extern void fork_hook_check(struct task_struct *p, unsigned long clone_flags);
extern void exit_hook_check(struct task_struct *tsk, long code);
#endif
