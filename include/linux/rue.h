/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_RUE_H
#define __LINUX_RUE_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/mutex.h>

struct rue_ops {
#ifdef CONFIG_CGROUP_NET_CLASSID
	struct rue_net_ops *net;
#endif

#ifdef CONFIG_MEMCG
	struct rue_mem_ops *mem;
#endif
};

extern int sysctl_net_qos_enable;

extern int sysctl_vm_memory_qos;
extern struct rue_mem_ops mem_ops;

extern bool rue_installed;
extern struct rue_ops *rue_mod_ops;
DECLARE_PER_CPU(long, nr_rue_calls);
extern struct mutex rue_mutex;

int register_rue_ops(struct rue_ops *ops);
int try_unregister_rue_ops(void);

#ifdef CONFIG_CGROUP_NET_CLASSID
#define RUE_NET_FUNC(ops, func) ops->net->func  /* RUE NET OPs */
#endif

#ifdef CONFIG_MEMCG
#define RUE_MEM_FUNC(ops, func) ops->mem->func  /* RUE MEM OPs */
#endif

#define RUE_FUNC(subsys, ops, func) RUE_##subsys##_FUNC(ops, func)

#define RUE_CALL_TYPE(subsys, func, retype, ...)                               \
	({                                                                     \
		retype ret = {0};                                              \
		struct rue_ops *__ops;                                         \
		typeof(RUE_FUNC(subsys, __ops, func)) __f;                     \
		preempt_disable();                                             \
		__ops = READ_ONCE(rue_mod_ops);                                \
		if (__ops) {                                                   \
			__f = RUE_FUNC(subsys, __ops, func);                   \
			BUG_ON(!__f);                                          \
			this_cpu_inc(nr_rue_calls);                            \
			preempt_enable();                                      \
			ret = __f(__VA_ARGS__);                                \
			this_cpu_dec(nr_rue_calls);                            \
		} else {                                                       \
			preempt_enable();                                      \
		}                                                              \
		ret;                                                           \
	})

#define RUE_CALL_VOID(subsys, func, ...)                                       \
	({                                                                     \
		struct rue_ops *__ops;                                         \
		typeof(RUE_FUNC(subsys, __ops, func)) __f;                     \
		preempt_disable();                                             \
		__ops = READ_ONCE(rue_mod_ops);                                \
		if (__ops) {                                                   \
			__f = RUE_FUNC(subsys, __ops, func);                   \
			BUG_ON(!__f);                                          \
			this_cpu_inc(nr_rue_calls);                            \
			preempt_enable();                                      \
			__f(__VA_ARGS__);                                      \
			this_cpu_dec(nr_rue_calls);                            \
		} else {                                                       \
			preempt_enable();                                      \
		}                                                              \
	})

#define RUE_CALL_PTR(subsys, func, ...)                                        \
	RUE_CALL_TYPE(subsys, func, void *, __VA_ARGS__)

#define RUE_CALL_INT(subsys, func, ...)                                        \
	RUE_CALL_TYPE(subsys, func, int, __VA_ARGS__)

#endif /* __LINUX_RUE_H */
