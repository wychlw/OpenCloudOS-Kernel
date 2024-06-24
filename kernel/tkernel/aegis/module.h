#ifndef AEGIS_MODULE_MODULE_H_
#include <linux/cpumask.h>
#define AEGIS_MODULE_MODULE_H_

#define KERNEL_ATTR_RW(_name) \
	static struct kobj_attribute _name##_attr = \
__ATTR(_name, 0644, _name##_show, _name##_store)

extern int hook_info_flag;
extern long nr_hook_count(int flag);
extern long nr_execve_count(void);

extern int mod_sysctl_add(void);
extern void mod_sysctl_del(void);
extern const struct cpumask *hook_cpu_mask;

#endif  // AEGIS_MODULE_MODULE_H_
