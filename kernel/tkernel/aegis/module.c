#include <linux/module.h>
#include <net/sock.h>
#include <linux/cpu.h>
#include <linux/hook_frame.h>
#include "module.h"
#include "list.h"
#include "hook_info.h"

static bool module_putted;
static struct mutex hook_lock;
static struct kset *hook_sysfs_kset;
static enum cpuhp_state cpu_online_enum;
const struct cpumask *hook_cpu_mask = cpu_online_mask;

void hook_disable(void)
{
	mutex_lock(&hook_lock);
	hook_info_flag = 0;
	smp_wmb();
	hook_info_func_unregister();
	if (!module_putted && !hookinfo_nr()) {
		module_put(THIS_MODULE);
		module_putted = true;
	}
	mutex_unlock(&hook_lock);
}

static ssize_t disable_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	return sprintf(buf, "%s\t%s\t%ld\n",
			hook_info_flag ? "enabled" : "disabled",
			module_putted ? "unused" : "inuse", hookinfo_nr());
}

static ssize_t disable_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long v;

	if (kstrtoul(buf, 0, &v))
		return -EINVAL;

	if ((v & 0xffffffff00000000) !=  SYSCTL_SET_MAGIC)
		return -EINVAL;

	if (v & 0x00000000ffffffff)
		hook_disable();

	return count;
}

KERNEL_ATTR_RW(disable);

static struct attribute *security_moni_attrs[] = {
	&disable_attr.attr,
	NULL
};

static struct attribute_group hook_attrs_group = {
	.attrs = security_moni_attrs,
};

int hook_sysfs_init(void)
{
	int ret;

	hook_sysfs_kset = kset_create_and_add("aegis", NULL, kernel_kobj);
	if (!hook_sysfs_kset)
		return -ENOMEM;

	ret = sysfs_create_group(&hook_sysfs_kset->kobj, &hook_attrs_group);
	if (ret)
		kset_unregister(hook_sysfs_kset);

	return ret;
}

void hook_sysfs_exit(void)
{
	sysfs_remove_group(&hook_sysfs_kset->kobj, &hook_attrs_group);
	kset_unregister(hook_sysfs_kset);
}

static int cpu_online_func(unsigned int cpu)
{
	return 0;
}

static int cpu_offline_func(unsigned int cpu)
{
	hook_cpu_mask = cpu_possible_mask;
	return 0;
}

static __init int security_moni_init(void)
{
	int ret;

	if (hook_info_flag || hookinfo_nr()) {
		ret = -EBUSY;
		goto err_out;
	}

	if (!try_module_get(THIS_MODULE)) {
		ret =  -EFAULT;
		goto err_out;
	}

	mutex_init(&hook_lock);

	ret = list_module_init();
	if (ret)
		goto list_err;

	ret = hook_sysfs_init();
	if (ret)
		goto sysfs_err;

	ret = mod_sysctl_add();
	if (ret)
		goto sysctl_err;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "security/module:online",
				cpu_online_func, cpu_offline_func);
	if (ret < 0)
		goto cpuhp_err;

	cpu_online_enum = ret;

	hook_info_flag = 1;

	return 0;

cpuhp_err:
	mod_sysctl_del();
sysctl_err:
	hook_sysfs_exit();
sysfs_err:
	list_module_exit();
list_err:
	module_put(THIS_MODULE);
err_out:
	return ret;
}

static __exit void security_moni_exit(void)
{
	list_module_exit();
	hook_sysfs_exit();
	mod_sysctl_del();
	cpuhp_remove_state(cpu_online_enum);
}

module_init(security_moni_init);
module_exit(security_moni_exit);

MODULE_AUTHOR("zhipingdu/zgpeng/huntazhang");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");

