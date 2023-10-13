# SPDX-License-Identifier: GPL-2.0


ifneq ($(KERNELRELEASE),)
#inside kernel tree
obj-$(CONFIG_RUE)	:= rue.o
rue-y	:= rue_main.o syms.o
rue-$(CONFIG_BT_SCHED)	+= cpu_qos.o
rue-$(CONFIG_CGROUP_NET_CLASSID)	+= net_qos.o rx_cgroup.o tx_cgroup.o
rue-$(CONFIG_MEMCG)	+= mem_qos.o
rue-$(CONFIG_BLK_CGROUP)	+= io_qos.o

ifneq ($(M),)
ldflags-y += -T $(M)/syms.lds
else
ldflags-y += -T $(srctree)/$(src)/syms.lds
endif

else

KERNEL_DIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KERNEL_DIR) M=$$PWD

clean:
	rm -rf *.o *.o.p *~ core .depend .*.cmd *.ko *.mod.c \
		.tmp_versions Module.symvers modules.order \
		*.a *.mod *.builtin

endif
