# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# Makefile for DIM Linux Security Modules.
#
ifeq ($(CONFIG_DIM), y)

# DIM_CORE Module
obj-$(CONFIG_DIM_CORE) += dim_core.o

dim_core-y += core/dim_core_main.o
dim_core-y += core/dim_core_fs.o
dim_core-y += core/dim_core_mem_pool.o
dim_core-y += core/dim_core_measure.o
dim_core-y += core/dim_core_symbol.o
dim_core-y += core/dim_core_sig.o

dim_core-y += core/tasks/dim_core_measure_kernel.o
dim_core-y += core/tasks/dim_core_measure_module.o
dim_core-y += core/tasks/dim_core_measure_process/dim_vm_hash.o
dim_core-y += core/tasks/dim_core_measure_process/dim_core_measure_process.o
dim_core-y += core/tasks/dim_core_measure_process/dim_core_measure_process_vma.o

dim_core-y += core/policy/dim_core_policy.o
dim_core-y += core/policy/dim_core_policy_complex.o

dim_core-y += core/static_baseline/dim_core_static_baseline.o
dim_core-y += core/static_baseline/dim_core_static_baseline_complex.o

dim_core-y += common/dim_entry.o
dim_core-y += common/dim_utils.o
dim_core-y += common/dim_baseline.o
dim_core-y += common/dim_hash.o
dim_core-y += common/dim_measure_log.o
dim_core-y += common/dim_tpm.o
dim_core-y += common/dim_symbol.o
dim_core-y += common/dim_safe_func.o
dim_core-y += measure/dim_measure.o
dim_core-y += measure/dim_measure_baseline.o
dim_core-y += measure/dim_measure_task.o
dim_core-y += measure/dim_measure_utils.o
dim_core-y += measure/dim_measure_status.o

# DIM_MONITOR Module
obj-$(CONFIG_DIM_MONITOR) += dim_monitor.o

dim_monitor-y += monitor/dim_monitor_main.o
dim_monitor-y += monitor/dim_monitor_fs.o
dim_monitor-y += monitor/dim_monitor_measure.o
dim_monitor-y += monitor/dim_monitor_symbol.o

dim_monitor-y += monitor/measure_task/dim_monitor_measure_data.o
dim_monitor-y += monitor/measure_task/dim_monitor_measure_text.o

dim_monitor-y += common/dim_entry.o
dim_monitor-y += common/dim_hash.o
dim_monitor-y += common/dim_utils.o
dim_monitor-y += common/dim_measure_log.o
dim_monitor-y += common/dim_baseline.o
dim_monitor-y += common/dim_tpm.o
dim_monitor-y += common/dim_symbol.o
dim_monitor-y += common/dim_safe_func.o
dim_monitor-y += measure/dim_measure.o
dim_monitor-y += measure/dim_measure_baseline.o
dim_monitor-y += measure/dim_measure_task.o
dim_monitor-y += measure/dim_measure_utils.o
dim_monitor-y += measure/dim_measure_status.o

subdir-ccflags-y := -I$(srctree)/$(src)/core
subdir-ccflags-y += -I$(srctree)/$(src)/core/static_baseline
subdir-ccflags-y += -I$(srctree)/$(src)/core/tasks
subdir-ccflags-y += -I$(srctree)/$(src)/core/tasks/dim_core_measure_process
subdir-ccflags-y += -I$(srctree)/$(src)/core/policy
subdir-ccflags-y += -I$(srctree)/$(src)/monitor
subdir-ccflags-y += -I$(srctree)/$(src)/monitor/measure_task
subdir-ccflags-y += -I$(srctree)/$(src)/common
subdir-ccflags-y += -I$(srctree)/$(src)/measure

endif
