/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#ifndef LOONGARCH_EXTIOI_H
#define LOONGARCH_EXTIOI_H

#include <kvm/iodev.h>

#define EXTIOI_IRQS			256
#define EXTIOI_ROUTE_MAX_VCPUS		256
#define EXTIOI_IRQS_U8_NUMS		(EXTIOI_IRQS / 8)
#define EXTIOI_IRQS_U32_NUMS		(EXTIOI_IRQS_U8_NUMS / 4)
#define EXTIOI_IRQS_U64_NUMS		(EXTIOI_IRQS_U32_NUMS / 2)
/* map to ipnum per 32 irqs */
#define EXTIOI_IRQS_NODETYPE_COUNT	16

#define EXTIOI_BASE			0x1400
#define EXTIOI_SIZE			0x900

#define LS3A_INTC_IP			8

struct loongarch_extioi {
	spinlock_t lock;
	struct kvm *kvm;
	struct kvm_io_device device;
	/* hardware state */
	union nodetype {
		u64 reg_u64[EXTIOI_IRQS_NODETYPE_COUNT / 4];
		u32 reg_u32[EXTIOI_IRQS_NODETYPE_COUNT / 2];
		uint16_t reg_u16[EXTIOI_IRQS_NODETYPE_COUNT];
		u8 reg_u8[EXTIOI_IRQS_NODETYPE_COUNT * 2];
	} nodetype;

	/* one bit shows the state of one irq */
	union bounce {
		u64 reg_u64[EXTIOI_IRQS_U64_NUMS];
		u32 reg_u32[EXTIOI_IRQS_U32_NUMS];
		u8 reg_u8[EXTIOI_IRQS_U8_NUMS];
	} bounce;

	union isr {
		u64 reg_u64[EXTIOI_IRQS_U64_NUMS];
		u32 reg_u32[EXTIOI_IRQS_U32_NUMS];
		u8 reg_u8[EXTIOI_IRQS_U8_NUMS];
	} isr;
	union coreisr {
		u64 reg_u64[EXTIOI_ROUTE_MAX_VCPUS][EXTIOI_IRQS_U64_NUMS];
		u32 reg_u32[EXTIOI_ROUTE_MAX_VCPUS][EXTIOI_IRQS_U32_NUMS];
		u8 reg_u8[EXTIOI_ROUTE_MAX_VCPUS][EXTIOI_IRQS_U8_NUMS];
	} coreisr;
	union enable {
		u64 reg_u64[EXTIOI_IRQS_U64_NUMS];
		u32 reg_u32[EXTIOI_IRQS_U32_NUMS];
		u8 reg_u8[EXTIOI_IRQS_U8_NUMS];
	} enable;

	/* use one byte to config ipmap for 32 irqs at once */
	union ipmap {
		u64 reg_u64;
		u32 reg_u32[EXTIOI_IRQS_U32_NUMS / 4];
		u8 reg_u8[EXTIOI_IRQS_U8_NUMS / 4];
	} ipmap;
	/* use one byte to config coremap for one irq */
	union coremap {
		u64 reg_u64[EXTIOI_IRQS / 8];
		u32 reg_u32[EXTIOI_IRQS / 4];
		u8 reg_u8[EXTIOI_IRQS];
	} coremap;

	DECLARE_BITMAP(sw_coreisr[EXTIOI_ROUTE_MAX_VCPUS][LS3A_INTC_IP], EXTIOI_IRQS);
	uint8_t  sw_coremap[EXTIOI_IRQS];
};

void extioi_set_irq(struct loongarch_extioi *s, int irq, int level);
int kvm_loongarch_register_extioi_device(void);
#endif /* LOONGARCH_EXTIOI_H */
