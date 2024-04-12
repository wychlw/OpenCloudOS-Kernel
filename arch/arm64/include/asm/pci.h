/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_PCI_H
#define __ASM_PCI_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>

#include <asm/io.h>

#define PCIBIOS_MIN_IO		0x1000

/*
 * Set to 1 if the kernel should re-assign all PCI bus numbers
 */
#define pcibios_assign_all_busses() \
	(pci_has_flag(PCI_REASSIGN_ALL_BUS))

#ifdef CONFIG_ALTRA_ERRATUM_82288
extern bool __read_mostly have_altra_erratum_82288;
#endif

#define arch_can_pci_mmap_wc() 1

/* Generic PCI */
#include <asm-generic/pci.h>

#endif  /* __ASM_PCI_H */
