// SPDX-License-Identifier: GPL-2.0+
/*
 * Tencent RUE
 *
 * Copyright (c) 2023 Tencent Corporation.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>

static int rue_mod_init(void)
{
	pr_info("RUE mod init\n");
	return 0;
}

static void rue_mod_exit(void)
{
	pr_info("RUE mod exit\n");
}

module_init(rue_mod_init);
module_exit(rue_mod_exit);
MODULE_AUTHOR("Tencent Corporation");
MODULE_LICENSE("GPL v2");
