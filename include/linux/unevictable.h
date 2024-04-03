/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _TEXT_UNEVICTABLE_H
#define _TEXT_UNEVICTABLE_H

#ifdef CONFIG_TEXT_UNEVICTABLE
DECLARE_STATIC_KEY_FALSE(unevictable_enabled_key);

static inline bool unevictable_enabled(void)
{
	return static_branch_unlikely(&unevictable_enabled_key);
}
#else
static inline bool unevictable_enabled(void)
{
	return false;
}
#endif
#endif
