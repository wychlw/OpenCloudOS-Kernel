/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_LOG_DATA_H
#define BNXT_LOG_DATA_H

#define BNXT_L2_MAX_LOG_BUFFERS		1024
#define BNXT_L2_MAX_LIVE_LOG_SIZE	(4 << 20)

void bnxt_log_ring_states(struct bnxt *bp);
#endif
