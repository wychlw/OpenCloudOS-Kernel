/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2023 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include "bnxt_compat.h"
#include "bnxt.h"
#include "bnxt_coredump.h"
#include "bnxt_log.h"
#include "bnxt_log_data.h"

static void bnxt_log_drv_version(struct bnxt *bp)
{
	bnxt_log_live(bp, BNXT_LOGGER_L2, "\n");

	bnxt_log_live(bp, BNXT_LOGGER_L2, "Interface: %s  driver version: %s\n",
		      bp->dev->name, DRV_MODULE_VERSION);
}

static void bnxt_log_tx_sw_state(struct bnxt_napi *bnapi)
{
	struct bnxt_tx_ring_info *txr;
	struct bnxt *bp = bnapi->bp;
	int i = bnapi->index, j;

	bnxt_for_each_napi_tx(j, bnapi, txr)
		bnxt_log_live(bp, BNXT_LOGGER_L2, "[%d.%d]: tx{fw_ring: %d prod: %x cons: %x}\n",
			      i, j, txr->tx_ring_struct.fw_ring_id, txr->tx_prod,
			      txr->tx_cons);
}

static void bnxt_log_rx_sw_state(struct bnxt_napi *bnapi)
{
	struct bnxt_rx_ring_info *rxr = bnapi->rx_ring;
	struct bnxt *bp = bnapi->bp;
	int i = bnapi->index;

	if (!rxr)
		return;

	bnxt_log_live(bp, BNXT_LOGGER_L2, "[%d]: rx{fw_ring: %d prod: %x} rx_agg{fw_ring: %d agg_prod: %x sw_agg_prod: %x}\n",
		      i, rxr->rx_ring_struct.fw_ring_id, rxr->rx_prod,
		      rxr->rx_agg_ring_struct.fw_ring_id, rxr->rx_agg_prod,
		      rxr->rx_sw_agg_prod);
}

static void bnxt_log_cp_sw_state(struct bnxt_napi *bnapi)
{
	struct bnxt_cp_ring_info *cpr = &bnapi->cp_ring, *cpr2;
	struct bnxt *bp = bnapi->bp;
	int i = bnapi->index, j;

	bnxt_log_live(bp, BNXT_LOGGER_L2, "[%d]: cp{fw_ring: %d raw_cons: %x}\n",
		      i, cpr->cp_ring_struct.fw_ring_id, cpr->cp_raw_cons);
	for (j = 0; j < cpr->cp_ring_count; j++) {
		cpr2 = &cpr->cp_ring_arr[j];
		if (!cpr2->bnapi)
			continue;
		bnxt_log_live(bp, BNXT_LOGGER_L2, "[%d.%d]: cp{fw_ring: %d raw_cons: %x}\n",
			      i, j, cpr2->cp_ring_struct.fw_ring_id, cpr2->cp_raw_cons);
	}
}

void bnxt_log_ring_states(struct bnxt *bp)
{
	struct bnxt_napi *bnapi;
	int i;

	bnxt_log_drv_version(bp);

	if (!netif_running(bp->dev))
		return;

	for (i = 0; i < bp->cp_nr_rings; i++) {
		bnapi = bp->bnapi[i];
			bnxt_log_tx_sw_state(bnapi);
			bnxt_log_rx_sw_state(bnapi);
			bnxt_log_cp_sw_state(bnapi);
	}
}
