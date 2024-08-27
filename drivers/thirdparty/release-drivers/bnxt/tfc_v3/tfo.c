// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2023 Broadcom
 * All rights reserved.
 */

#include <linux/types.h>
#include "bnxt_compat.h"
#include "tfo.h"
#include "cfa_types.h"
#include "cfa_tim.h"
#include "bnxt.h"

/* Table scope stored configuration */
struct tfc_tsid_db {
	bool ts_valid;			/* Table scope is valid */
	bool ts_is_shared;		/* Table scope is shared */
	bool ts_is_bs_owner;		/* Backing store alloced by this instance (PF) */
	uint16_t ts_max_pools;		/* maximum pools per CPM instance */
	enum cfa_app_type ts_app;	/* application type TF/AFM */
	struct tfc_ts_mem_cfg ts_mem[CFA_REGION_TYPE_MAX][CFA_DIR_MAX]; /* backing store mem cfg */
	struct tfc_ts_pool_info ts_pool[CFA_DIR_MAX];			/* pool info config */
};

/* TFC Object Signature
 * This signature identifies the tfc object database and
 * is used for pointer validation
 */
#define TFC_OBJ_SIGNATURE 0xABACABAF

/* TFC Object
 * This data structure contains all data stored per bnxt port
 * Access is restricted through set/get APIs.
 *
 * If a module (e.g. tbl_scope needs to store data, it should
 * be added here and accessor functions created.
 */
struct tfc_object {
	u32 signature;					/* TF object signature */
	u16 sid;					/* Session ID */
	bool is_pf;					/* port is a PF */
	struct cfa_bld_mpcinfo mpc_info;		/* MPC ops handle */
	struct tfc_tsid_db tsid_db[TFC_TBL_SCOPE_MAX];	/* tsid database */
	/* TIM instance pointer (PF) - this is where the 4 instances
	 *  of the TPM (rx/tx_lkup, rx/tx_act) will be stored per shared
	 *  table scope.  Only valid on a PF.
	 */
	void *ts_tim;
};

void tfo_open(void **tfo, bool is_pf)
{
	struct tfc_object *tfco = NULL;
	u32 tim_db_size;
	int rc;

	tfco = kzalloc(sizeof(*tfco), GFP_KERNEL);
	if (!tfco)
		return;

	tfco->signature = TFC_OBJ_SIGNATURE;
	tfco->is_pf = is_pf;
	tfco->sid = INVALID_SID;
	tfco->ts_tim = NULL;

	/* Bind to the MPC builder */
	rc = cfa_bld_mpc_bind(CFA_P70, &tfco->mpc_info);
	if (rc) {
		netdev_dbg(NULL, "%s: MPC bind failed\n", __func__);
		goto cleanup;
	}
	if (is_pf) {
		/* Allocate TIM */
		rc = cfa_tim_query(TFC_TBL_SCOPE_MAX, CFA_REGION_TYPE_MAX,
				   &tim_db_size);
		if (rc)
			goto cleanup;

		tfco->ts_tim = kzalloc(tim_db_size, GFP_KERNEL);
		if (!tfco->ts_tim)
			goto cleanup;

		rc = cfa_tim_open(tfco->ts_tim,
				  tim_db_size,
				  TFC_TBL_SCOPE_MAX,
				  CFA_REGION_TYPE_MAX);
		if (rc) {
			kfree(tfco->ts_tim);
			tfco->ts_tim = NULL;
			goto cleanup;
		}
	}

	*tfo = tfco;
	return;

cleanup:
	kfree(tfco);
	*tfo = NULL;
}

void tfo_close(void **tfo)
{
	struct tfc_object *tfco = (struct tfc_object *)(*tfo);
	void *tim = NULL, *tpm = NULL;
	enum cfa_region_type region;
	int dir, rc, tsid;

	if (*tfo && tfco->signature == TFC_OBJ_SIGNATURE) {
		/*  If TIM is setup free it and any TPMs */
		if (tfo_tim_get(*tfo, &tim))
			goto done;

		if (!tim)
			goto done;

		for (tsid = 0; tsid < TFC_TBL_SCOPE_MAX; tsid++) {
			for (region = 0; region < CFA_REGION_TYPE_MAX; region++) {
				for (dir = 0; dir < CFA_DIR_MAX; dir++) {
					tpm = NULL;
					rc = cfa_tim_tpm_inst_get(tim, tsid, region, dir, &tpm);
					if (!rc && tpm) {
						kfree(tpm);
						cfa_tim_tpm_inst_set(tim, tsid, region, dir, NULL);
					}
				}
			}
		}
		kfree(tfco->ts_tim);
		tfco->ts_tim = NULL;
done:
		kfree(*tfo);
		*tfo = NULL;
	}
}

int tfo_mpcinfo_get(void *tfo, struct cfa_bld_mpcinfo **mpc_info)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;

	if (!tfo)
		return -EINVAL;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	*mpc_info = &tfco->mpc_info;

	return 0;
}

int tfo_ts_validate(void *tfo, u8 ts_tsid, bool *ts_valid)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}
	tsid_db = &tfco->tsid_db[ts_tsid];

	if (ts_valid)
		*ts_valid = tsid_db->ts_valid;

	return 0;
}

int tfo_ts_set(void *tfo, u8 ts_tsid, bool ts_is_shared,
	       enum cfa_app_type ts_app, bool ts_valid, u16 ts_max_pools)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}

	tsid_db = &tfco->tsid_db[ts_tsid];

	tsid_db->ts_valid = ts_valid;
	tsid_db->ts_is_shared = ts_is_shared;
	tsid_db->ts_app = ts_app;
	tsid_db->ts_max_pools = ts_max_pools;

	return 0;
}

int tfo_ts_get(void *tfo, u8 ts_tsid, bool *ts_is_shared,
	       enum cfa_app_type *ts_app, bool *ts_valid,
	       u16 *ts_max_pools)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}

	tsid_db = &tfco->tsid_db[ts_tsid];

	if (ts_valid)
		*ts_valid = tsid_db->ts_valid;

	if (ts_is_shared)
		*ts_is_shared = tsid_db->ts_is_shared;

	if (ts_app)
		*ts_app = tsid_db->ts_app;

	if (ts_max_pools)
		*ts_max_pools = tsid_db->ts_max_pools;

	return 0;
}

/* Set the table scope memory configuration for this direction */
int tfo_ts_set_mem_cfg(void *tfo, uint8_t ts_tsid, enum cfa_dir dir,
		       enum cfa_region_type region, bool is_bs_owner,
		       struct tfc_ts_mem_cfg *mem_cfg)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (!mem_cfg) {
		netdev_dbg(NULL, "%s: Invalid mem_cfg pointer\n", __func__);
		return -EINVAL;
	}

	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}

	tsid_db = &tfco->tsid_db[ts_tsid];

	tsid_db->ts_mem[region][dir] = *mem_cfg;
	tsid_db->ts_is_bs_owner = is_bs_owner;

	return 0;
}

/* Get the table scope memory configuration for this direction */
int tfo_ts_get_mem_cfg(void *tfo, u8 ts_tsid, enum cfa_dir dir,
		       enum cfa_region_type region, bool *is_bs_owner,
		       struct tfc_ts_mem_cfg *mem_cfg)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (!mem_cfg) {
		netdev_dbg(NULL, "%s: Invalid mem_cfg pointer\n", __func__);
		return -EINVAL;
	}

	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}

	tsid_db = &tfco->tsid_db[ts_tsid];

	*mem_cfg = tsid_db->ts_mem[region][dir];
	if (is_bs_owner)
		*is_bs_owner = tsid_db->ts_is_bs_owner;

	return 0;
}

/* Get the Pool Manager instance */
int tfo_ts_get_cpm_inst(void *tfo, u8 ts_tsid, enum cfa_dir dir,
			struct tfc_cpm **cpm_lkup, struct tfc_cpm **cpm_act)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (!cpm_lkup) {
		netdev_dbg(NULL, "%s: Invalid cpm_lkup pointer\n", __func__);
		return -EINVAL;
	}

	if (!cpm_act) {
		netdev_dbg(NULL, "%s: Invalid cpm_act pointer\n", __func__);
		return -EINVAL;
	}
	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}

	tsid_db = &tfco->tsid_db[ts_tsid];

	*cpm_lkup = tsid_db->ts_pool[dir].lkup_cpm;
	*cpm_act = tsid_db->ts_pool[dir].act_cpm;

	return 0;
}

/* Set the Pool Manager instance */
int tfo_ts_set_cpm_inst(void *tfo, u8 ts_tsid, enum cfa_dir dir,
			struct tfc_cpm *cpm_lkup, struct tfc_cpm *cpm_act)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}
	tsid_db = &tfco->tsid_db[ts_tsid];

	tsid_db->ts_pool[dir].lkup_cpm = cpm_lkup;
	tsid_db->ts_pool[dir].act_cpm = cpm_act;

	return 0;
}

/* Set the table scope pool memory configuration for this direction */
int tfo_ts_set_pool_info(void *tfo, u8 ts_tsid, enum cfa_dir dir,
			 struct tfc_ts_pool_info *ts_pool)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (!ts_pool) {
		netdev_dbg(NULL, "%s: Invalid ts_pool pointer\n", __func__);
		return -EINVAL;
	}

	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}
	tsid_db = &tfco->tsid_db[ts_tsid];

	tsid_db->ts_pool[dir] = *ts_pool;

	return 0;
}

/* Get the table scope pool memory configuration for this direction */
int tfo_ts_get_pool_info(void *tfo, u8 ts_tsid, enum cfa_dir dir,
			 struct tfc_ts_pool_info *ts_pool)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;
	struct tfc_tsid_db *tsid_db;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (!ts_pool) {
		netdev_dbg(NULL, "%s: Invalid ts_pool pointer\n", __func__);
		return -EINVAL;
	}
	if (ts_tsid >= TFC_TBL_SCOPE_MAX) {
		netdev_dbg(NULL, "%s: Invalid tsid %d\n", __func__, ts_tsid);
		return -EINVAL;
	}
	tsid_db = &tfco->tsid_db[ts_tsid];

	*ts_pool = tsid_db->ts_pool[dir];

	return 0;
}

int tfo_sid_set(void *tfo, uint16_t sid)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (tfco->sid != INVALID_SID && sid != INVALID_SID &&
	    tfco->sid != sid) {
		netdev_dbg(NULL, "%s: Cannot set SID %u, current session is %u.\n",
			   __func__, sid, tfco->sid);
		return -EINVAL;
	}

	tfco->sid = sid;

	return 0;
}

int tfo_sid_get(void *tfo, uint16_t *sid)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (!sid) {
		netdev_dbg(NULL, "%s: Invalid sid pointer\n", __func__);
		return -EINVAL;
	}

	if (tfco->sid == INVALID_SID) {
		/* Session has not been created */
		return -ENODATA;
	}

	*sid = tfco->sid;

	return 0;
}

int tfo_tim_set(void *tfo, void *tim)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (!tim) {
		netdev_dbg(NULL, "%s: Invalid tim pointer\n", __func__);
		return -EINVAL;
	}

	if (tfco->ts_tim && tfco->ts_tim != tim) {
		netdev_dbg(NULL, "%s: Cannot set TS TIM, TIM is already set\n", __func__);
		return -EINVAL;
	}

	tfco->ts_tim = tim;

	return 0;
}

int tfo_tim_get(void *tfo, void **tim)
{
	struct tfc_object *tfco = (struct tfc_object *)tfo;

	if (tfco->signature != TFC_OBJ_SIGNATURE) {
		netdev_dbg(NULL, "%s: Invalid tfo object\n", __func__);
		return -EINVAL;
	}

	if (!tim) {
		netdev_dbg(NULL, "%s: Invalid tim pointer to pointer\n", __func__);
		return -EINVAL;
	}

	if (!tfco->ts_tim)
		/* ts tim could be null, no need to log error message */
		return -ENODATA;

	*tim = tfco->ts_tim;

	return 0;
}
