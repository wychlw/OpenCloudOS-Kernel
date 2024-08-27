// SPDX-License-Identifier: BSD-3-Clause
/* Copyright(c) 2019-2023 Broadcom
 * All rights reserved.
 */

#include <linux/types.h>
#include "tfc.h"
#include "bnxt_compat.h"
#include "bnxt.h"
#include "bnxt_hwrm.h"
#include "tfc.h"
#include "tfc_msg.h"

int tfc_global_id_alloc(struct tfc *tfcp, u16 fid, enum tfc_domain_id domain_id,
			u16 req_cnt, const struct tfc_global_id_req *req,
			struct tfc_global_id *rsp, u16 *rsp_cnt,
			bool *first)
{
	struct bnxt *bp = tfcp->bp;
	int rc;
	u16 sid;

	if (!req) {
		netdev_dbg(bp->dev, "%s: global_id req is NULL\n", __func__);
		return -EINVAL;
	}

	if (!rsp) {
		netdev_dbg(bp->dev, "%s: global_id rsp is NULL\n", __func__);
		return -EINVAL;
	}

	if (!BNXT_PF(bp) && !BNXT_VF_IS_TRUSTED(bp)) {
		netdev_dbg(bp->dev, "%s: bp not PF or trusted VF\n", __func__);
		return -EINVAL;
	}

	rc = tfo_sid_get(tfcp->tfo, &sid);
	if (rc) {
		netdev_dbg(bp->dev, "%s: Failed to retrieve SID, rc:%d\n",
			   __func__, rc);
		return rc;
	}

	rc = tfc_msg_global_id_alloc(tfcp, fid, sid, domain_id, req_cnt,
				     req, rsp, rsp_cnt, first);
	return rc;
}
