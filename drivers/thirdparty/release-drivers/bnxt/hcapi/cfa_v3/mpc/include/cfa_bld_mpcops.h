/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2023 Broadcom
 * All rights reserved.
 */

#ifndef _CFA_BLD_MPCOPS_H_
#define _CFA_BLD_MPCOPS_H_

#include "cfa_types.h"

/**
 * CFA HW data object definition
 */
struct cfa_mpc_data_obj {
	/** [in] MPC field identifier */
	u16 field_id;
	/** [in] Value of the HW field */
	u64 val;
};

struct cfa_bld_mpcops;

/**
 *  @addtogroup CFA_BLD CFA Builder Library
 *  \ingroup CFA_V3
 *  @{
 */

/**
 * CFA MPC ops interface
 */
struct cfa_bld_mpcinfo {
	/** [out] CFA MPC Builder operations function pointer table */
	const struct cfa_bld_mpcops *mpcops;
};

/**
 *  @name CFA_BLD_MPC CFA Builder Host MPC OPS API
 *  CFA builder host specific API used by host CFA application to bind
 *  to different CFA devices and access device by using MPC OPS.
 */

/**@{*/
/** CFA builder MPC bind API
 *
 * This API retrieves the CFA global MPC configuration.
 *
 * @param[in] hw_ver
 *   hardware version of the CFA
 *
 * @param[out] mpc_info
 *   CFA MPC interface
 *
 * @return
 *   0 for SUCCESS, negative value for FAILURE
 */
int cfa_bld_mpc_bind(enum cfa_ver hw_ver, struct cfa_bld_mpcinfo *mpc_info);

/** CFA device specific function hooks for CFA MPC command composition
 *  and response parsing
 *
 * The following device hooks can be defined; unless noted otherwise, they are
 * optional and can be filled with a null pointer. The pupose of these hooks
 * to support CFA device operations for different device variants.
 */
struct cfa_bld_mpcops {
	/** Build MPC Cache read command
	 *
	 * This API composes the MPC cache read command given the list
	 * of read parameters specified as an array of cfa_mpc_data_obj objects.
	 *
	 * @param[in] cmd
	 *   MPC command buffer to compose the cache read command into.
	 *
	 * @param[in,out] cmd_buff_len
	 *   Pointer to command buffer length variable. The caller sets this
	 *   to the size of the 'cmd' buffer in byes. The api updates this to
	 *   the actual size of the composed command. If the buffer length
	 *   passed is not large enough to hold the composed command, an error
	 *   is returned by the api.
	 *
	 * @param[in] fields
	 *   Array of CFA data objects indexed by CFA_BLD_MPC_READ_CMD_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_READ_CMD_MAX_FLD. If the caller intends to set a
	 *   specific field in the MPC command, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself (See example
	 *   below). Otherwise set the field_id to INVALID_U16. If the caller
	 *   sets the field_id for a field that is not valid for the device
	 *   an error is returned.
	 *
	 * To set the table type to EM:
	 * fields[CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD].field_id =
	 *     CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD;
	 * fields[CFA_BLD_MPC_READ_CMD_TABLE_TYPE_FLD].val =
	 *     CFA_HW_TABLE_LOOKUP;
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_build_cache_read)(u8 *cmd,
					    u32 *cmd_buff_len,
					    struct cfa_mpc_data_obj *fields);

	/** Build MPC Cache Write command
	 *
	 * This API composes the MPC cache write command given the list
	 * of write parameters specified as an array of cfa_mpc_data_obj
	 * objects.
	 *
	 * @param[in] cmd
	 *   MPC command buffer to compose the cache write command into.
	 *
	 * @param[in,out] cmd_buff_len
	 *   Pointer to command buffer length variable. The caller sets this
	 *   to the size of the 'cmd' buffer in byes. The api updates this to
	 *   the actual size of the composed command. If the buffer length
	 *   passed is not large enough to hold the composed command, an error
	 *   is returned by the api.
	 *
	 * @param[in] data
	 *   Pointer to the data to be written. Note that this data is just
	 *   copied at the right offset into the command buffer. The actual MPC
	 *   write happens when the command is issued over the MPC interface.
	 *
	 * @param[in] fields
	 *   Array of CFA data objects indexed by CFA_BLD_MPC_WRITE_CMD_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_WRITE_CMD_MAX_FLD. If the caller intends to set a
	 *   specific field in the MPC command, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise
	 *   set the field_id to INVALID_U16. If the caller sets the field_id for
	 *   a field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_build_cache_write)(u8 *cmd,
					     u32 *cmd_buff_len,
					     const u8 *data,
					     struct cfa_mpc_data_obj *fields);

	/** Build MPC Cache Invalidate (Evict) command
	 *
	 * This API composes the MPC cache evict command given the list
	 * of evict parameters specified as an array of cfa_mpc_data_obj
	 * objects.
	 *
	 * @param[in] cmd
	 *   MPC command buffer to compose the cache evict command into.
	 *
	 * @param[in,out] cmd_buff_len
	 *   Pointer to command buffer length variable. The caller sets this
	 *   to the size of the 'cmd' buffer in byes. The api updates this to
	 *   the actual size of the composed command. If the buffer length
	 *   passed is not large enough to hold the composed command, an error
	 *   is returned by the api.
	 *
	 * @param[in] fields
	 *   Array of cfa_mpc_data_obj indexed by
	 *   CFA_BLD_MPC_INVALIDATE_CMD_XXX_FLD enum values. The size of this
	 *   array shall be CFA_BLD_MPC_INVALIDATE_CMD_MAX_FLD. If the caller
	 *   intends to set a specific field in the MPC command, the caller
	 *   should set the field_id in cfa_mpc_data_obj to the array index
	 *   itself. Otherwise set the field_id to INVALID_U16. If the caller
	 *   sets the field_id for a field that is not valid for the device an
	 *   error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_build_cache_evict)(u8 *cmd,
					     u32 *cmd_buff_len,
					     struct cfa_mpc_data_obj *fields);

	/** Build MPC Cache read and clear command
	 *
	 * This API composes the MPC cache read-n-clear command given the list
	 * of read parameters specified as an array of cfa_mpc_data_obj objects.
	 *
	 * @param[in] cmd
	 *   MPC command buffer to compose the cache read-n-clear command into.
	 *
	 * @param[in,out] cmd_buff_len
	 *   Pointer to command buffer length variable. The caller sets this
	 *   to the size of the 'cmd' buffer in byes. The api updates this to
	 *   the actual size of the composed command. If the buffer length
	 *   passed is not large enough to hold the composed command, an error
	 *   is returned by the api.
	 *
	 * @param[in] fields
	 *   Array of cfa_mpc_data_obj indexed by
	 *   CFA_BLD_MPC_READ_CLR_CMD_XXX_FLD enum values. The size of this
	 *   array shall be CFA_BLD_MPC_READ_CLR_CMD_MAX_FLD. If the caller
	 *   intends to set a specific field in the MPC command, the caller
	 *   should set the field_id in cfa_mpc_data_obj to the array index
	 *   itself. Otherwise set the field_id to INVALID_U16. If the caller
	 *   sets the field_id for a field that is not valid for the device
	 *   an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_build_cache_read_clr)(u8 *cmd,
						u32 *cmd_buff_len,
						struct cfa_mpc_data_obj *fields);

	/** Build MPC EM search command
	 *
	 * This API composes the MPC EM search command given the list
	 * of EM search parameters specified as an array of cfa_mpc_data_obj
	 * objects
	 *
	 * @param[in] cmd
	 *   MPC command buffer to compose the EM search command into.
	 *
	 * @param[in,out] cmd_buff_len
	 *   Pointer to command buffer length variable. The caller sets this
	 *   to the size of the 'cmd' buffer in byes. The api updates this to
	 *   the actual size of the composed command. If the buffer length
	 *   passed is not large enough to hold the composed command, an error
	 *   is returned by the api.
	 *
	 * @param[in] em_entry
	 *   Pointer to the em_entry to be searched.
	 *
	 * @param[in] fields
	 *   Array of cfa_mpc_data_obj indexed by
	 *   CFA_BLD_MPC_EM_SEARCH_CMD_XXX_FLD enum values. The size of this
	 *   array shall be CFA_BLD_MPC_EM_SEARCH_CMD_MAX_FLD. If the caller
	 *   intends to set a specific field in the MPC command, the caller
	 *   should set the field_id in cfa_mpc_data_obj to the array index
	 *   itself. Otherwise set the field_id to INVALID_U16. If the caller
	 *   sets the field_id for a field that is not valid for the device an
	 *   error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_build_em_search)(u8 *cmd, u32 *cmd_buff_len,
					   u8 *em_entry,
					   struct cfa_mpc_data_obj *fields);

	/** Build MPC EM insert command
	 *
	 * This API composes the MPC EM insert command given the list
	 * of EM insert parameters specified as an array of cfa_mpc_data_obj objects
	 *
	 * @param[in] cmd
	 *   MPC command buffer to compose the EM insert command into.
	 *
	 * @param[in,out] cmd_buff_len
	 *   Pointer to command buffer length variable. The caller sets this
	 *   to the size of the 'cmd' buffer in bytes. The api updates this to
	 *   the actual size of the composed command. If the buffer length
	 *   passed is not large enough to hold the composed command, an error
	 *   is returned by the api.
	 *
	 * @param[in] em_entry
	 *   Pointer to the em_entry to be inserted.
	 *
	 * @param[in] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_EM_INSERT_CMD_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_EM_INSERT_CMD_MAX_FLD. If the caller intends to set a
	 *   specific field in the MPC command, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_build_em_insert)(u8 *cmd, u32 *cmd_buff_len,
					   const u8 *em_entry,
					   struct cfa_mpc_data_obj *fields);

	/** Build MPC EM delete command
	 *
	 * This API composes the MPC EM delete command given the list
	 * of EM delete parameters specified as an array of cfa_mpc_data_obj objects
	 *
	 * @param[in] cmd
	 *   MPC command buffer to compose the EM delete command into.
	 *
	 * @param[in,out] cmd_buff_len
	 *   Pointer to command buffer length variable. The caller sets this
	 *   to the size of the 'cmd' buffer in byes. The api updates this to
	 *   the actual size of the composed command. If the buffer length
	 *   passed is not large enough to hold the composed command, an error
	 *   is returned by the api.
	 *
	 * @param[in] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_EM_DELETE_CMD_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_EM_DELETE_CMD_MAX_FLD. If the caller intends to set a
	 *   specific field in the MPC command, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_build_em_delete)(u8 *cmd, u32 *cmd_buff_len,
					   struct cfa_mpc_data_obj *fields);

	/** Build MPC EM chain command
	 *
	 * This API composes the MPC EM chain command given the list
	 * of EM chain parameters specified as an array of cfa_mpc_data_obj objects
	 *
	 * @param[in] cmd
	 *   MPC command buffer to compose the EM chain command into.
	 *
	 * @param[in,out] cmd_buff_len
	 *   Pointer to command buffer length variable. The caller sets this
	 *   to the size of the 'cmd' buffer in byes. The api updates this to
	 *   the actual size of the composed command. If the buffer length
	 *   passed is not large enough to hold the composed command, an error
	 *   is returned by the api.
	 *
	 * @param[in] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_EM_CHAIN_CMD_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_EM_CHAIN_CMD_MAX_FLD. If the caller intends to set a
	 *   specific field in the MPC command, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_build_em_chain)(u8 *cmd, u32 *cmd_buff_len,
					  struct cfa_mpc_data_obj *fields);

	/** Parse MPC Cache read response
	 *
	 * This API parses the MPC cache read response message and returns
	 * the read parameters as an array of cfa_mpc_data_obj objects.
	 *
	 * @param[in] resp
	 *   MPC response buffer containing the cache read response.
	 *
	 * @param[in] resp_buff_len
	 *   Response buffer length in bytes
	 *
	 * @param[in] rd_data
	 *   Buffer to copy the MPC read data into
	 *
	 * @param[in] rd_data_len
	 *   Size of the rd_data buffer in bytes
	 *
	 * @param[out] fields
	 *   Array of CFA data objects indexed by CFA_BLD_MPC_READ_CMP_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_READ_CMP_MAX_FLD. If the caller intends to retrieve a
	 *   specific field in the MPC response, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_parse_cache_read)(u8 *resp,
					    u32 resp_buff_len,
					    u8 *rd_data,
					    u32 rd_data_len,
					    struct cfa_mpc_data_obj *fields);

	/** Parse MPC Cache Write response
	 *
	 * This API parses the MPC cache write response message and returns
	 * the write response fields as an array of cfa_mpc_data_obj objects.
	 *
	 * @param[in] resp
	 *   MPC response buffer containing the cache write response.
	 *
	 * @param[in] resp_buff_len
	 *   Response buffer length in bytes
	 *
	 * @param[out] fields
	 *   Array of CFA data objects indexed by CFA_BLD_MPC_WRITE_CMP_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_WRITE_CMP_MAX_FLD. If the caller intends to retrieve a
	 *   specific field in the MPC response, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_parse_cache_write)(u8 *resp,
					     u32 resp_buff_len,
					     struct cfa_mpc_data_obj *fields);

	/** Parse MPC Cache Invalidate (Evict) response
	 *
	 * This API parses the MPC cache evict response message and returns
	 * the evict response fields as an array of cfa_mpc_data_obj objects.
	 *
	 * @param[in] resp
	 *   MPC response buffer containing the cache evict response.
	 *
	 * @param[in] resp_buff_len
	 *   Response buffer length in bytes
	 *
	 * @param[out] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_INVALIDATE_CMP_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_INVALIDATE_CMP_MAX_FLD. If the caller intends to get a
	 *   specific field in the MPC response, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_parse_cache_evict)(u8 *resp,
					     u32 resp_buff_len,
					     struct cfa_mpc_data_obj *fields);

	/* clang-format off */
	/** Parse MPC Cache read and clear response
	 *
	 * This API parses the MPC cache read-n-clear response message and
	 * returns the read response fields as an array of cfa_mpc_data_obj objects.
	 *
	 * @param[in] resp
	 *   MPC response buffer containing the cache read-n-clear response.
	 *
	 * @param[in] resp_buff_len
	 *   Response buffer length in bytes
	 *
	 * @param[in] rd_data
	 *   Buffer to copy the MPC read data into
	 *
	 * @param[in] rd_data_len
	 *   Size of the rd_data buffer in bytes
	 *
	 * @param[out] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_READ_CLR_CMP_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_READ_CLR_CMP_MAX_FLD. If the caller intends to get a
	 *   specific field in the MPC response, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_parse_cache_read_clr)(u8 *resp,
						u32 resp_buff_len, u8 *rd_data, u32 rd_data_len,
						struct cfa_mpc_data_obj *fields);

	/* clang-format on */
	/** Parse MPC EM search response
	 *
	 * This API parses the MPC EM search response message and returns
	 * the EM search response fields as an array of cfa_mpc_data_obj objects
	 *
	 * @param[in] resp
	 *   MPC response buffer containing the EM search response.
	 *
	 * @param[in] resp_buff_len
	 *   Response buffer length in bytes
	 *
	 * @param[out] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_EM_SEARCH_CMP_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_EM_SEARCH_CMP_MAX_FLD. If the caller intends to get a
	 *   specific field in the MPC response, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_parse_em_search)(u8 *resp,
					   u32 resp_buff_len,
					   struct cfa_mpc_data_obj *fields);

	/** Parse MPC EM insert response
	 *
	 * This API parses the MPC EM insert response message and returns
	 * the EM insert response fields as an array of cfa_mpc_data_obj objects
	 *
	 * @param[in] resp
	 *   MPC response buffer containing the EM insert response.
	 *
	 * @param[in] resp_buff_len
	 *   Response buffer length in bytes
	 *
	 * @param[out] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_EM_INSERT_CMP_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_EM_INSERT_CMP_MAX_FLD. If the caller intends to get a
	 *   specific field in the MPC response, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_parse_em_insert)(u8 *resp,
					   u32 resp_buff_len,
					   struct cfa_mpc_data_obj *fields);

	/** Parse MPC EM delete response
	 *
	 * This API parses the MPC EM delete response message and returns
	 * the EM delete response fields as an array of cfa_mpc_data_obj objects
	 *
	 * @param[in] resp
	 *   MPC response buffer containing the EM delete response.
	 *
	 * @param[in] resp_buff_len
	 *   Response buffer length in bytes
	 *
	 * @param[out] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_EM_DELETE_CMP_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_EM_DELETE_CMP_MAX_FLD. If the caller intends to get a
	 *   specific field in the MPC response, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_parse_em_delete)(u8 *resp,
					   u32 resp_buff_len,
					   struct cfa_mpc_data_obj *fields);

	/** Parse MPC EM chain response
	 *
	 * This API parses the MPC EM chain response message and returns
	 * the EM chain response fields as an array of cfa_mpc_data_obj objects
	 *
	 * @param[in] resp
	 *   MPC response buffer containing the EM chain response.
	 *
	 * @param[in] resp_buff_len
	 *   Response buffer length in bytes
	 *
	 * @param[out] fields
	 *   Array of cfa_mpc_data_obj indexed by CFA_BLD_MPC_EM_CHAIN_CMP_XXX_FLD
	 *   enum values. The size of this array shall be
	 *   CFA_BLD_MPC_EM_CHAIN_CMP_MAX_FLD. If the caller intends to get a
	 *   specific field in the MPC response, the caller should set the
	 *   field_id in cfa_mpc_data_obj to the array index itself. Otherwise set
	 *   the field_id to INVALID_U16. If the caller sets the field_id for a
	 *   field that is not valid for the device an error is returned.
	 *
	 * @return
	 *   0 for SUCCESS, negative errno for FAILURE
	 *
	 */
	int (*cfa_bld_mpc_parse_em_chain)(u8 *resp, u32 resp_buff_len,
					  struct cfa_mpc_data_obj *fields);
};

/**@}*/

/**@}*/
#endif /* _CFA_BLD_DEVOPS_H_ */
