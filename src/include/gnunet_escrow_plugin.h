/*
     This file is part of GNUnet
     Copyright (C) 2020 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Johannes Späth
 *
 * @file
 * Plugin API for escrow methods
 *
 * @defgroup escrow-plugin  escrow plugin API for escrow methods
 * @{
 */
#ifndef GNUNET_ESCROW_PLUGIN_H
#define GNUNET_ESCROW_PLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_escrow_lib.h"
#include "gnunet_identity_service.h"
#include "../escrow/escrow.h"
#include "gnunet_scheduler_lib.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Function called to start the escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param userSecret the user secret (e.g. for derivation of escrow identities)
 *                   for GNS escrow, this has to be UNIQUE in the whole network!
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return a wrapper for the plugin operation
 */
typedef struct ESCROW_PluginOperationWrapper *(*GNUNET_ESCROW_StartKeyEscrowFunction) (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_IDENTITY_Ego *ego,
  const char *userSecret,
  GNUNET_SCHEDULER_TaskCallback cb,
  uint32_t op_id);

/**
 * Function called to verify the escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return a wrapper for the plugin operation
 */
typedef struct ESCROW_PluginOperationWrapper *(*GNUNET_ESCROW_VerifyKeyEscrowFunction) (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_IDENTITY_Ego *ego,
  struct GNUNET_ESCROW_Anchor *escrowAnchor,
  GNUNET_SCHEDULER_TaskCallback cb,
  uint32_t op_id);

/**
 * Function called to restore a key from an escrow
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return a wrapper for the plugin operation
 */
typedef struct ESCROW_PluginOperationWrapper *(*GNUNET_ESCROW_RestoreKeyFunction) (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_ESCROW_Anchor *escrowAnchor,
  const char *egoName,
  GNUNET_SCHEDULER_TaskCallback cb,
  uint32_t op_id);


/**
 * Function called to get the status of an escrow, i.e.
 *   -> when the last successful escrow was
 *   -> when the next recommended escrow is
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego of which the status has to be obtained
 * 
 * @return the status of the escrow packed into a GNUNET_ESCROW_Status struct
 */
typedef struct GNUNET_ESCROW_Status *(*GNUNET_ESCROW_GetEscrowStatusFunction) (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_IDENTITY_Ego *ego);


/**
 * Function called to deserialize an escrow anchor string into a
 * GNUNET_ESCROW_Anchor struct
 * 
 * @param h the handle for the escrow component
 * @param anchorString the encoded escrow anchor string
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct
 */
typedef struct GNUNET_ESCROW_Anchor *(*GNUNET_ESCROW_AnchorStringToDataFunction) (
  struct GNUNET_ESCROW_Handle *h,
  char *anchorString);


/**
 * Function called to serialize an escrow anchor struct into a string
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor struct
 * 
 * @return the encoded escrow anchor string
 */
typedef char *(*GNUNET_ESCROW_AnchorDataToStringFunction) (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_ESCROW_Anchor *escrowAnchor);


/**
 * Function called to cancel a plugin operation
 * 
 * @param plugin_op_wrap plugin operation wrapper containing the plugin operation
 */
typedef void (*GNUNET_ESCROW_CancelPluginOperationFunction) (
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap);


/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_ESCROW_KeyPluginFunctions
{
  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * Start key escrow
   */
  GNUNET_ESCROW_StartKeyEscrowFunction start_key_escrow;

  /**
   * Verify key escrow
   */
  GNUNET_ESCROW_VerifyKeyEscrowFunction verify_key_escrow;

  /**
   * Restore key escrow
   */
  GNUNET_ESCROW_RestoreKeyFunction restore_key;

  /**
   * Get the status of an escrow
   */
  GNUNET_ESCROW_GetEscrowStatusFunction get_status;

  /**
   * Deserialize anchor string to data
   */
  GNUNET_ESCROW_AnchorStringToDataFunction anchor_string_to_data;

  /**
   * Serialize anchor data to string
   */
  GNUNET_ESCROW_AnchorDataToStringFunction anchor_data_to_string;

  /**
   * Cancel plugin operation
   */
  GNUNET_ESCROW_CancelPluginOperationFunction cancel_plugin_operation;
};


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */ /* end of group */
