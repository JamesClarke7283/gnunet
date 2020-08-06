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
 * @file escrow/plugin_escrow_anastasis.c
 * @brief escrow-plugin-anastasis escrow plugin for escrow of the key using Anastasis
 *
 * @author Johannes Späth
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_escrow_plugin.h"
#include "escrow_plugin_helper.h"
#include <inttypes.h>


/**
 * Identity handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Handle for the plugin instance
 */
struct ESCROW_PluginHandle ph;


/**
 * Start the Anastasis escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return plugin operation wrapper
 */
struct ESCROW_PluginOperationWrapper *
start_anastasis_key_escrow (struct GNUNET_ESCROW_Handle *h,
                            const struct GNUNET_IDENTITY_Ego *ego,
                            GNUNET_SCHEDULER_TaskCallback cb,
                            uint32_t op_id)
{
  struct ESCROW_Plugin_AnchorContinuationWrapper *w;

  w = GNUNET_new (struct ESCROW_Plugin_AnchorContinuationWrapper);
  w->h = h;
  w->op_id = op_id;

  // TODO: implement
  w->escrowAnchor = NULL;
  GNUNET_SCHEDULER_add_now (cb, w);
  return NULL;
}


/**
 * Verify the Anastasis escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return plugin operation wrapper
 */
struct ESCROW_PluginOperationWrapper *
verify_anastasis_key_escrow (struct GNUNET_ESCROW_Handle *h,
                             const struct GNUNET_IDENTITY_Ego *ego,
                             struct GNUNET_ESCROW_Anchor *escrowAnchor,
                             GNUNET_SCHEDULER_TaskCallback cb,
                             uint32_t op_id)
{
  struct ESCROW_Plugin_VerifyContinuationWrapper *w;

  w = GNUNET_new (struct ESCROW_Plugin_VerifyContinuationWrapper);
  w->h = h;
  w->op_id = op_id;

  // TODO: implement
  w->verificationResult = GNUNET_ESCROW_INVALID;
  GNUNET_SCHEDULER_add_now (cb, w);
  return NULL;
}


/**
 * Restore the key from Anastasis escrow
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return plugin operation wrapper
 */
struct ESCROW_PluginOperationWrapper *
restore_anastasis_key_escrow (struct GNUNET_ESCROW_Handle *h,
                              struct GNUNET_ESCROW_Anchor *escrowAnchor,
                              char *egoName,
                              GNUNET_SCHEDULER_TaskCallback cb,
                              uint32_t op_id)
{
  struct ESCROW_Plugin_EgoContinuationWrapper *w;

  w = GNUNET_new (struct ESCROW_Plugin_EgoContinuationWrapper);
  w->h = h;
  w->op_id = op_id;

  // TODO: implement
  w->ego = NULL;
  GNUNET_SCHEDULER_add_now (cb, w);
  return NULL;
}


/**
 * Get the status of a Anastasis escrow
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego of which the status has to be obtained
 * @param escrowAnchor the escrow anchor needed to restore the key
 * 
 * @return the status of the escrow packed into a GNUNET_ESCROW_Status struct
 */
struct GNUNET_ESCROW_Status *
anastasis_get_status (struct GNUNET_ESCROW_Handle *h,
                      const struct GNUNET_IDENTITY_Ego *ego,
                      struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  struct GNUNET_ESCROW_Status *status;
  
  status = GNUNET_new (struct GNUNET_ESCROW_Status);
  // TODO: get the correct time values
  status->last_escrow_time = GNUNET_TIME_absolute_get ();
  status->next_recommended_escrow_time = GNUNET_TIME_absolute_get ();
  // END TODO
  
  return status;
}


/**
 * Deserialize an escrow anchor string into a GNUNET_ESCROW_Anchor struct
 * 
 * @param anchorString the encoded escrow anchor string
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct
 */
struct GNUNET_ESCROW_Anchor *
anastasis_anchor_string_to_data (struct GNUNET_ESCROW_Handle *h,
                                 char *anchorString)
{
  struct GNUNET_ESCROW_Anchor *anchor;
  uint32_t data_size;

  data_size = strlen (anchorString) + 1;

  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor) + data_size);
  anchor->size = data_size;
  // TODO: deserialize?
  GNUNET_memcpy (&anchor[1], anchorString, data_size);

  return anchor;
}


/**
 * Serialize an escrow anchor struct into a string
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor struct
 * 
 * @return the encoded escrow anchor string
 */
char *
anastasis_anchor_data_to_string (struct GNUNET_ESCROW_Handle *h,
                                 struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  // TODO: implement
  return NULL;
}


/**
 * Cancel an Anastasis plugin operation.
 * 
 * @param plugin_op_wrap the plugin operation wrapper containing the operation
 */
void
cancel_anastasis_operation (struct ESCROW_PluginOperationWrapper *plugin_op_wrap)
{
  // TODO: implement
  return;
}


/**
 * IdentityInitContinuation for the Anastasis plugin
 */
void
anastasis_cont_init ()
{
  return;
}


/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * 
 * @return the exported block API
 */
void *
libgnunet_plugin_escrow_anastasis_init (void *cls)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  api = GNUNET_new (struct GNUNET_ESCROW_KeyPluginFunctions);
  api->start_key_escrow = &start_anastasis_key_escrow;
  api->verify_key_escrow = &verify_anastasis_key_escrow;
  api->restore_key = &restore_anastasis_key_escrow;
  api->get_status = &anastasis_get_status;
  api->anchor_string_to_data = &anastasis_anchor_string_to_data;
  api->cancel_plugin_operation = &cancel_anastasis_operation;

  ph.id_init_cont = &anastasis_cont_init;

  identity_handle = GNUNET_IDENTITY_connect (cfg,
                                             &ESCROW_list_ego,
                                             &ph);

  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * 
 * @return NULL
 */
void *
libgnunet_plugin_escrow_anastasis_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowKeyPluginFunctions *api = cls;

  GNUNET_free (api);
  GNUNET_IDENTITY_disconnect (identity_handle);
  ESCROW_cleanup_ego_list (&ph);

  return NULL;
}


/* end of plugin_escrow_anastasis.c */
