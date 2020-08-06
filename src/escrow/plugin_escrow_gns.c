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
 * @file escrow/plugin_escrow_gns.c
 * @brief escrow-plugin-gns escrow plugin for the escrow of the key
 *        using GNS and escrow identities
 *
 * @author Johannes Späth
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_escrow_plugin.h"
#include "escrow_plugin_helper.h"
#include <sss.h>
#include <inttypes.h>


struct ESCROW_GnsPluginOperation
{
  /**
   * Handle for the escrow component
   */
  struct GNUNET_ESCROW_Handle *h;

  /**
   * Scheduler task the SCHEDULE operation returns (needed for cancellation)
   */
  struct GNUNET_SCHEDULER_Task *sched_task;
};

/**
 * Identity handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Handle for the plugin instance
 */
struct ESCROW_PluginHandle ph;


/**
 * Start the GNS escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return plugin operation wrapper
 */
struct ESCROW_PluginOperationWrapper *
start_gns_key_escrow (struct GNUNET_ESCROW_Handle *h,
                      const struct GNUNET_IDENTITY_Ego *ego,
                      GNUNET_SCHEDULER_TaskCallback cb,
                      uint32_t op_id)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  sss_Keyshare keyshares;
  struct GNUNET_ESCROW_Anchor *anchor;
  int anchorDataSize;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;
  struct ESCROW_Plugin_AnchorContinuationWrapper *w;
  unsigned long long shares, share_threshold;

  // create a new GNS plugin operation (in a wrapper) and insert it into the DLL
  plugin_op_wrap = GNUNET_new (struct ESCROW_PluginOperationWrapper);
  plugin_op_wrap->plugin_op = GNUNET_new (struct ESCROW_GnsPluginOperation);
  GNUNET_CONTAINER_DLL_insert_tail (ph.plugin_op_head,
                                    ph.plugin_op_tail,
                                    plugin_op_wrap);

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;
  p_op->h = h;

  w = GNUNET_new (struct ESCROW_Plugin_AnchorContinuationWrapper);
  w->h = h;
  w->op_id = op_id;

  if (NULL == ego)
  {
    w->escrowAnchor = NULL;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (cb, w);
    return plugin_op_wrap;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);

  // split the private key (SSS)
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (h->cfg,
                                                          "escrow",
                                                          "gns_shares",
                                                          &shares))
  {
    fprintf (stderr, "Number of shares not specified in config!");
    w->escrowAnchor = NULL;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (cb, w);
    return plugin_op_wrap;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (h->cfg,
                                                          "escrow",
                                                          "gns_share_threshold",
                                                          &share_threshold))
  {
    fprintf (stderr, "Share threshold not specified in config");
    w->escrowAnchor = NULL;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (cb, w);
    return plugin_op_wrap;
  }
  sss_create_keyshares (&keyshares,
                        pk->d,
                        (uint8_t)shares,
                        (uint8_t)share_threshold);

  // create the escrow identities

  // distribute the shares to the identities


  // TODO: implement
  anchorDataSize = 0; // TODO!
  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor) + anchorDataSize);
  
  w->escrowAnchor = anchor;

  p_op->sched_task = GNUNET_SCHEDULER_add_now (cb, w);
  return plugin_op_wrap;
}


/**
 * Verify the GNS escrow of the key
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
verify_gns_key_escrow (struct GNUNET_ESCROW_Handle *h,
                       const struct GNUNET_IDENTITY_Ego *ego,
                       struct GNUNET_ESCROW_Anchor *escrowAnchor,
                       GNUNET_SCHEDULER_TaskCallback cb,
                       uint32_t op_id)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;
  struct ESCROW_Plugin_VerifyContinuationWrapper *w;

  // create a new GNS plugin operation (in a wrapper) and insert it into the DLL
  plugin_op_wrap = GNUNET_new (struct ESCROW_PluginOperationWrapper);
  plugin_op_wrap->plugin_op = GNUNET_new (struct ESCROW_GnsPluginOperation);
  GNUNET_CONTAINER_DLL_insert_tail (ph.plugin_op_head,
                                    ph.plugin_op_tail,
                                    plugin_op_wrap);

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;
  p_op->h = h;

  w = GNUNET_new (struct ESCROW_Plugin_VerifyContinuationWrapper);
  w->h = h;
  w->op_id = op_id;

  // TODO: implement
  w->verificationResult = GNUNET_ESCROW_INVALID;
  p_op->sched_task = GNUNET_SCHEDULER_add_now (cb, w);
  return plugin_op_wrap;
}


/**
 * Restore the key from GNS escrow
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
restore_gns_key_escrow (struct GNUNET_ESCROW_Handle *h,
                        struct GNUNET_ESCROW_Anchor *escrowAnchor,
                        char *egoName,
                        GNUNET_SCHEDULER_TaskCallback cb,
                        uint32_t op_id)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;
  struct ESCROW_Plugin_EgoContinuationWrapper *w;

  // create a new GNS plugin operation (in a wrapper) and insert it into the DLL
  plugin_op_wrap = GNUNET_new (struct ESCROW_PluginOperationWrapper);
  plugin_op_wrap->plugin_op = GNUNET_new (struct ESCROW_GnsPluginOperation);
  GNUNET_CONTAINER_DLL_insert_tail (ph.plugin_op_head,
                                    ph.plugin_op_tail,
                                    plugin_op_wrap);

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;
  p_op->h = h;

  w = GNUNET_new (struct ESCROW_Plugin_EgoContinuationWrapper);
  w->h = h;
  w->op_id = op_id;

  // TODO: implement
  w->ego = NULL;
  p_op->sched_task = GNUNET_SCHEDULER_add_now (cb, w);
  return plugin_op_wrap;
}


/**
 * Get the status of a GNS escrow
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego of which the status has to be obtained
 * @param escrowAnchor the escrow anchor needed to restore the key
 * 
 * @return the status of the escrow packed into a GNUNET_ESCROW_Status struct
 */
struct GNUNET_ESCROW_Status *
gns_get_status (struct GNUNET_ESCROW_Handle *h,
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
gns_anchor_string_to_data (struct GNUNET_ESCROW_Handle *h,
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
gns_anchor_data_to_string (struct GNUNET_ESCROW_Handle *h,
                           struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  // TODO: implement
  return NULL;
}


/**
 * Cancel a GNS plugin operation.
 * 
 * @param plugin_op_wrap the plugin operation wrapper containing the operation
 */
void
cancel_gns_operation (struct ESCROW_PluginOperationWrapper *plugin_op_wrap)
{
  // TODO: implement
  return;
}


/**
 * IdentityInitContinuation for the GNS plugin
 */
void
gns_cont_init ()
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
libgnunet_plugin_escrow_gns_init (void *cls)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  api = GNUNET_new (struct GNUNET_ESCROW_KeyPluginFunctions);
  api->start_key_escrow = &start_gns_key_escrow;
  api->verify_key_escrow = &verify_gns_key_escrow;
  api->restore_key = &restore_gns_key_escrow;
  api->get_status = &gns_get_status;
  api->anchor_string_to_data = &gns_anchor_string_to_data;
  api->cancel_plugin_operation = &cancel_gns_operation;

  ph.id_init_cont = &gns_cont_init;

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
libgnunet_plugin_escrow_gns_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowKeyPluginFunctions *api = cls;

  GNUNET_free (api);
  GNUNET_IDENTITY_disconnect (identity_handle);
  ESCROW_cleanup_ego_list (&ph);

  return NULL;
}


/* end of plugin_escrow_gns.c */
