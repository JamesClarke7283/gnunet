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
 * @file escrow/plugin_escrow_plaintext.c
 * @brief escrow-plugin-plaintext escrow plugin for plaintext escrow of the key
 *
 * @author Johannes Späth
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_escrow_plugin.h"
#include "escrow_plugin_helper.h"
#include "gnunet_identity_service.h"
#include "../identity/identity.h"
#include "escrow.h"
#include <inttypes.h>


struct ESCROW_PlaintextPluginOperation
{
  /**
   * Handle for the escrow component
   */
  struct GNUNET_ESCROW_Handle *h;

  /**
   * Scheduler task the SCHEDULE operation returns (needed for cancellation)
   */
  struct GNUNET_SCHEDULER_Task *sched_task;

  /**
   * Identity operation
   */
  struct GNUNET_IDENTITY_Operation *id_op;

  /**
   * Private key of the created ego
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;

  /**
   * Continuation for a plugin operation (e.g. used for restore, as this
   * callback has to be called from the IDENTITY service after finishing)
   */
  ESCROW_Plugin_Continuation cont;

  /**
   * Ego continuation wrapper
   */
  struct ESCROW_Plugin_EgoContinuationWrapper *ego_wrap;

  /**
   * Anchor continuation wrapper
   */
  struct ESCROW_Plugin_AnchorContinuationWrapper *anchor_wrap;

  /**
   * Verify continuation wrapper
   */
  struct ESCROW_Plugin_VerifyContinuationWrapper *verify_wrap;
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
 * Clean up a plugin operation, i.e. remove it from the list and
 * free the respective memory
 */
void
cleanup_plugin_operation (struct ESCROW_PluginOperationWrapper *plugin_op_wrap)
{
  struct ESCROW_PlaintextPluginOperation *p_op;

  p_op = (struct ESCROW_PlaintextPluginOperation*)plugin_op_wrap->plugin_op;

  GNUNET_CONTAINER_DLL_remove (ph.plugin_op_head,
                               ph.plugin_op_tail,
                               plugin_op_wrap);
  if (NULL != p_op->anchor_wrap)
    GNUNET_free (p_op->anchor_wrap);
  if (NULL != p_op->ego_wrap)
    GNUNET_free (p_op->ego_wrap);
  if (NULL != p_op->verify_wrap)
    GNUNET_free (p_op->verify_wrap);
  GNUNET_free (p_op);
  GNUNET_free (plugin_op_wrap);
}


void
start_cont (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_PlaintextPluginOperation *p_op;
  
  p_op = (struct ESCROW_PlaintextPluginOperation*)plugin_op_wrap->plugin_op;
  p_op->cont (p_op->anchor_wrap);

  cleanup_plugin_operation (plugin_op_wrap);
}


/**
 * Start the plaintext escrow of the key, i.e. simply hand out the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param userSecret the user secret (e.g. for derivation of escrow identities)
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return plugin operation wrapper
 */
struct ESCROW_PluginOperationWrapper *
start_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                            struct GNUNET_IDENTITY_Ego *ego,
                            const char *userSecret,
                            ESCROW_Plugin_Continuation cb,
                            uint32_t op_id)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  struct GNUNET_ESCROW_Anchor *anchor;
  char *pkString;
  uint32_t anchorDataSize;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_PlaintextPluginOperation *p_op;
  struct ESCROW_Plugin_AnchorContinuationWrapper *w;

  // create a new plaintext plugin operation (in a wrapper) and insert it into the DLL
  plugin_op_wrap = GNUNET_new (struct ESCROW_PluginOperationWrapper);
  plugin_op_wrap->plugin_op = GNUNET_new (struct ESCROW_PlaintextPluginOperation);
  GNUNET_CONTAINER_DLL_insert_tail (ph.plugin_op_head,
                                    ph.plugin_op_tail,
                                    plugin_op_wrap);

  p_op = (struct ESCROW_PlaintextPluginOperation *)plugin_op_wrap->plugin_op;
  p_op->h = h;
  p_op->cont = cb;

  w = GNUNET_new (struct ESCROW_Plugin_AnchorContinuationWrapper);
  w->h = h;
  w->op_id = op_id;
  p_op->anchor_wrap = w;

  if (NULL == ego)
  {
    w->escrowAnchor = NULL;
    w->emsg = _ ("ESCROW_put was called with ego == NULL!\n");
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&start_cont, plugin_op_wrap);
    return plugin_op_wrap;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);
  pkString = GNUNET_CRYPTO_ecdsa_private_key_to_string (pk);

  anchorDataSize = strlen (pkString) + 1;
  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor) + anchorDataSize);
  anchor->method = GNUNET_ESCROW_KEY_PLAINTEXT;
  anchor->size = anchorDataSize;
  GNUNET_memcpy (&anchor[1], pkString, anchorDataSize);

  w->escrowAnchor = anchor;

  /* set the last escrow time */
  ESCROW_update_escrow_status (h, ego, "plaintext");

  p_op->sched_task = GNUNET_SCHEDULER_add_now (&start_cont, plugin_op_wrap);
  return plugin_op_wrap;
}


void
verify_cont (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_PlaintextPluginOperation *p_op;
  
  p_op = (struct ESCROW_PlaintextPluginOperation*)plugin_op_wrap->plugin_op;
  p_op->cont (p_op->verify_wrap);

  cleanup_plugin_operation (plugin_op_wrap);
}


/**
 * Verify the plaintext escrow of the key
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
verify_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                             const struct GNUNET_IDENTITY_Ego *ego,
                             struct GNUNET_ESCROW_Anchor *escrowAnchor,
                             ESCROW_Plugin_Continuation cb,
                             uint32_t op_id)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  char *pkString;
  int verificationResult;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_PlaintextPluginOperation *p_op;
  struct ESCROW_Plugin_VerifyContinuationWrapper *w;
  
  // create a new plaintext plugin operation (in a wrapper) and insert it into the DLL
  plugin_op_wrap = GNUNET_new (struct ESCROW_PluginOperationWrapper);
  plugin_op_wrap->plugin_op = GNUNET_new (struct ESCROW_PlaintextPluginOperation);
  GNUNET_CONTAINER_DLL_insert_tail (ph.plugin_op_head,
                                    ph.plugin_op_tail,
                                    plugin_op_wrap);

  p_op = (struct ESCROW_PlaintextPluginOperation *)plugin_op_wrap->plugin_op;
  p_op->h = h;
  p_op->cont = cb;

  w = GNUNET_new (struct ESCROW_Plugin_VerifyContinuationWrapper);
  w->h = h;
  w->op_id = op_id;
  p_op->verify_wrap = w;

  if (NULL == ego)
  {
    w->verificationResult = GNUNET_ESCROW_INVALID;
    w->emsg = _ ("ESCROW_verify was called with ego == NULL!\n");
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&verify_cont, plugin_op_wrap);
    return plugin_op_wrap;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);
  pkString = GNUNET_CRYPTO_ecdsa_private_key_to_string (pk);
  verificationResult = strncmp (pkString,
                                (char *)&escrowAnchor[1],
                                strlen (pkString)) == 0 ?
    GNUNET_ESCROW_VALID : GNUNET_ESCROW_INVALID;

  w->verificationResult = verificationResult;
  p_op->sched_task = GNUNET_SCHEDULER_add_now (&verify_cont, plugin_op_wrap);
  return plugin_op_wrap;
}


void
ego_created (const struct GNUNET_IDENTITY_Ego *ego)
{
  struct ESCROW_PluginOperationWrapper *curr;
  struct ESCROW_PlaintextPluginOperation *curr_p_op;
  char *ego_pk_string, *curr_pk_string;

  ego_pk_string = GNUNET_CRYPTO_ecdsa_private_key_to_string (&ego->pk);

  for (curr = ph.plugin_op_head; NULL != curr; curr = curr->next)
  {
    curr_p_op = (struct ESCROW_PlaintextPluginOperation *)curr->plugin_op;
    curr_pk_string = GNUNET_CRYPTO_ecdsa_private_key_to_string (curr_p_op->pk);
    // compare the strings of the private keys
    if (0 == strcmp (ego_pk_string, curr_pk_string))
    {
      // the ego was created due to a restore operation that is not yet finished
      curr_p_op->ego_wrap->ego = ego;
      curr_p_op->cont (curr_p_op->ego_wrap);

      cleanup_plugin_operation (curr);

      GNUNET_free (curr_pk_string);
      GNUNET_free (ego_pk_string);
      return;
    }
    GNUNET_free (curr_pk_string);
  }
  GNUNET_free (ego_pk_string);
}


/**
 * Creation operation finished.
 * This method only handles errors that may have occurred. On success,
 * the callback is executed by the ESCROW_list_ego function, as the
 * new ego is in our ego list only after ESCROW_list_ego has added it.
 *
 * @param cls pointer to operation handle
 * @param pk private key of the ego, or NULL on error
 * @param emsg error message, NULL on success
 */
static void
create_finished (void *cls,
                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk,
                 const char *emsg)
{
  struct ESCROW_PlaintextPluginOperation *p_op = cls;

  if (NULL == pk)
  {
    if (NULL != emsg)
    {
      fprintf (stderr,
               "Identity create operation returned with error: %s\n",
               emsg);
      p_op->ego_wrap->emsg = _ ("Identity create failed!\n");
    }
    else
      p_op->ego_wrap->emsg = _ ("Failed to create ego!\n");
    p_op->ego_wrap->ego = NULL;
    p_op->cont (p_op->ego_wrap);
    return;
  }

  /* no error occurred, p_op->restore_cont will be called in ego_created, which
     is called from ESCROW_list_ego after adding the new ego to our list */
  p_op->pk = pk;
}


void
handle_restore_error (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_PlaintextPluginOperation *p_op;
  
  p_op = (struct ESCROW_PlaintextPluginOperation*)plugin_op_wrap->plugin_op;
  p_op->cont (p_op->ego_wrap);

  cleanup_plugin_operation (plugin_op_wrap);
}


/**
 * Restore the key from plaintext escrow
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
restore_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                              struct GNUNET_ESCROW_Anchor *escrowAnchor,
                              const char *egoName,
                              ESCROW_Plugin_Continuation cb,
                              uint32_t op_id)
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey pk;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_PlaintextPluginOperation *p_op;
  struct ESCROW_Plugin_EgoContinuationWrapper *w;

  // create a new plaintext plugin operation (in a wrapper) and insert it into the DLL
  plugin_op_wrap = GNUNET_new (struct ESCROW_PluginOperationWrapper);
  plugin_op_wrap->plugin_op = GNUNET_new (struct ESCROW_PlaintextPluginOperation);
  GNUNET_CONTAINER_DLL_insert_tail (ph.plugin_op_head,
                                    ph.plugin_op_tail,
                                    plugin_op_wrap);

  p_op = (struct ESCROW_PlaintextPluginOperation *)plugin_op_wrap->plugin_op;
  p_op->h = h;
  // set cont here (has to be scheduled from the IDENTITY service when it finished)
  p_op->cont = cb;

  w = GNUNET_new (struct ESCROW_Plugin_EgoContinuationWrapper);
  w->h = h;
  w->op_id = op_id;
  p_op->ego_wrap = w;

  if (NULL == escrowAnchor)
  {
    w->ego = NULL;
    w->emsg = _ ("ESCROW_get was called with escrowAnchor == NULL!\n");
    // schedule handle_restore_error, which calls the callback and cleans up
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&handle_restore_error, plugin_op_wrap);
    return plugin_op_wrap;
  }
  if (GNUNET_OK !=
    GNUNET_CRYPTO_ecdsa_private_key_from_string ((char *)&escrowAnchor[1],
                                                 strlen ((char *)&escrowAnchor[1]),
                                                 &pk))
  {
    w->ego = NULL;
    w->emsg = _ ("Failed to create ECDSA private key from escrow anchor!\n");
    // schedule handle_restore_error, which calls the callback and cleans up
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&handle_restore_error, plugin_op_wrap);
    return plugin_op_wrap;
  }
  
  p_op->id_op = GNUNET_IDENTITY_create (identity_handle,
                                        egoName,
                                        &pk,
                                        &create_finished,
                                        p_op);
  
  return plugin_op_wrap;
}


/**
 * Get the status of a plaintext escrow
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego of which the status has to be obtained
 * 
 * @return the status of the escrow packed into a GNUNET_ESCROW_Status struct
 */
struct GNUNET_ESCROW_Status *
plaintext_get_status (struct GNUNET_ESCROW_Handle *h,
                      struct GNUNET_IDENTITY_Ego *ego)
{
  return ESCROW_get_escrow_status (h, ego);
}


/**
 * Deserialize an escrow anchor string into a GNUNET_ESCROW_Anchor struct
 * 
 * @param h the handle for the escrow component
 * @param anchorString the encoded escrow anchor string
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct
 */
struct GNUNET_ESCROW_Anchor *
plaintext_anchor_string_to_data (struct GNUNET_ESCROW_Handle *h,
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
plaintext_anchor_data_to_string (struct GNUNET_ESCROW_Handle *h,
                                 struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  char *anchorString;

  anchorString = GNUNET_malloc (escrowAnchor->size);
  GNUNET_memcpy (anchorString, &escrowAnchor[1], escrowAnchor->size);

  return anchorString;
}


/**
 * Cancel a plaintext plugin operation.
 * 
 * @param plugin_op_wrap the plugin operation wrapper containing the operation
 */
void
cancel_plaintext_operation (struct ESCROW_PluginOperationWrapper *plugin_op_wrap)
{
  struct ESCROW_PluginOperationWrapper *curr;
  struct ESCROW_PlaintextPluginOperation *plugin_op;

  for (curr = ph.plugin_op_head; NULL != curr; curr = curr->next)
  {
    if (curr == plugin_op_wrap)
    {
      GNUNET_CONTAINER_DLL_remove (ph.plugin_op_head,
                                   ph.plugin_op_tail,
                                   curr);
      plugin_op = (struct ESCROW_PlaintextPluginOperation *)curr->plugin_op;
      GNUNET_IDENTITY_cancel (plugin_op->id_op);
      if (NULL != plugin_op->sched_task)
        GNUNET_SCHEDULER_cancel (plugin_op->sched_task);
      GNUNET_free (plugin_op);
      GNUNET_free (curr);
      return;
    }
  }
}


/**
 * IdentityInitContinuation for the plaintext plugin
 */
void
plaintext_cont_init ()
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
libgnunet_plugin_escrow_plaintext_init (void *cls)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  api = GNUNET_new (struct GNUNET_ESCROW_KeyPluginFunctions);
  api->start_key_escrow = &start_plaintext_key_escrow;
  api->verify_key_escrow = &verify_plaintext_key_escrow;
  api->restore_key = &restore_plaintext_key_escrow;
  api->get_status = &plaintext_get_status;
  api->anchor_string_to_data = &plaintext_anchor_string_to_data;
  api->anchor_data_to_string = &plaintext_anchor_data_to_string;
  api->cancel_plugin_operation = &cancel_plaintext_operation;

  ph.state = ESCROW_PLUGIN_STATE_INIT;
  ph.id_init_cont = &plaintext_cont_init;

  // set ego_create_cont here so it is called every time an ego is created
  ph.ego_create_cont = &ego_created;
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
libgnunet_plugin_escrow_plaintext_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowKeyPluginFunctions *api = cls;

  GNUNET_free (api);
  GNUNET_IDENTITY_disconnect (identity_handle);
  ESCROW_cleanup_ego_list (&ph);

  return NULL;
}


/* end of plugin_escrow_plaintext.c */
