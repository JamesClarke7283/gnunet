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
#include "gnunet_namestore_service.h"
#include "../identity/identity.h"
#include <sss.h>
#include <inttypes.h>


struct IdentityOperationEntry
{
  /**
   * DLL
   */
  struct IdentityOperationEntry *prev;
  
  /**
   * DLL
   */
  struct IdentityOperationEntry *next;

  /**
   * Identity operation
   */
  struct GNUNET_IDENTITY_Operation *id_op;

  /**
   * Private key of the respective ego
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
};


struct PkEntry
{
  /**
   * DLL
   */
  struct PkEntry *prev;

  /**
   * DLL
   */
  struct PkEntry *next;

  /**
   * private key
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
};


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

  /**
   * Namestore handle
   */
  struct GNUNET_NAMESTORE_Handle *ns_h;

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

  /**
   * Counter for the created escrow identities
   */
  uint8_t escrow_id_counter;

  /**
   * Number of shares
   */
  uint8_t shares;

  /**
   * Share threshold
   */
  uint8_t share_threshold;

  /**
   * Private key of the ego
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;

  /**
   * DLL head for identity operations
   */
  struct IdentityOperationEntry *id_ops_head;

  /**
   * DLL tail for identity operations
   */
  struct IdentityOperationEntry *id_ops_tail;

  /**
   * DLL head for escrow private keys
   */
  struct PkEntry *escrow_pks_head;

  /**
   * DLL tail for escrow private keys
   */
  struct PkEntry *escrow_pks_tail;
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
  struct ESCROW_GnsPluginOperation *p_op;
  struct IdentityOperationEntry *curr_id_op;
  struct PkEntry *curr_pk;

  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;

  GNUNET_CONTAINER_DLL_remove (ph.plugin_op_head,
                               ph.plugin_op_tail,
                               plugin_op_wrap);
  if (NULL != p_op->anchor_wrap)
    GNUNET_free (p_op->anchor_wrap);
  if (NULL != p_op->ego_wrap)
    GNUNET_free (p_op->ego_wrap);
  if (NULL != p_op->verify_wrap)
    GNUNET_free (p_op->verify_wrap);
  /* clean up identity operation list */
  for (curr_id_op = p_op->id_ops_head; NULL != curr_id_op; curr_id_op = curr_id_op->next)
  {
    GNUNET_CONTAINER_DLL_remove (p_op->id_ops_head,
                                 p_op->id_ops_tail,
                                 curr_id_op);
    GNUNET_IDENTITY_cancel (curr_id_op->id_op);
    GNUNET_free (curr_id_op->id_op);
    GNUNET_free (curr_id_op);
  }
  /* clean up escrow pk list */
  for (curr_pk = p_op->escrow_pks_head; NULL != curr_pk; curr_pk = curr_pk->next)
  {
    GNUNET_CONTAINER_DLL_remove (p_op->escrow_pks_head,
                                 p_op->escrow_pks_tail,
                                 curr_pk);
    GNUNET_free (curr_pk);
  }
  /* disconnect from namestore service */
  GNUNET_NAMESTORE_disconnect (p_op->ns_h);
  GNUNET_free (p_op);
  GNUNET_free (plugin_op_wrap);
}


void
start_cont (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  
  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;
  p_op->cont (p_op->anchor_wrap);

  cleanup_plugin_operation (plugin_op_wrap);
}


sss_Keyshare *
split_private_key (struct ESCROW_GnsPluginOperation *p_op)
{
  sss_Keyshare *keyshares;

  keyshares = GNUNET_malloc (sizeof (sss_Keyshare) * p_op->shares);
  sss_create_keyshares (keyshares,
                        p_op->pk->d,
                        p_op->shares,
                        p_op->share_threshold);

  return keyshares;
}


void
distribute_keyshares (struct ESCROW_GnsPluginOperation *p_op,
                      sss_Keyshare *keyshares)
{
  struct GNUNET_NAMESTORE_Handle *ns_h;
  struct PkEntry *curr_pk;
  char *curr_label;

  ns_h = GNUNET_NAMESTORE_connect (p_op->h->cfg);
  p_op->ns_h = ns_h;

  for (curr_pk = p_op->escrow_pks_head; NULL != curr_pk; curr_pk = curr_pk->next)
  {
    // TODO: implement
    curr_label = NULL;
    GNUNET_NAMESTORE_records_store (ns_h,
                                    curr_pk->pk,
                                    curr_label,
                                    0,
                                    NULL,
                                    NULL,
                                    NULL);
  }
}


void
escrow_ids_finished (struct ESCROW_PluginOperationWrapper *plugin_op_wrap)
{
  struct ESCROW_GnsPluginOperation *p_op;
  sss_Keyshare *keyshares;
  struct GNUNET_ESCROW_Anchor *anchor;
  int anchorDataSize;

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  /* split the private key (SSS) */
  keyshares = split_private_key (p_op);
  if (NULL == keyshares)
  {
    p_op->anchor_wrap->escrowAnchor = NULL;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&start_cont, p_op);
    return;
  }

  /* distribute the shares to the identities */
  distribute_keyshares (p_op, keyshares);

  // TODO: implement
  anchorDataSize = 0; // TODO!
  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor) + anchorDataSize);
  
  p_op->anchor_wrap->escrowAnchor = anchor;

  /* call the continuation */
  p_op->cont (p_op->anchor_wrap);
  cleanup_plugin_operation (plugin_op_wrap);
}


void
escrow_id_created (void *cls,
                   const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk,
                   const char *emsg)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  struct IdentityOperationEntry *curr_id_op;
  struct PkEntry *pk_entry;

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  if (NULL == pk)
  {
    if (NULL != emsg)
      fprintf (stderr,
               "Identity create operation returned with error: %s\n",
               emsg);
    else
      fprintf (stderr, "Failed to create ego!");
    p_op->anchor_wrap->escrowAnchor = NULL;
    p_op->cont (p_op->anchor_wrap);
    // this also cancels all running identity operations
    cleanup_plugin_operation (plugin_op_wrap);
    return;
  }

  /* escrow identity successfully created */
  for (curr_id_op = p_op->id_ops_head; NULL != curr_id_op; curr_id_op = curr_id_op->next)
  {
    if (pk == curr_id_op->pk)
    {
      GNUNET_CONTAINER_DLL_remove (p_op->id_ops_head,
                                   p_op->id_ops_tail,
                                   curr_id_op);
      GNUNET_free (curr_id_op);
      break;
    }
  }

  /* insert pk into our list */
  pk_entry = GNUNET_new (struct PkEntry);
  GNUNET_CONTAINER_DLL_insert_tail (p_op->escrow_pks_head,
                                    p_op->escrow_pks_tail,
                                    pk_entry);

  p_op->escrow_id_counter++;
  if (p_op->escrow_id_counter == p_op->shares)
  {
    escrow_ids_finished (plugin_op_wrap);
  }
}


static uint8_t
count_digits (uint8_t n)
{
  uint8_t i = 0;
  while (n != 0)
  {
    i++;
    n /= 10;
  }
  return i;
}


static char *
get_escrow_id_name (const char *name,
                    uint8_t i)
{
  char *str, *prefix, *number;
  uint8_t j = 0;

  prefix = "escrow-id_";
  number = GNUNET_malloc (count_digits (i) + 1);
  sprintf (number, "%d", i);

  str = GNUNET_malloc (strlen (prefix)
                       + strlen (name)
                       + 1
                       + strlen (number)
                       + 1);

  memcpy (str, prefix, strlen (prefix));
  j += strlen (prefix);
  memcpy (str + j, name, strlen (name));
  j += strlen (name);
  str[j++] = '_';
  memcpy (str + j, number, strlen (number));
  j += strlen (number);
  str[j] = '\0';

  GNUNET_free (number);

  return str;
}


static int
escrow_id_exists (const char *name,
                  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk)
{
  struct EgoEntry *curr;

  for (curr = ph.ego_head; NULL != curr; curr = curr->next)
  {
    if (0 == strcmp (name, curr->identifier))
    {
      if (curr->ego->pk.d == pk->d) // TODO: correct equality check?
        return GNUNET_YES;
      else // the escrow id's name exists for an ego, but the pk is wrong
        return GNUNET_SYSERR;
    }
  }

  return GNUNET_NO;
}


static struct GNUNET_CRYPTO_EcdsaPrivateKey *
derive_private_key (const char *name,
                    void *password,
                    uint8_t i)
{
  // TODO: derive key
  return NULL;
}


static void
create_escrow_identities (struct ESCROW_PluginOperationWrapper *plugin_op_wrap,
                          const char *name)
{
  struct ESCROW_GnsPluginOperation *p_op;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *curr_pk;
  char *curr_name;
  struct IdentityOperationEntry *curr_id_op;
  struct PkEntry *curr_pk_entry;
  int exists_ret;

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  for (uint8_t i = 0; i < p_op->shares; i++)
  {
    curr_pk = derive_private_key (name, NULL, i); // TODO: password
    curr_name = get_escrow_id_name (name, i);

    // check if the escrow identity already exists
    exists_ret = escrow_id_exists (curr_name, curr_pk);
    if (GNUNET_SYSERR == exists_ret)
    {
      p_op->anchor_wrap->escrowAnchor = NULL;
      p_op->cont (p_op->anchor_wrap);
      // this also cancels all running identity operations
      cleanup_plugin_operation (plugin_op_wrap);
      return;
    }
    else if (GNUNET_YES == exists_ret)
    {
      // the escrow id already exists, so insert the pk into our list
      curr_pk_entry = GNUNET_new (struct PkEntry);
      curr_pk_entry->pk = curr_pk;
      GNUNET_CONTAINER_DLL_insert (p_op->escrow_pks_head,
                                   p_op->escrow_pks_tail,
                                   curr_pk_entry);
    }
    else // GNUNET_NO
    {
      /* store the identity operation in our list */
      curr_id_op = GNUNET_new (struct IdentityOperationEntry);
      curr_id_op->pk = curr_pk;
      curr_id_op->id_op = GNUNET_IDENTITY_create (identity_handle,
                                                  curr_name,
                                                  curr_pk,
                                                  &escrow_id_created,
                                                  plugin_op_wrap);
      GNUNET_CONTAINER_DLL_insert (p_op->id_ops_head,
                                  p_op->id_ops_tail,
                                  curr_id_op);
    }
  }
}


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
                      struct GNUNET_IDENTITY_Ego *ego,
                      GNUNET_SCHEDULER_TaskCallback cb,
                      uint32_t op_id)
{
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
  p_op->cont = cb;

  w = GNUNET_new (struct ESCROW_Plugin_AnchorContinuationWrapper);
  w->h = h;
  w->op_id = op_id;
  p_op->anchor_wrap = w;

  if (NULL == ego)
  {
    w->escrowAnchor = NULL;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&start_cont, plugin_op_wrap);
    return plugin_op_wrap;
  }
  p_op->pk = GNUNET_IDENTITY_ego_get_private_key (ego);

  // get config
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (h->cfg,
                                                          "escrow",
                                                          "gns_shares",
                                                          &shares))
  {
    fprintf (stderr, "Number of shares not specified in config!");
    w->escrowAnchor = NULL;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&start_cont, plugin_op_wrap);
    return plugin_op_wrap;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (h->cfg,
                                                          "escrow",
                                                          "gns_share_threshold",
                                                          &share_threshold))
  {
    fprintf (stderr, "Share threshold not specified in config");
    w->escrowAnchor = NULL;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&start_cont, plugin_op_wrap);
    return plugin_op_wrap;
  }
  p_op->shares = (uint8_t)shares;
  p_op->share_threshold = (uint8_t)share_threshold;

  /* create the escrow identities */
  // TODO: check for existing escrow identities
  create_escrow_identities (plugin_op_wrap, ego->name);

  /* operation continues in escrow_ids_finished
     after all escrow identities are created */

  return plugin_op_wrap;
}


void
verify_cont (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  
  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;
  p_op->cont (p_op->verify_wrap);

  cleanup_plugin_operation (plugin_op_wrap);
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
  p_op->cont = cb;

  w = GNUNET_new (struct ESCROW_Plugin_VerifyContinuationWrapper);
  w->h = h;
  w->op_id = op_id;
  p_op->verify_wrap = w;

  // TODO: implement
  w->verificationResult = GNUNET_ESCROW_INVALID;
  p_op->sched_task = GNUNET_SCHEDULER_add_now (&verify_cont, plugin_op_wrap);
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
                        const char *egoName,
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
 * 
 * @return the status of the escrow packed into a GNUNET_ESCROW_Status struct
 */
struct GNUNET_ESCROW_Status *
gns_get_status (struct GNUNET_ESCROW_Handle *h,
                struct GNUNET_IDENTITY_Ego *ego)
{
  return ESCROW_get_escrow_status (h, ego);
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
  struct ESCROW_PluginOperationWrapper *curr;
  struct ESCROW_GnsPluginOperation *p_op;
  struct IdentityOperationEntry *curr_id_op;
  struct PkEntry *curr_pk;

  for (curr = ph.plugin_op_head; NULL != curr; curr = curr->next)
  {
    if (curr == plugin_op_wrap)
    {
      GNUNET_CONTAINER_DLL_remove (ph.plugin_op_head,
                                   ph.plugin_op_tail,
                                   curr);
      p_op = (struct ESCROW_GnsPluginOperation *)curr->plugin_op;

      /* clean up the identity operation list */
      for (curr_id_op = p_op->id_ops_head; NULL != curr_id_op; curr_id_op = curr_id_op->next)
      {
        GNUNET_CONTAINER_DLL_remove (p_op->id_ops_head,
                                     p_op->id_ops_tail,
                                     curr_id_op);
        GNUNET_IDENTITY_cancel (curr_id_op->id_op);
        GNUNET_free (curr_id_op);
      }

      /* clean up the escrow pk list */
      for (curr_pk = p_op->escrow_pks_head; NULL != curr_pk; curr_pk = curr_pk->next)
      {
        GNUNET_CONTAINER_DLL_remove (p_op->escrow_pks_head,
                                     p_op->escrow_pks_tail,
                                     curr_pk);
        GNUNET_free (curr_pk);
      }

      if (NULL != p_op->ns_h)
      {
        GNUNET_NAMESTORE_disconnect (p_op->ns_h);
        p_op->ns_h = NULL;
      }

      if (NULL != p_op->sched_task)
        GNUNET_SCHEDULER_cancel (p_op->sched_task);
      GNUNET_free (p_op);
      GNUNET_free (curr);
      return;
    }
  }
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

  ph.state = ESCROW_PLUGIN_STATE_INIT;
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
