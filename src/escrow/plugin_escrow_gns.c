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
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "../identity/identity.h"
#include <sss.h>
#include <inttypes.h>


/**
 * Continuation with a private key (used for restore_private_key)
 */
typedef void (*PkContinuation) (void *cls,
                                const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk);


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
  struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;

  /**
   * Name of the respective ego
   */
  char *name;

  /**
   * Index of the respective share
   */
  uint8_t i;

  /**
   * The plugin operation that started the identity operation
   */
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
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
  struct GNUNET_CRYPTO_EcdsaPrivateKey pk;

  /**
   * index of the respective share
   */
  uint8_t i;
};


struct NamestoreQueueEntry
{
  /**
   * DLL
   */
  struct NamestoreQueueEntry *prev;

  /**
   * DLL
   */
  struct NamestoreQueueEntry *next;

  /**
   * Namestore queue entry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Plugin operation that called the namestore operation
   */
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
};


// define TimeoutTaskEntry here, as it is already needed in GnsLookupRequest
struct TimeoutTaskEntry;


struct GnsLookupRequestEntry
{
  /**
   * DLL
   */
  struct GnsLookupRequestEntry *prev;

  /**
   * DLL
   */
  struct GnsLookupRequestEntry *next;

  /**
   * GNS lookup request
   */
  struct GNUNET_GNS_LookupRequest *lr;

  /**
   * Plugin operation that started the lookup
   */
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;

  /**
   * index of the respective share
   */
  uint8_t i;

  /**
   * Timeout task scheduled for this lookup request
   */
  struct TimeoutTaskEntry *tt;
};


struct TimeoutTaskEntry
{
  /**
   * DLL
   */
  struct TimeoutTaskEntry *prev;

  /**
   * DLL
   */
  struct TimeoutTaskEntry *next;

  /**
   * Timeout task
   */
  struct GNUNET_SCHEDULER_Task *tt;

  /**
   * GNS lookup request this timeout is for
   */
  struct GnsLookupRequestEntry *gns_lr;

  /**
   * Plugin operation that started the timeout
   */
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
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
   * GNS handle
   */
  struct GNUNET_GNS_Handle *gns_h;

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
   * Continuation to be called with the restored private key
   */
  PkContinuation restore_pk_cont;

  /**
   * Closure for @a cont
   */
  void *restore_pk_cont_cls;

  /**
   * Array for the restored keyshares
   */
  sss_Keyshare *restored_keyshares;

  /**
   * Identity operation for the create of the restored ego
   */
  struct GNUNET_IDENTITY_Operation *id_op;

  /**
   * The ego
   */
  struct GNUNET_IDENTITY_Ego *ego;

  /**
   * The name of the ego
   */
  char *egoName;

  /**
   * Private key of the ego
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey pk;

  /**
   * User secret string
   */
  char *userSecret;

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

  /**
   * DLL head for namestore queue entries
   */
  struct NamestoreQueueEntry *ns_qes_head;

  /**
   * DLL tail for namestore queue entries
   */
  struct NamestoreQueueEntry *ns_qes_tail;

  /**
   * DLL head for GNS lookup requests
   */
  struct GnsLookupRequestEntry *gns_lrs_head;

  /**
   * DLL tail for GNS lookup requests
   */
  struct GnsLookupRequestEntry *gns_lrs_tail;

  /**
   * DLL head for GNS timeout tasks
   */
  struct TimeoutTaskEntry *tts_head;

  /**
   * DLL tail for GNS timeout tasks
   */
  struct TimeoutTaskEntry *tts_tail;
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
  struct IdentityOperationEntry *curr_id_op, *next_id_op;
  struct PkEntry *curr_pk, *next_pk;
  struct NamestoreQueueEntry *curr_ns_qe, *next_ns_qe;
  struct GnsLookupRequestEntry *curr_gns_lr, *next_gns_lr;
  struct TimeoutTaskEntry *curr_tt, *next_tt;

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
  if (NULL != p_op->userSecret)
    GNUNET_free (p_op->userSecret);
  /* clean up identity operation list */
  for (curr_id_op = p_op->id_ops_head; NULL != curr_id_op; curr_id_op = next_id_op)
  {
    next_id_op = curr_id_op->next;
    GNUNET_CONTAINER_DLL_remove (p_op->id_ops_head,
                                 p_op->id_ops_tail,
                                 curr_id_op);
    GNUNET_IDENTITY_cancel (curr_id_op->id_op);
    GNUNET_free (curr_id_op->pk);
    GNUNET_free (curr_id_op->name);
    GNUNET_free (curr_id_op);
  }
  /* clean up escrow pk list */
  for (curr_pk = p_op->escrow_pks_head; NULL != curr_pk; curr_pk = next_pk)
  {
    next_pk = curr_pk->next;
    GNUNET_CONTAINER_DLL_remove (p_op->escrow_pks_head,
                                 p_op->escrow_pks_tail,
                                 curr_pk);
    GNUNET_free (curr_pk);
  }
  /* clean up namestore operation list */
  for (curr_ns_qe = p_op->ns_qes_head; NULL != curr_ns_qe; curr_ns_qe = next_ns_qe)
  {
    next_ns_qe = curr_ns_qe->next;
    GNUNET_CONTAINER_DLL_remove (p_op->ns_qes_head,
                                 p_op->ns_qes_tail,
                                 curr_ns_qe);
    // also frees the curr_ns_qe->ns_qe
    GNUNET_NAMESTORE_cancel (curr_ns_qe->ns_qe);
    GNUNET_free (curr_ns_qe);
  }
  /* clean up GNS lookup request list */
  for (curr_gns_lr = p_op->gns_lrs_head; NULL != curr_gns_lr; curr_gns_lr = next_gns_lr)
  {
    next_gns_lr = curr_gns_lr->next;
    GNUNET_CONTAINER_DLL_remove (p_op->gns_lrs_head,
                                 p_op->gns_lrs_tail,
                                 curr_gns_lr);
    GNUNET_GNS_lookup_cancel (curr_gns_lr->lr);
    GNUNET_free (curr_gns_lr);
  }
  /* clean up timeout task list */
  for (curr_tt = p_op->tts_head; NULL != curr_tt; curr_tt = next_tt)
  {
    next_tt = curr_tt->next;
    GNUNET_CONTAINER_DLL_remove (p_op->tts_head,
                                 p_op->tts_tail,
                                 curr_tt);
    GNUNET_SCHEDULER_cancel (curr_tt->tt);
    GNUNET_free (curr_tt);
  }
  /* free the keyshares array */
  if (NULL != p_op->restored_keyshares)
    GNUNET_free (p_op->restored_keyshares);
  /* disconnect from namestore service */
  if (NULL != p_op->ns_h)
    GNUNET_NAMESTORE_disconnect (p_op->ns_h);
  /* disconnect from GNS service */
  if (NULL != p_op->gns_h)
    GNUNET_GNS_disconnect (p_op->gns_h);
  /* cancel scheduled task */
  if (NULL != p_op->sched_task)
    GNUNET_SCHEDULER_cancel (p_op->sched_task);
  /* cancel identity operation */
  if (NULL != p_op->id_op)
    GNUNET_IDENTITY_cancel (p_op->id_op);
  if (NULL != p_op->egoName)
    GNUNET_free (p_op->egoName);
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


void
verify_cont (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  
  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;
  p_op->cont (p_op->verify_wrap);

  cleanup_plugin_operation (plugin_op_wrap);
}


static void
handle_restore_error (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  
  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;
  p_op->cont (p_op->ego_wrap);

  cleanup_plugin_operation (plugin_op_wrap);
}


sss_Keyshare *
split_private_key (struct ESCROW_GnsPluginOperation *p_op)
{
  sss_Keyshare *keyshares;

  keyshares = GNUNET_malloc (sizeof (sss_Keyshare) * p_op->shares);
  sss_create_keyshares (keyshares,
                        p_op->pk.d,
                        p_op->shares,
                        p_op->share_threshold);

  return keyshares;
}


static void
keyshare_distribution_finished (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  struct GNUNET_ESCROW_Anchor *anchor;
  int anchorDataSize;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All keyshares distributed\n");

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  anchorDataSize = strlen(p_op->userSecret) + 1;
  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor) + anchorDataSize);
  anchor->method = GNUNET_ESCROW_KEY_GNS;
  anchor->egoName = GNUNET_strdup (p_op->ego->name);
  anchor->size = anchorDataSize;
  GNUNET_memcpy (&anchor[1], p_op->userSecret, anchorDataSize);
  
  p_op->anchor_wrap->escrowAnchor = anchor;

  /* set the last escrow time */
  ESCROW_update_escrow_status (p_op->h, p_op->ego, "gns");

  /* call the continuation */
  start_cont (plugin_op_wrap);
}


static void
keyshare_distributed (void *cls,
                      int32_t success,
                      const char *emsg)
{
  struct NamestoreQueueEntry *ns_qe = cls;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Keyshare distributed\n");

  plugin_op_wrap = ns_qe->plugin_op_wrap;
  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  // remove qe from our list
  GNUNET_CONTAINER_DLL_remove (p_op->ns_qes_head,
                               p_op->ns_qes_tail,
                               ns_qe);

  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store keyshare %s\n",
                emsg);
    p_op->anchor_wrap->escrowAnchor = NULL;
    p_op->anchor_wrap->emsg = _ ("Keyshare distribution failed!\n");
    p_op->cont (p_op->anchor_wrap);
    // this also cancels all running namestore operations
    cleanup_plugin_operation (plugin_op_wrap);
    return;
  }

  // check if all namestore operations are finished
  GNUNET_free (ns_qe);
  if (NULL == p_op->ns_qes_head)
  {
    // schedule the further execution, lets NAMESTORE clean up its operation list
    GNUNET_SCHEDULER_add_now (&keyshare_distribution_finished, plugin_op_wrap);
  }
}


static char *
get_label (const char *userSecret)
{
  char *label;
  struct GNUNET_HashCode hash;
  struct GNUNET_CRYPTO_HashAsciiEncoded hashEnc;

  // the label is the hash of the userSecret
  GNUNET_CRYPTO_hash (userSecret, strlen (userSecret), &hash);
  GNUNET_CRYPTO_hash_to_enc (&hash, &hashEnc);
  label = GNUNET_strdup ((char *)hashEnc.encoding);

  return label;
}


static int
distribute_keyshares (struct ESCROW_PluginOperationWrapper *plugin_op_wrap,
                      sss_Keyshare *keyshares)
{
  struct ESCROW_GnsPluginOperation *p_op;
  struct GNUNET_NAMESTORE_Handle *ns_h;
  struct NamestoreQueueEntry *curr_ns_qe;
  struct PkEntry *curr_pk;
  char *curr_label;
  struct GNUNET_GNSRECORD_Data curr_rd[1];

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Distributing keyshares\n");

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  ns_h = GNUNET_NAMESTORE_connect (p_op->h->cfg);
  p_op->ns_h = ns_h;

  for (curr_pk = p_op->escrow_pks_head; NULL != curr_pk; curr_pk = curr_pk->next)
  {
    curr_label = get_label (p_op->userSecret);
    curr_ns_qe = GNUNET_new (struct NamestoreQueueEntry);

    curr_rd[0].data_size = sizeof (sss_Keyshare);
    curr_rd[0].data = keyshares[curr_pk->i];
    curr_rd[0].record_type = GNUNET_GNSRECORD_TYPE_ESCROW_KEYSHARE;
    curr_rd[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
    // TODO: config param?
    curr_rd[0].expiration_time = 30 * 24 * GNUNET_TIME_relative_get_hour_().rel_value_us;

    curr_ns_qe->plugin_op_wrap = plugin_op_wrap;
    curr_ns_qe->ns_qe = GNUNET_NAMESTORE_records_store (ns_h,
                                                        &curr_pk->pk,
                                                        curr_label,
                                                        1,
                                                        curr_rd,
                                                        &keyshare_distributed,
                                                        curr_ns_qe);
    GNUNET_CONTAINER_DLL_insert_tail (p_op->ns_qes_head,
                                      p_op->ns_qes_tail,
                                      curr_ns_qe);
    GNUNET_free (curr_label);
  }

  return GNUNET_OK;
}


void
escrow_ids_finished (struct ESCROW_PluginOperationWrapper *plugin_op_wrap)
{
  struct ESCROW_GnsPluginOperation *p_op;
  sss_Keyshare *keyshares;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All escrow identities created\n");

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  /* split the private key (SSS) */
  keyshares = split_private_key (p_op);
  if (NULL == keyshares)
  {
    p_op->anchor_wrap->escrowAnchor = NULL;
    p_op->anchor_wrap->emsg = _ ("Failed to split the key!\n");
    start_cont (plugin_op_wrap);
    return;
  }

  /* distribute the shares to the identities */
  if (GNUNET_OK != distribute_keyshares (plugin_op_wrap, keyshares))
  {
    p_op->anchor_wrap->escrowAnchor = NULL;
    p_op->anchor_wrap->emsg = _ ("Failed to distribute the keyshares!\n");
    start_cont (plugin_op_wrap);
    return;
  }
  
  /* operation continues in keyshare_distribution_finished
     after all keyshares have been distributed */
}


void
escrow_id_created (void *cls,
                   const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk,
                   const char *emsg)
{
  struct IdentityOperationEntry *id_op = cls;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;
  struct PkEntry *pk_entry;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Escrow identity %d created\n", id_op->i);

  plugin_op_wrap = id_op->plugin_op_wrap;
  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  if (NULL == pk)
  {
    if (NULL != emsg)
    {
      fprintf (stderr,
               "Identity create operation returned with error: %s\n",
               emsg);
      p_op->anchor_wrap->emsg = _ ("Identity create failed!\n");
    }
    else
      p_op->anchor_wrap->emsg = _ ("Failed to create ego!\n");
    p_op->anchor_wrap->escrowAnchor = NULL;
    p_op->cont (p_op->anchor_wrap);
    // this also cancels all running identity operations
    cleanup_plugin_operation (plugin_op_wrap);
    return;
  }

  /* escrow identity successfully created */
  GNUNET_CONTAINER_DLL_remove (p_op->id_ops_head,
                               p_op->id_ops_tail,
                               id_op);

  /* insert pk into our list */
  pk_entry = GNUNET_new (struct PkEntry);
  pk_entry->pk = *pk;
  pk_entry->i = id_op->i;
  GNUNET_CONTAINER_DLL_insert_tail (p_op->escrow_pks_head,
                                    p_op->escrow_pks_tail,
                                    pk_entry);

  GNUNET_free (id_op);

  /* check if this was the last id_op */
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

  do
  {
    i++;
    n /= 10;
  } while (n != 0);

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
      if (0 == memcmp (&curr->ego->pk,
                       pk,
                       sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey)))
        return GNUNET_YES;
      else // the escrow id's name exists for an ego, but the pk is wrong
        return GNUNET_SYSERR;
    }
  }

  return GNUNET_NO;
}


static struct GNUNET_CRYPTO_EcdsaPrivateKey *
derive_private_key (const char *name,
                    const char *password,
                    uint8_t i)
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  static const char ctx[] = "gnunet-escrow-id-ctx";
  
  pk = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  GNUNET_CRYPTO_kdf (pk,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
                     ctx, strlen (ctx),
                     password, strlen (password),
                     name, strlen (name),
                     &i, 1,
                     NULL);

  pk->d[0] &= 248;
  pk->d[31] &= 127;
  pk->d[31] |= 64;
  
  return pk;
}


static void
handle_existing_wrong_ego_deletion (void *cls,
                                    const char *emsg)
{
  struct IdentityOperationEntry *curr_id_op = cls;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;

  plugin_op_wrap = curr_id_op->plugin_op_wrap;
  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  if (NULL != emsg)
  {
    fprintf (stderr,
             "Identity create operation returned with error: %s\n",
             emsg);
    p_op->anchor_wrap->emsg = _ ("Identity delete of wrong existing ego failed!\n");
    p_op->anchor_wrap->escrowAnchor = NULL;
    p_op->cont (p_op->anchor_wrap);
    // this also cancels all running identity operations
    cleanup_plugin_operation (plugin_op_wrap);
    return;
  }

  /* no error occured, so create the new identity */
  // the IdentityOperationEntry is reused, so only the id_op is updated
  curr_id_op->id_op = GNUNET_IDENTITY_create (identity_handle,
                                              curr_id_op->name,
                                              curr_id_op->pk,
                                              &escrow_id_created,
                                              curr_id_op);
}


static void
create_escrow_identities (struct ESCROW_PluginOperationWrapper *plugin_op_wrap,
                          const char *name)
{
  struct ESCROW_GnsPluginOperation *p_op;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *curr_pk;
  char *curr_name, *curr_pk_string;
  struct IdentityOperationEntry *curr_id_op;
  struct PkEntry *curr_pk_entry;
  int exists_ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating escrow identities\n");

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  for (uint8_t i = 0; i < p_op->shares; i++)
  {
    curr_pk = derive_private_key (name, p_op->userSecret, i);
    curr_name = get_escrow_id_name (name, i);

    // TODO: REMOVE THIS LOGGING BEFORE PRODUCTIONAL USE!
    curr_pk_string = GNUNET_CRYPTO_ecdsa_private_key_to_string (curr_pk);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "derived private key: %s\n",
                curr_pk_string);
    GNUNET_free (curr_pk_string);

    // check if the escrow identity already exists
    exists_ret = escrow_id_exists (curr_name, curr_pk);
    if (GNUNET_SYSERR == exists_ret)
    {
      /* an ego with identifier name but the wrong pk exists, delete it first */
      curr_id_op = GNUNET_new (struct IdentityOperationEntry);
      curr_id_op->pk = curr_pk;
      curr_id_op->name = curr_name;
      curr_id_op->i = i;
      curr_id_op->plugin_op_wrap = plugin_op_wrap;
      curr_id_op->id_op = GNUNET_IDENTITY_delete (identity_handle,
                                                  curr_name,
                                                  &handle_existing_wrong_ego_deletion,
                                                  curr_id_op);
      GNUNET_CONTAINER_DLL_insert (p_op->id_ops_head,
                                   p_op->id_ops_tail,
                                   curr_id_op);
    }
    else if (GNUNET_YES == exists_ret)
    {
      // the escrow id already exists, so insert the pk into our list
      curr_pk_entry = GNUNET_new (struct PkEntry);
      curr_pk_entry->pk = *curr_pk;
      curr_pk_entry->i = i;
      GNUNET_CONTAINER_DLL_insert (p_op->escrow_pks_head,
                                   p_op->escrow_pks_tail,
                                   curr_pk_entry);
      
      p_op->escrow_id_counter++;
      if (p_op->escrow_id_counter == p_op->shares)
      {
        escrow_ids_finished (plugin_op_wrap);
      }
    }
    else // GNUNET_NO
    {
      /* store the identity operation in our list */
      curr_id_op = GNUNET_new (struct IdentityOperationEntry);
      curr_id_op->pk = curr_pk;
      curr_id_op->name = curr_name;
      curr_id_op->i = i;
      curr_id_op->plugin_op_wrap = plugin_op_wrap;
      curr_id_op->id_op = GNUNET_IDENTITY_create (identity_handle,
                                                  curr_name,
                                                  curr_pk,
                                                  &escrow_id_created,
                                                  curr_id_op);
      GNUNET_CONTAINER_DLL_insert (p_op->id_ops_head,
                                   p_op->id_ops_tail,
                                   curr_id_op);
    }
  }
}


static void
handle_config_load_error (struct ESCROW_PluginOperationWrapper *plugin_op_wrap,
                          char *emsg)
{
  struct ESCROW_GnsPluginOperation *p_op;

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  if (NULL != p_op->anchor_wrap)
  {
    p_op->anchor_wrap->escrowAnchor = NULL;
    p_op->anchor_wrap->emsg = emsg;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&start_cont, plugin_op_wrap);
    return;
  }

  if (NULL != p_op->verify_wrap)
  {
    p_op->verify_wrap->verificationResult = GNUNET_ESCROW_INVALID;
    p_op->verify_wrap->emsg = emsg;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&verify_cont, plugin_op_wrap);
    return;
  }

  if (NULL != p_op->ego_wrap)
  {
    p_op->ego_wrap->ego = NULL;
    p_op->ego_wrap->emsg = emsg;
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&handle_restore_error, plugin_op_wrap);
    return;
  }
}


static int
load_keyshare_config (struct ESCROW_PluginOperationWrapper *plugin_op_wrap)
{
  struct ESCROW_GnsPluginOperation *p_op;
  unsigned long long shares, share_threshold;

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (p_op->h->cfg,
                                                          "escrow",
                                                          "gns_shares",
                                                          &shares))
  {
    handle_config_load_error (plugin_op_wrap,
                              "Number of shares not specified in config!");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (p_op->h->cfg,
                                                          "escrow",
                                                          "gns_share_threshold",
                                                          &share_threshold))
  {
    handle_config_load_error (plugin_op_wrap,
                              "Share threshold not specified in config");
    return GNUNET_SYSERR;
  }
  p_op->shares = (uint8_t)shares;
  p_op->share_threshold = (uint8_t)share_threshold;

  return GNUNET_OK;
}


static void
continue_start (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  struct GNUNET_TIME_Relative delay;

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  if (ESCROW_PLUGIN_STATE_POST_INIT != ph.state)
  {
    delay.rel_value_us = 100 * GNUNET_TIME_relative_get_millisecond_().rel_value_us;
    GNUNET_SCHEDULER_add_delayed (delay, &continue_start, plugin_op_wrap);
    return;
  }

  /* load config */
  if (GNUNET_OK != load_keyshare_config (plugin_op_wrap))
    return;

  /* create the escrow identities */
  create_escrow_identities (plugin_op_wrap, p_op->ego->name);

  /* operation continues in escrow_ids_finished
     after all escrow identities are created */
}


/**
 * Start the GNS escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param userSecret the user secret (used for derivation of escrow identities)
 *                   this has to be UNIQUE in the whole network!
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return plugin operation wrapper
 */
struct ESCROW_PluginOperationWrapper *
start_gns_key_escrow (struct GNUNET_ESCROW_Handle *h,
                      struct GNUNET_IDENTITY_Ego *ego,
                      const char *userSecret,
                      GNUNET_SCHEDULER_TaskCallback cb,
                      uint32_t op_id)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;
  struct ESCROW_Plugin_AnchorContinuationWrapper *w;
  struct GNUNET_TIME_Relative delay;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting GNS escrow\n");

  // create a new GNS plugin operation (in a wrapper) and insert it into the DLL
  plugin_op_wrap = GNUNET_new (struct ESCROW_PluginOperationWrapper);
  plugin_op_wrap->plugin_op = GNUNET_new (struct ESCROW_GnsPluginOperation);
  GNUNET_CONTAINER_DLL_insert_tail (ph.plugin_op_head,
                                    ph.plugin_op_tail,
                                    plugin_op_wrap);

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;
  p_op->h = h;
  p_op->cont = cb;
  p_op->ego = ego;

  w = GNUNET_new (struct ESCROW_Plugin_AnchorContinuationWrapper);
  w->h = h;
  w->op_id = op_id;
  p_op->anchor_wrap = w;

  if (NULL == ego || NULL == userSecret)
  {
    w->escrowAnchor = NULL;
    if (NULL == ego)
      w->emsg = _ ("ESCROW_put was called with ego == NULL\n");
    else if (NULL == userSecret)
      w->emsg = _ ("GNS escrow needs a user secret!\n");
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&start_cont, plugin_op_wrap);
    return plugin_op_wrap;
  }
  p_op->pk = *GNUNET_IDENTITY_ego_get_private_key (ego);
  p_op->userSecret = GNUNET_strdup (userSecret);

  if (ESCROW_PLUGIN_STATE_POST_INIT == ph.state)
  {
    continue_start (plugin_op_wrap);
  }
  else
  {
    delay.rel_value_us = 200 * GNUNET_TIME_relative_get_millisecond_().rel_value_us;
    GNUNET_SCHEDULER_add_delayed (delay, &continue_start, plugin_op_wrap);
  }

  return plugin_op_wrap;
}


static uint8_t
count_keyshares (sss_Keyshare *keyshares, uint8_t n)
{
  uint8_t i, c;
  sss_Keyshare null_ks;

  memset (null_ks, 0, sizeof (sss_Keyshare));

  c = 0;
  for (i = 0; i < n; i++)
  {
    if (0 != memcmp (keyshares[i], &null_ks, sizeof (sss_Keyshare)))
      c++;
  }

  return c;
}


static void
remove_empty_keyshares (sss_Keyshare *keyshares, uint8_t n)
{
  uint8_t i, j;
  sss_Keyshare null_ks;

  memset (null_ks, 0, sizeof (sss_Keyshare));

  for (i = j = 0; i < n; i++)
  {
    if (0 != memcmp (keyshares[i], &null_ks, sizeof (sss_Keyshare)))
    {
      memcpy (keyshares[j], keyshares[i], sizeof (sss_Keyshare));
      j++;
    }
  }
}


static void
process_keyshares (void *cls)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  uint8_t keyshares_count;

  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;

  /* check if enough keyshares have been restored */
  keyshares_count = count_keyshares (p_op->restored_keyshares, p_op->shares);
  if (keyshares_count < p_op->share_threshold)
  {
    /* the key cannot be restored */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "need %hhu shares, but could only get %hhu\n",
                p_op->share_threshold,
                keyshares_count);

    if (NULL != p_op->verify_wrap) // this was called by a verify operation
    {
      p_op->verify_wrap->emsg =
        _ ("key could not be restored, failed to get enough keyshares\n");
      p_op->restore_pk_cont (p_op->restore_pk_cont_cls, NULL);
      return;
    }

    if (NULL != p_op->ego_wrap) // this was called by a restore operation
    {
      p_op->ego_wrap->emsg =
        _ ("key could not be restored, failed to get enough keyshares\n");
      p_op->restore_pk_cont (p_op->restore_pk_cont_cls, NULL);
      return;
    }
  }

  /* combine the shares */
  if (keyshares_count != p_op->shares)
    remove_empty_keyshares (p_op->restored_keyshares, p_op->shares);

  pk = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  sss_combine_keyshares (pk->d,
                         p_op->restored_keyshares,
                         keyshares_count);

  p_op->restore_pk_cont (p_op->restore_pk_cont_cls, pk);
}


static void
process_gns_lookup_result (void *cls,
                           uint32_t rd_count,
                           const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GnsLookupRequestEntry *gns_lr = cls;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;
  sss_Keyshare keyshare;
  char keyshare_string[64], *end;

  plugin_op_wrap = gns_lr->plugin_op_wrap;
  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;

  /* remove gns_lr from our list */
  GNUNET_CONTAINER_DLL_remove (p_op->gns_lrs_head,
                               p_op->gns_lrs_tail,
                               gns_lr);

  /* cancel the timeout for that lookup */
  GNUNET_CONTAINER_DLL_remove (p_op->tts_head,
                               p_op->tts_tail,
                               gns_lr->tt);
  GNUNET_SCHEDULER_cancel (gns_lr->tt->tt);
  GNUNET_free (gns_lr->tt);

  if (1 != rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "did not get exactly _one_ record from GNS\n");
    goto END;
  }

  if (sizeof (sss_Keyshare) != rd[0].data_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "the size of the GNS record differs from the size of a keyshare\n");
    goto END;
  }

  GNUNET_memcpy (&keyshare,
                 rd[0].data,
                 rd[0].data_size);

  end = GNUNET_STRINGS_data_to_string (&keyshare,
                                       sizeof (sss_Keyshare),
                                       keyshare_string,
                                       sizeof (keyshare_string));
  GNUNET_break (NULL != end);
  *end = '\0';

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "got keyshare %s from GNS\n", keyshare_string);

  GNUNET_memcpy (p_op->restored_keyshares[gns_lr->i],
                 &keyshare,
                 sizeof (sss_Keyshare));

  END:
  GNUNET_free (gns_lr);

  // check if this was the last gns_lr, i.e. our list is empty
  if (NULL == p_op->gns_lrs_head)
  {
    // schedule the further execution, lets GNS clean up its operation list
    GNUNET_SCHEDULER_add_now (&process_keyshares, plugin_op_wrap);
  }
}


static void
timeout_gns_request (void *cls)
{
  struct TimeoutTaskEntry *curr_tt = cls;
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;
  struct ESCROW_GnsPluginOperation *p_op;

  plugin_op_wrap = curr_tt->plugin_op_wrap;
  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;

  /* remove timeout task from our list */
  GNUNET_CONTAINER_DLL_remove (p_op->tts_head,
                               p_op->tts_tail,
                               curr_tt);

  /* cancel the GNS lookup and remove it from our list */
  GNUNET_GNS_lookup_cancel (curr_tt->gns_lr->lr);
  GNUNET_CONTAINER_DLL_remove (p_op->gns_lrs_head,
                               p_op->gns_lrs_tail,
                               curr_tt->gns_lr);
  GNUNET_free (curr_tt->gns_lr);

  GNUNET_free (curr_tt);

  /* check if this was the last pending GNS lookup */
  if (NULL == p_op->gns_lrs_head)
  {
    // no need to schedule, as the timeout is already scheduled
    process_keyshares (plugin_op_wrap);
  }
}


static char *
get_user_secret_from_anchor (const struct GNUNET_ESCROW_Anchor *anchor)
{
  char *userSecret;

  userSecret = GNUNET_malloc (anchor->size);
  GNUNET_memcpy (userSecret, &anchor[1], anchor->size);

  return userSecret;
}


static void
restore_private_key (struct ESCROW_PluginOperationWrapper *plugin_op_wrap,
                     struct GNUNET_ESCROW_Anchor *escrowAnchor, // TODO: use escrowAnchor??
                     PkContinuation cont,
                     void *cont_cls)
{
  struct ESCROW_GnsPluginOperation *p_op;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *curr_escrow_pk;
  struct GNUNET_CRYPTO_EcdsaPublicKey curr_escrow_pub;
  char *label, *curr_escrow_pk_string;
  struct GnsLookupRequestEntry *curr_gns_lr;
  struct GNUNET_TIME_Relative delay;
  struct TimeoutTaskEntry *curr_tt;

  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;

  p_op->gns_h = GNUNET_GNS_connect (p_op->h->cfg);
  p_op->restore_pk_cont = cont;
  p_op->restore_pk_cont_cls = cont_cls;
  p_op->restored_keyshares = GNUNET_malloc (sizeof (sss_Keyshare) * p_op->shares);
  // ensure that the array is initialized with 0, as this is needed for counting the shares
  memset (p_op->restored_keyshares, 0, sizeof (sss_Keyshare) * p_op->shares);

  label = get_label (p_op->userSecret);

  // init delay to 2s
  delay.rel_value_us = 2 * GNUNET_TIME_relative_get_second_().rel_value_us;

  for (uint8_t i = 0; i < p_op->shares; i++)
  {
    curr_escrow_pk = derive_private_key (p_op->egoName, p_op->userSecret, i);

    // TODO: REMOVE THIS LOGGING BEFORE PRODUCTIONAL USE!
    curr_escrow_pk_string = GNUNET_CRYPTO_ecdsa_private_key_to_string (curr_escrow_pk);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "derived private key: %s\n",
                curr_escrow_pk_string);
    GNUNET_free (curr_escrow_pk_string);

    curr_gns_lr = GNUNET_new (struct GnsLookupRequestEntry);
    curr_gns_lr->plugin_op_wrap = plugin_op_wrap;
    curr_gns_lr->i = i;
    GNUNET_CRYPTO_ecdsa_key_get_public (curr_escrow_pk, &curr_escrow_pub);
    curr_gns_lr->lr = GNUNET_GNS_lookup (p_op->gns_h,
                                         label,
                                         &curr_escrow_pub,
                                         GNUNET_GNSRECORD_TYPE_ESCROW_KEYSHARE,
                                         GNUNET_GNS_LO_DEFAULT,
                                         &process_gns_lookup_result,
                                         curr_gns_lr);
    GNUNET_CONTAINER_DLL_insert_tail (p_op->gns_lrs_head,
                                      p_op->gns_lrs_tail,
                                      curr_gns_lr);

    /* start timeout for GNS lookup (cancels the lr if not yet finished) */
    curr_tt = GNUNET_new (struct TimeoutTaskEntry);
    curr_tt->gns_lr = curr_gns_lr;
    curr_tt->plugin_op_wrap = plugin_op_wrap;
    curr_tt->tt = GNUNET_SCHEDULER_add_delayed (delay,
                                                &timeout_gns_request,
                                                curr_tt);
    GNUNET_CONTAINER_DLL_insert_tail (p_op->tts_head,
                                      p_op->tts_tail,
                                      curr_tt);

    // set the timeout task for the current gns lr entry
    curr_gns_lr->tt = curr_tt;
  }
  GNUNET_free (label);
}


static void
verify_restored_pk (void *cls,
                    const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *ego_pk;
  int verificationResult;

  p_op = (struct ESCROW_GnsPluginOperation *)plugin_op_wrap->plugin_op;

  if (NULL == pk)
    verificationResult = GNUNET_ESCROW_INVALID;
  else
  {
    ego_pk = GNUNET_IDENTITY_ego_get_private_key (p_op->ego);
    verificationResult = memcmp (pk,
                                 ego_pk,
                                 sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey))
                        == 0 ? GNUNET_ESCROW_VALID : GNUNET_ESCROW_INVALID;
  }

  // check if all shares could be restored
  if (GNUNET_ESCROW_VALID == verificationResult &&
      count_keyshares (p_op->restored_keyshares, p_op->shares) < p_op->shares)
    verificationResult = GNUNET_ESCROW_SHARES_MISSING;

  p_op->verify_wrap->verificationResult = verificationResult;
  verify_cont (plugin_op_wrap);
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
                       struct GNUNET_IDENTITY_Ego *ego,
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
  p_op->ego = ego;
  p_op->egoName = GNUNET_strdup (ego->name);
  p_op->userSecret = get_user_secret_from_anchor (escrowAnchor);

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
  if (0 != strcmp (ego->name, escrowAnchor->egoName))
  {
    w->verificationResult = GNUNET_ESCROW_INVALID;
    w->emsg = _ ("This anchor was not created when putting ego that in escrow!\n");
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&verify_cont, plugin_op_wrap);
    return plugin_op_wrap;
  }

  /* load config */
  if (GNUNET_OK != load_keyshare_config (plugin_op_wrap))
    return plugin_op_wrap;

  restore_private_key (plugin_op_wrap,
                       escrowAnchor,
                       &verify_restored_pk,
                       plugin_op_wrap);

  return plugin_op_wrap;
}


void
ego_created (const struct GNUNET_IDENTITY_Ego *ego)
{
  struct ESCROW_PluginOperationWrapper *curr;
  struct ESCROW_GnsPluginOperation *curr_p_op;
  char *ego_pk_string, *curr_pk_string;

  ego_pk_string = GNUNET_CRYPTO_ecdsa_private_key_to_string (&ego->pk);

  for (curr = ph.plugin_op_head; NULL != curr; curr = curr->next)
  {
    curr_p_op = (struct ESCROW_GnsPluginOperation *)curr->plugin_op;
    curr_pk_string = GNUNET_CRYPTO_ecdsa_private_key_to_string (&curr_p_op->pk);
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


static void
id_create_finished (void *cls,
                    const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk,
                    const char *emsg)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;
  
  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;

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
  p_op->pk = *pk;
}


static void
restore_ego_from_pk (void *cls,
                     const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk)
{
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap = cls;
  struct ESCROW_GnsPluginOperation *p_op;

  p_op = (struct ESCROW_GnsPluginOperation*)plugin_op_wrap->plugin_op;

  if (NULL == pk)
  {
    p_op->ego_wrap->ego = NULL;
    handle_restore_error (plugin_op_wrap);
    return;
  }

  p_op->id_op = GNUNET_IDENTITY_create (identity_handle,
                                        p_op->egoName,
                                        pk,
                                        &id_create_finished,
                                        plugin_op_wrap);
}


/**
 * Restore the key from GNS escrow
 * 
 * @param h the handle for the escrow component
 * @param anchor the escrow anchor needed to restore the key
 * @param cb the function called upon completion
 * @param op_id unique ID of the respective ESCROW_Operation
 * 
 * @return plugin operation wrapper
 */
struct ESCROW_PluginOperationWrapper *
restore_gns_key_escrow (struct GNUNET_ESCROW_Handle *h,
                        struct GNUNET_ESCROW_Anchor *anchor,
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
  // set cont here (has to be scheduled from the IDENTITY service when it finished)
  p_op->cont = cb;
  p_op->egoName = GNUNET_strdup (anchor->egoName);
  p_op->userSecret = get_user_secret_from_anchor (anchor);

  w = GNUNET_new (struct ESCROW_Plugin_EgoContinuationWrapper);
  w->h = h;
  w->op_id = op_id;
  p_op->ego_wrap = w;

  if (NULL == anchor)
  {
    w->ego = NULL;
    w->emsg = _ ("ESCROW_get was called with anchor == NULL!\n");
    // schedule handle_restore_error, which calls the callback and cleans up
    p_op->sched_task = GNUNET_SCHEDULER_add_now (&handle_restore_error, plugin_op_wrap);
    return plugin_op_wrap;
  }

  /* load config */
  if (GNUNET_OK != load_keyshare_config (plugin_op_wrap))
    return plugin_op_wrap;

  restore_private_key (plugin_op_wrap,
                       anchor,
                       &restore_ego_from_pk,
                       plugin_op_wrap);

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
 * Cancel a GNS plugin operation.
 * 
 * @param plugin_op_wrap the plugin operation wrapper containing the operation
 */
void
cancel_gns_operation (struct ESCROW_PluginOperationWrapper *plugin_op_wrap)
{
  struct ESCROW_PluginOperationWrapper *curr;

  for (curr = ph.plugin_op_head; NULL != curr; curr = curr->next)
  {
    if (curr == plugin_op_wrap)
    {
      GNUNET_CONTAINER_DLL_remove (ph.plugin_op_head,
                                   ph.plugin_op_tail,
                                   curr);
      cleanup_plugin_operation (curr);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GNS plugin initialized\n");
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
  api->cancel_plugin_operation = &cancel_gns_operation;

  ph.state = ESCROW_PLUGIN_STATE_INIT;
  ph.id_init_cont = &gns_cont_init;

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
libgnunet_plugin_escrow_gns_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowKeyPluginFunctions *api = cls;

  GNUNET_free (api);
  GNUNET_IDENTITY_disconnect (identity_handle);
  ESCROW_cleanup_ego_list (&ph);

  return NULL;
}


/* end of plugin_escrow_gns.c */
