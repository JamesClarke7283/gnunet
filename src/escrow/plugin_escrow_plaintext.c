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
#include <inttypes.h>


/**
 * Identity handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Handle for the plugin instance
 */
struct EscrowPluginHandle ph;


/**
 * Start the plaintext escrow of the key, i.e. simply hand out the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param cb the function called upon completion
 */
void
start_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                            const struct GNUNET_IDENTITY_Ego *ego,
                            GNUNET_ESCROW_AnchorContinuation cb)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  struct GNUNET_ESCROW_Anchor *anchor;
  char *pkString;
  uint32_t anchorDataSize;

  if (NULL == ego)
  {
    cb (h, NULL);
    return;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);
  pkString = GNUNET_CRYPTO_ecdsa_private_key_to_string (pk);

  anchorDataSize = strlen (pkString) + 1;
  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor) + anchorDataSize);
  anchor->method = GNUNET_ESCROW_KEY_PLAINTEXT;
  anchor->size = anchorDataSize;
  GNUNET_memcpy (&anchor[1], pkString, anchorDataSize);

  cb (h, anchor);
}


/**
 * Renew the plaintext escrow of the key, i.e. simply hand out the key
 * 
 * @param op the escrow operation
 * @param escrowAnchor the the escrow anchor returned by the start method
 */
void
renew_plaintext_key_escrow (struct GNUNET_ESCROW_Operation *op,
                            struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  op->cb_renew (op->cb_cls, escrowAnchor);
}


/**
 * Verify the plaintext escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param cb the function called upon completion
 */
void
verify_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                             const struct GNUNET_IDENTITY_Ego *ego,
                             struct GNUNET_ESCROW_Anchor *escrowAnchor,
                             GNUNET_ESCROW_VerifyContinuation cb)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  char *pkString;
  int verificationResult;

  if (NULL == ego)
  {
    cb (h, GNUNET_ESCROW_INVALID);
    return;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);
  pkString = GNUNET_CRYPTO_ecdsa_private_key_to_string (pk);
  verificationResult = strncmp (pkString,
                                (char *)&escrowAnchor[1],
                                strlen (pkString)) == 0 ?
    GNUNET_ESCROW_VALID : GNUNET_ESCROW_INVALID;
  cb (h, verificationResult);
}


void
ego_created (const struct GNUNET_IDENTITY_Ego *ego)
{
  ph.ego_create_cont = NULL;
  ph.curr_restore_cb (ph.escrow_handle, ego);
  ph.curr_restore_cb = NULL;
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
  GNUNET_ESCROW_EgoContinuation cb = cls;

  if (NULL == pk)
  {
    if (NULL != emsg)
      fprintf (stderr,
               "Identity create operation returned with error: %s\n",
               emsg);
    else
      fprintf (stderr, "Failed to create ego!");
    cb (ph.escrow_handle, NULL);
    return;
  }

  /* no error occurred, op->cb_get will be called from ESCROW_list_ego after 
     adding the new ego to our list */
  ph.ego_create_cont = &ego_created;
  ph.curr_restore_cb = cb;
}


/**
 * Restore the key from plaintext escrow
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 * @param cb the function called upon completion
 */
void
restore_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                              struct GNUNET_ESCROW_Anchor *escrowAnchor,
                              char *egoName,
                              GNUNET_ESCROW_EgoContinuation cb)
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey pk;
  struct GNUNET_IDENTITY_Operation *id_op;

  // TODO: is this the right place for that?
  ph.escrow_handle = h;

  if (NULL == escrowAnchor)
  {
    cb (h, NULL);
    return;
  }
  if (GNUNET_OK !=
    GNUNET_CRYPTO_ecdsa_private_key_from_string ((char *)&escrowAnchor[1],
                                                 strlen ((char *)&escrowAnchor[1]),
                                                 &pk))
  {
    cb (h, NULL);
    return;
  }
  
  id_op = GNUNET_IDENTITY_create (identity_handle,
                                  egoName,
                                  &pk,
                                  &create_finished,
                                  cb);

  // TODO: return id_op?
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
 * Cancel ... TODO
 */
void
cancel_plaintext_ ()
{
  return;
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
  api->renew_key_escrow = &renew_plaintext_key_escrow;
  api->verify_key_escrow = &verify_plaintext_key_escrow;
  api->restore_key = &restore_plaintext_key_escrow;
  api->anchor_string_to_data = &plaintext_anchor_string_to_data;
  api->anchor_data_to_string = &plaintext_anchor_data_to_string;

  ph.id_init_cont = &plaintext_cont_init;

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
