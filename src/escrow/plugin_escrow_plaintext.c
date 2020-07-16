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
 * @param cb function to call with the escrow anchor on completion
 * @param cb_cls closure for @a cb
 */
void
start_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                            const struct GNUNET_IDENTITY_Ego *ego,
                            GNUNET_ESCROW_AnchorContinuation cb,
                            void *cb_cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  struct GNUNET_ESCROW_Anchor *anchor;
  char *pkString;
  uint32_t anchorDataSize;

  if (NULL == ego)
  {
    cb (cb_cls, NULL);
    return;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);
  pkString = GNUNET_CRYPTO_ecdsa_private_key_to_string (pk);

  anchorDataSize = strlen (pkString) + 1;
  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor) + anchorDataSize);
  anchor->method = GNUNET_ESCROW_KEY_PLAINTEXT;
  anchor->size = anchorDataSize;
  GNUNET_memcpy (&anchor[1], pkString, anchorDataSize);

  cb (cb_cls, anchor);
}


/**
 * Renew the plaintext escrow of the key, i.e. simply hand out the key
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the the escrow anchor returned by the start method
 * @param cb function to call with the (new) escrow anchor on completion
 * @param cb_cls closure for @a cb
 */
void
renew_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                            struct GNUNET_ESCROW_Anchor *escrowAnchor,
                            GNUNET_ESCROW_AnchorContinuation cb,
                            void *cb_cls)
{
  cb (cb_cls, escrowAnchor);
}


/**
 * Verify the plaintext escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param cb function to call with the verification result on completion, i.e.
 *  GNUNET_ESCROW_VALID if the escrow could successfully by restored,
 *  GNUNET_ESCROW_RENEW_NEEDED if the escrow needs to be renewed,
 *  GNUNET_ESCROW_INVALID otherwise
 * @param cb_cls closure for @a cb
 */
void
verify_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                             const struct GNUNET_IDENTITY_Ego *ego,
                             struct GNUNET_ESCROW_Anchor *escrowAnchor,
                             GNUNET_ESCROW_VerifyContinuation cb,
                             void *cb_cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  char *pkString;
  int verificationResult;

  if (NULL == ego)
  {
    cb (cb_cls, GNUNET_ESCROW_INVALID);
    return;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);
  pkString = GNUNET_CRYPTO_ecdsa_private_key_to_string (pk);
  verificationResult = strncmp (pkString,
                                (char *)escrowAnchor,
                                strlen (pkString)) == 0 ?
    GNUNET_ESCROW_VALID : GNUNET_ESCROW_INVALID;
  cb (cb_cls, verificationResult);
}


/**
 * Restore the key from plaintext escrow
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 * @param cb function to call with the restored ego on completion
 * @param cb_cls closure for @a cb
 */
void
restore_plaintext_key_escrow (struct GNUNET_ESCROW_Handle *h,
                              struct GNUNET_ESCROW_Anchor *escrowAnchor,
                              char *egoName,
                              GNUNET_ESCROW_EgoContinuation cb,
                              void *cb_cls)
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey pk;
  struct GNUNET_IDENTITY_Operation *op;

  if (NULL == escrowAnchor)
  {
    cb (cb_cls, NULL);
    return;
  }
  if (GNUNET_OK !=
    GNUNET_CRYPTO_ecdsa_private_key_from_string ((char *)escrowAnchor,
                                                 strlen ((char *)escrowAnchor),
                                                 &pk))
  {
    cb (cb_cls, NULL);
    return;
  }
  
  // TODO: implement
  op = GNUNET_IDENTITY_create (NULL,
                               egoName,
                               &pk,
                               NULL,
                               NULL);
  cb (cb_cls, NULL);
}


/**
 * Deserialize an escrow anchor string into a GNUNET_ESCROW_Anchor struct
 * 
 * @param anchorString the encoded escrow anchor string
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct
 */
struct GNUNET_ESCROW_Anchor *
plaintext_anchor_string_to_data (char *anchorString)
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
 * ContinueIdentityInitFunction for the plaintext plugin
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

  ph.cont = &plaintext_cont_init;

  identity_handle = GNUNET_IDENTITY_connect (cfg,
                                             &ESCROW_list_ego,
                                             &ph);

  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
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
