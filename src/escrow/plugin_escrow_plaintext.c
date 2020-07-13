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
#include "gnunet_identity_service.h"
#include <inttypes.h>


/**
 * Start the plaintext escrow of the key, i.e. simply hand out the key
 * 
 * @param ego the identity ego containing the private key
 * @return the escrow anchor needed to restore the key
 */
void *
start_plaintext_key_escrow (const struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;

  if (NULL == ego)
  {
    return NULL;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);
  return GNUNET_CRYPTO_ecdsa_private_key_to_string (pk);
}


/**
 * Renew the plaintext escrow of the key, i.e. simply hand out the key
 * 
 * @param escrowAnchor the the escrow anchor returned by the start method
 * @return the escrow anchor needed to restore the key
 */
void *
renew_plaintext_key_escrow (const struct GNUNET_IDENTITY_Ego *ego)
{
  return start_plaintext_key_escrow (ego);
}


/**
 * Verify the plaintext escrow of the key
 * 
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @return GNUNET_ESCROW_VALID if the escrow could successfully by restored,
 *         GNUNET_ESCROW_RENEW_NEEDED if the escrow needs to be renewed,
 *         GNUNET_ESCROW_INVALID otherwise
 */
int
verify_plaintext_key_escrow (const struct GNUNET_IDENTITY_Ego *ego,
                             void *escrowAnchor)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  char *pkString;

  if (NULL == ego)
  {
    return GNUNET_ESCROW_INVALID;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);
  pkString = GNUNET_CRYPTO_ecdsa_private_key_to_string (pk);
  return strncmp (pkString, (char *)escrowAnchor, strlen (pkString)) == 0 ?
    GNUNET_ESCROW_VALID : GNUNET_ESCROW_INVALID;
}


/**
 * Restore the key from plaintext escrow
 * 
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 * @return the identity ego containing the private key
 */
const struct GNUNET_IDENTITY_Ego *
restore_plaintext_key_escrow (void *escrowAnchor,
                              char *egoName)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey pk;
  struct GNUNET_IDENTITY_Operation *op;

  if (NULL == escrowAnchor)
  {
    return NULL;
  }
  // TODO: ecdsa method for string -> privkey
  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_private_key_from_string ((char *)escrowAnchor,
                                                                strlen ((char *)escrowAnchor),
                                                                &pk))
  {
    return NULL;
  }
  
  // TODO: implement
  op = GNUNET_IDENTITY_create (NULL,
                               egoName,
                               &pk,
                               NULL,
                               NULL);
  return NULL;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_escrow_plaintext_init (void *cls)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_ESCROW_KeyPluginFunctions);
  api->start_key_escrow = &start_plaintext_key_escrow;
  api->renew_key_escrow = &renew_plaintext_key_escrow;
  api->verify_key_escrow = &verify_plaintext_key_escrow;
  api->restore_key = &restore_plaintext_key_escrow;
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
  return NULL;
}


/* end of plugin_escrow_plaintext.c */
