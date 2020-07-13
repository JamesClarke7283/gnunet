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
#include <sss.h>
#include <inttypes.h>

#define GNUNET_ESCROW_GNS_NumberOfShares 6
#define GNUNET_ESCROW_GNS_ShareThreshold 3


/**
 * Start the GNS escrow of the key
 * 
 * @param ego the identity ego containing the private key
 * @return the escrow anchor needed to restore the key
 */
void *
start_gns_key_escrow (const struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk;
  sss_Keyshare keyshares;
  void *escrowAnchor;

  if (NULL == ego)
  {
    return GNUNET_NO;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (ego);

  // split the private key (SSS)
  sss_create_keyshares(keyshares,
                       pk,
                       GNUNET_ESCROW_GNS_NumberOfShares,
                       GNUNET_ESCROW_GNS_ShareThreshold);

  // create the escrow identities

  // distribute the shares to the identities


  // TODO: implement
  return escrowAnchor;
}


/**
 * Renew the GNS escrow of the key
 * 
 * @param escrowAnchor the the escrow anchor returned by the start method
 * @return the escrow anchor needed to restore the key
 */
void *
renew_gns_key_escrow (const struct GNUNET_IDENTITY_Ego *ego)
{
  // TODO: implement
  return NULL;
}


/**
 * Verify the GNS escrow of the key
 * 
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @return GNUNET_ESCROW_VALID if the escrow could successfully by restored,
 *         GNUNET_ESCROW_RENEW_NEEDED if the escrow needs to be renewed,
 *         GNUNET_ESCROW_INVALID otherwise
 */
int
verify_gns_key_escrow (const struct GNUNET_IDENTITY_Ego *ego,
                       void *escrowAnchor)
{
  // TODO: implement
  return GNUNET_ESCROW_INVALID;
}


/**
 * Restore the key from GNS escrow
 * 
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 * @return the identity ego containing the private key
 */
const struct GNUNET_IDENTITY_Ego *
restore_gns_key_escrow (void *escrowAnchor,
                        char *egoName)
{
  // TODO: implement
  return NULL;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_escrow_gns_init (void *cls)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_ESCROW_KeyPluginFunctions);
  api->start_key_escrow = &start_gns_key_escrow;
  api->renew_key_escrow = &renew_gns_key_escrow;
  api->verify_key_escrow = &verify_gns_key_escrow;
  api->restore_key = &restore_gns_key_escrow;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_escrow_gns_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowKeyPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_escrow_gns.c */
