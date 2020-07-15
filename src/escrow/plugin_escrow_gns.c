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

#define GNUNET_ESCROW_GNS_NumberOfShares 6
#define GNUNET_ESCROW_GNS_ShareThreshold 3


/**
 * Identity handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Handle for the plugin instance
 */
struct EscrowPluginHandle ph;


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
renew_gns_key_escrow (void *escrowAnchor)
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
 * Deserialize an escrow anchor string into a GNUNET_ESCROW_Anchor struct
 * 
 * @param anchorString the encoded escrow anchor string
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct
 */
const struct GNUNET_ESCROW_Anchor *
gns_anchor_string_to_data (char *anchorString)
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
 * ContinueIdentityInitFunction for the GNS plugin
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
 * @return the exported block API
 */
void *
libgnunet_plugin_escrow_gns_init (void *cls)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  api = GNUNET_new (struct GNUNET_ESCROW_KeyPluginFunctions);
  api->start_key_escrow = &start_gns_key_escrow;
  api->renew_key_escrow = &renew_gns_key_escrow;
  api->verify_key_escrow = &verify_gns_key_escrow;
  api->restore_key = &restore_gns_key_escrow;
  api->anchor_string_to_data = &gns_anchor_string_to_data;

  ph.cont = &gns_cont_init;

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
libgnunet_plugin_escrow_gns_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowKeyPluginFunctions *api = cls;

  GNUNET_free (api);
  GNUNET_IDENTITY_disconnect (identity_handle);
  ESCROW_cleanup_ego_list (&ph);

  return NULL;
}


/* end of plugin_escrow_gns.c */
