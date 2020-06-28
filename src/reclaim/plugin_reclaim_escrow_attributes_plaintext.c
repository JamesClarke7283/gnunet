/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014, 2016 GNUnet e.V.

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
 * @file reclaim-escrow/plugin_reclaim_escrow_attributes_plaintext.c
 * @brief reclaim-escrow-plugin-attributes-plaintext escrow plugin for
 *        plaintext escrow of the attributes
 *
 * @author Johannes Späth
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include <inttypes.h>


/**
 * Start the plaintext escrow of the attributes, i.e. simply hand them out
 * 
 * @param identity the private key of the identity
 * @param escrowAnchor the anchor needed to restore the attributes
 * @return GNUNET_OK if successful
 */
int
start_plaintext_attributes_escrow (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                   void *escrowAnchor)
{
  // TODO: implement
  return GNUNET_NO;
}


/**
 * Renew the plaintext escrow of the attributes, i.e. simply hand them out
 * 
 * @param identity the private key of the identity
 * @param escrowAnchor the anchor needed to restore the attributes
 * @return GNUNET_OK if successful
 */
int
renew_plaintext_attributes_escrow (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                   void *escrowAnchor)
{
  return start_plaintext_attributes_escrow(identity, escrowAnchor);
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_reclaim_escrow_plaintext_init (void *cls)
{
  struct GNUNET_RECLAIM_EscrowAttributesPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_RECLAIM_EscrowAttributesPluginFunctions);
  api->start_attributes_escrow = &start_plaintext_attributes_escrow;
  api->renew_attributes_escrow = &renew_plaintext_attributes_escrow;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_escrow_plaintext_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowAttributesPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_escrow_attributes_plaintext.c */
