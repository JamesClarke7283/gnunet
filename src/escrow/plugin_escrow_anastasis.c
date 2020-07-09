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
 * @file escrow/plugin_escrow_anastasis.c
 * @brief escrow-plugin-anastasis escrow plugin for escrow of the key using Anastasis
 *
 * @author Johannes Späth
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_escrow_plugin.h"
#include <inttypes.h>


/**
 * Start the Anastasis escrow of the key
 * 
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the anchor needed to restore the key
 * @return GNUNET_OK if successful
 */
int
start_anastasis_key_escrow (const struct GNUNET_IDENTITY_Ego *ego,
                            void *escrowAnchor)
{
  // TODO: implement
  return GNUNET_NO;
}


/**
 * Renew the Anastasis escrow of the key
 * 
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the anchor needed to restore the key
 * @return GNUNET_OK if successful
 */
int
renew_anastasis_key_escrow (const struct GNUNET_IDENTITY_Ego *ego,
                            void *escrowAnchor)
{
  // TODO: implement
  return GNUNET_NO;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_escrow_anastasis_init (void *cls)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_ESCROW_KeyPluginFunctions);
  api->start_key_escrow = &start_anastasis_key_escrow;
  api->renew_key_escrow = &renew_anastasis_key_escrow;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_escrow_anastasis_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowKeyPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_escrow_anastasis.c */
