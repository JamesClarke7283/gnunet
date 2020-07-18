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
#include "escrow_plugin_helper.h"
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
 * Start the Anastasis escrow of the key
 * 
 * @param op the escrow operation
 * @param ego the identity ego containing the private key
 */
void
start_anastasis_key_escrow (struct GNUNET_ESCROW_Operation *op,
                            const struct GNUNET_IDENTITY_Ego *ego)
{
  // TODO: implement
  op->cb_put (op->cb_cls, NULL);
}


/**
 * Renew the Anastasis escrow of the key
 * 
 * @param op the escrow operation
 * @param escrowAnchor the the escrow anchor returned by the start method
 */
void
renew_anastasis_key_escrow (struct GNUNET_ESCROW_Operation *op,
                            struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  // TODO: implement
  op->cb_renew (op->cb_cls, NULL);
}


/**
 * Verify the Anastasis escrow of the key
 * 
 * @param op the escrow operation
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 */
void
verify_anastasis_key_escrow (struct GNUNET_ESCROW_Operation *op,
                             const struct GNUNET_IDENTITY_Ego *ego,
                             struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  // TODO: implement
  op->cb_verify (op->cb_cls, GNUNET_ESCROW_INVALID);
}


/**
 * Restore the key from Anastasis escrow
 * 
 * @param op the escrow operation
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 */
void
restore_anastasis_key_escrow (struct GNUNET_ESCROW_Operation *op,
                              struct GNUNET_ESCROW_Anchor *escrowAnchor,
                              char *egoName)
{
  // TODO: implement
  op->cb_get (op->cb_cls, NULL);
}


/**
 * Deserialize an escrow anchor string into a GNUNET_ESCROW_Anchor struct
 * 
 * @param anchorString the encoded escrow anchor string
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct
 */
struct GNUNET_ESCROW_Anchor *
anastasis_anchor_string_to_data (struct GNUNET_ESCROW_Handle *h,
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
anastasis_anchor_data_to_string (struct GNUNET_ESCROW_Handle *h,
                                 struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  // TODO: implement
  return NULL;
}


/**
 * IdentityInitContinuation for the Anastasis plugin
 */
void
anastasis_cont_init ()
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
libgnunet_plugin_escrow_anastasis_init (void *cls)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  api = GNUNET_new (struct GNUNET_ESCROW_KeyPluginFunctions);
  api->start_key_escrow = &start_anastasis_key_escrow;
  api->renew_key_escrow = &renew_anastasis_key_escrow;
  api->verify_key_escrow = &verify_anastasis_key_escrow;
  api->restore_key = &restore_anastasis_key_escrow;
  api->anchor_string_to_data = &anastasis_anchor_string_to_data;

  ph.cont = &anastasis_cont_init;

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
libgnunet_plugin_escrow_anastasis_done (void *cls)
{
  struct GNUNET_RECLAIM_EscrowKeyPluginFunctions *api = cls;

  GNUNET_free (api);
  GNUNET_IDENTITY_disconnect (identity_handle);
  ESCROW_cleanup_ego_list (&ph);

  return NULL;
}


/* end of plugin_escrow_anastasis.c */
