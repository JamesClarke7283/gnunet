/*
   This file is part of GNUnet.
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
 * @author Johannes Späth
 * @file escrow/escrow_api.c
 * 
 * @brief api to interact with the escrow component
 */

#include "gnunet_util_lib.h"
#include "gnunet_escrow_lib.h"
#include "gnunet_escrow_plugin.h"


/**
 * Init canary for the plaintext plugin
 */
static int plaintext_initialized;


/**
 * Init canary for the GNS plugin
 */
static int gns_initialized;


/**
 * Init canary for the Anastasis plugin
 */
static int anastasis_initialized;


/**
 * Pointer to the plaintext plugin API
 */
static struct GNUNET_ESCROW_KeyPluginFunctions *plaintext_api;


/**
 * Pointer to the GNS plugin API
 */
static struct GNUNET_ESCROW_KeyPluginFunctions *gns_api;


/**
 * Pointer to the Anastasis plugin API
 */
static struct GNUNET_ESCROW_KeyPluginFunctions *anastasis_api;


/**
 * Initialize an escrow plugin
 * 
 * @param method the escrow method determining the plugin
 * 
 * @return pointer to the escrow plugin API
 */
struct GNUNET_ESCROW_KeyPluginFunctions *
init_plugin (enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  switch (method)
  {
    case GNUNET_ESCROW_KEY_PLAINTEXT:
      if (GNUNET_YES == plaintext_initialized)
        return plaintext_api;
      plaintext_initialized = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Loading PLAINTEXT escrow plugin\n");
      plaintext_api = GNUNET_PLUGIN_load ("libgnunet_plugin_escrow_plaintext",
                                          NULL);
      return plaintext_api;
    case GNUNET_ESCROW_KEY_GNS:
      if (GNUNET_YES == gns_initialized)
        return gns_api;
      gns_initialized = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Loading GNS escrow plugin\n");
      gns_api = GNUNET_PLUGIN_load ("libgnunet_plugin_escrow_gns",
                                    NULL);
      return gns_api;
    case GNUNET_ESCROW_KEY_ANASTASIS:
      if (GNUNET_YES == anastasis_initialized)
        return anastasis_api;
      anastasis_initialized = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Loading ANASTASIS escrow plugin\n");
      anastasis_api = GNUNET_PLUGIN_load ("libgnunet_plugin_escrow_anastasis",
                                          NULL);
      return anastasis_api;
  }
  // should never be reached
  return NULL;
}


/**
 * Put some data in escrow using the specified escrow method
 * 
 * @param ego the identity ego to put in escrow
 * @param method the escrow method to use
 * 
 * @return the escrow anchor needed to get the data back
 */
void *
GNUNET_ESCROW_put (const struct GNUNET_IDENTITY_Ego *ego,
                   enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = init_plugin (method);
  return api->start_key_escrow (ego);
}


/**
 * Renew the escrow of the data related to the given escrow anchor
 * 
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * 
 * @return the escrow anchor needed to get the data back
 */
void *
GNUNET_ESCROW_renew (void *escrowAnchor,
                     enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = init_plugin (method);
  return api->renew_key_escrow (escrowAnchor);
}


/**
 * Get the escrowed data back
 * 
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param egoName the name of the ego to get back
 * @param method the escrow method to use
 * 
 * @return a new identity ego restored from the escrow
 */
const struct GNUNET_IDENTITY_Ego *
GNUNET_ESCROW_get (void *escrowAnchor,
                   char *egoName,
                   enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = init_plugin (method);
  return api->restore_key (escrowAnchor, egoName);
}


/**
 * Verify the escrowed data
 * 
 * @param ego the identity ego that was put into escrow
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * 
 * @return GNUNET_ESCROW_VALID if the escrow could successfully by restored,
 *         GNUNET_ESCROW_RENEW_NEEDED if the escrow needs to be renewed,
 *         GNUNET_ESCROW_INVALID otherwise
 */
int
GNUNET_ESCROW_verify (const struct GNUNET_IDENTITY_Ego *ego,
                      void *escrowAnchor,
                      enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = init_plugin (method);
  return api->verify_key_escrow (ego, escrowAnchor);
}
