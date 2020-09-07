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
 * @file escrow/escrow_plugin.h
 * 
 * @brief helper functions for escrow plugins
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_escrow_plugin.h"
#include "escrow.h"


/**
 * Maintains the ego list for an escrow plugin.
 * This function is an implementation of GNUNET_IDENTITY_Callback.
 *
 * It is initially called for all egos and then again
 * whenever a ego's identifier changes or if it is deleted.  At the
 * end of the initial pass over all egos, the function is once called
 * with 'NULL' for 'ego'. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with 'GNUNET_IDENTITY_create' or 'GNUNET_IDENTITY_get',
 * this function is only called ONCE, and 'NULL' being passed in
 * 'ego' does indicate an error (i.e. name is taken or no default
 * value is known).  If 'ego' is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of 'GNUNET_IDENTITY_connect' (if
 * that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) ego but the NEW identifier.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the 'identifier'.  In this case,
 * the 'ego' is henceforth invalid (and the 'ctx' should also be
 * cleaned up).
 *
 * @param cls plugin handle
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
void
ESCROW_list_ego (void *cls,
                 struct GNUNET_IDENTITY_Ego *ego,
                 void **ctx,
                 const char *identifier);


/**
 * Cleanup the ego list of an escrow plugin.
 * 
 * @param ph handle for the plugin
 */
void
ESCROW_cleanup_ego_list (struct ESCROW_PluginHandle *ph);


/**
 * Build an anchor struct.
 * 
 * @param method escrow method
 * @param egoName name of the ego
 * @param data anchor data
 * @param data_size size of the anchor data
 * 
 * @return a new anchor struct
 */
struct GNUNET_ESCROW_Anchor *
ESCROW_build_anchor (enum GNUNET_ESCROW_Key_Escrow_Method method,
                     const char *egoName,
                     void *data,
                     uint32_t data_size);


/**
 * Update the status of an escrow in the configuration after a VERIFY operation.
 * 
 * @param h handle for the escrow component
 * @param ego the ego of which the escrow status is updated
 * @param plugin_name the name of the used plugin
 * 
 * @return GNUNET_OK on success
 */
int
ESCROW_update_escrow_status_verify (struct GNUNET_ESCROW_Handle *h,
                                    struct GNUNET_IDENTITY_Ego *ego,
                                    const char *plugin_name);


/**
 * Update the status of an escrow in the configuration after a PUT operation.
 * 
 * @param h handle for the escrow component
 * @param ego the ego of which the escrow status is updated
 * @param plugin_name the name of the used plugin
 * 
 * @return GNUNET_OK on success
 */
int
ESCROW_update_escrow_status_put (struct GNUNET_ESCROW_Handle *h,
                                 struct GNUNET_IDENTITY_Ego *ego,
                                 const char *plugin_name);


/**
 * Get the status of an escrow from the configuration.
 * 
 * @param h handle for the escrow component
 * @param ego the ego of which the escrow status has to be obtained
 * 
 * @return the status of the escrow, packed into a GNUNET_ESCROW_Status struct
 */
struct GNUNET_ESCROW_Status *
ESCROW_get_escrow_status (struct GNUNET_ESCROW_Handle *h,
                          struct GNUNET_IDENTITY_Ego *ego);
