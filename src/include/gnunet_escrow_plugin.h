/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 GNUnet e.V.

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
 *
 * @file
 * Plugin API for escrow methods
 *
 * @defgroup escrow-plugin  escrow plugin API for escrow methods
 * @{
 */
#ifndef GNUNET_ESCROW_PLUGIN_H
#define GNUNET_ESCROW_PLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_escrow_lib.h"
#include "gnunet_identity_service.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Function called to start the escrow of the key
 * 
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the anchor needed to restore the key
 * @return GNUNET_OK if successful
 */
typedef int (*GNUNET_ESCROW_StartKeyEscrowFunction) (
  const struct GNUNET_IDENTITY_Ego *ego,
  void *escrowAnchor);

/**
 * Function called to renew the escrow of the key
 * 
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the anchor needed to restore the key
 * @return GNUNET_OK if successful
 */
typedef int (*GNUNET_ESCROW_RenewKeyEscrowFunction) (
  const struct GNUNET_IDENTITY_Ego *ego,
  void *escrowAnchor);


/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_ESCROW_KeyPluginFunctions
{
  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * Start key escrow
   */
  GNUNET_ESCROW_StartKeyEscrowFunction start_key_escrow;

  /**
   * Renew key escrow
   */
  GNUNET_ESCROW_RenewKeyEscrowFunction renew_key_escrow;
};


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */ /* end of group */
