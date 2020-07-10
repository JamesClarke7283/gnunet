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
 * @return the escrow anchor needed to restore the key
 */
typedef void *(*GNUNET_ESCROW_StartKeyEscrowFunction) (
  const struct GNUNET_IDENTITY_Ego *ego);

/**
 * Function called to renew the escrow of the key
 * 
 * @param escrowAnchor the the escrow anchor returned by the start method
 * @return the escrow anchor needed to restore the key
 */
typedef void *(*GNUNET_ESCROW_RenewKeyEscrowFunction) (
  void *escrowAnchor);

/**
 * Function called to verify the escrow of the key
 * 
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @return GNUNET_OK if verification is successful
 */
typedef int (*GNUNET_ESCROW_VerifyKeyEscrowFunction) (
  const struct GNUNET_IDENTITY_Ego *ego,
  void *escrowAnchor);

/**
 * Function called to restore a key from an escrow
 * 
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 * @return the identity ego containing the private key
 */
typedef const struct GNUNET_IDENTITY_Ego *(*GNUNET_ESCROW_RestoreKeyFunction) (
  void *escrowAnchor,
  char *egoName);


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

  /**
   * Verify key escrow
   */
  GNUNET_ESCROW_VerifyKeyEscrowFunction verify_key_escrow;

  /**
   * Restore key escrow
   */
  GNUNET_ESCROW_RestoreKeyFunction restore_key;
};


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */ /* end of group */
