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
 *
 * @file
 * Escrow definitions
 *
 * @defgroup escrow escrow component
 * @{
 */
#ifndef GNUNET_ESCROW_LIB_H
#define GNUNET_ESCROW_LIB_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"


/**
 * Enum for the different key escrow methods
 */
enum GNUNET_ESCROW_Key_Escrow_Method {
  GNUNET_ESCROW_KEY_PLAINTEXT,
  GNUNET_ESCROW_KEY_GNS,
  GNUNET_ESCROW_KEY_ANASTASIS
};


/**
 * Put some data in escrow using the specified escrow method
 * 
 * @param ego the identity ego to put in escrow
 * @param method the escrow method to use
 * 
 * @return the escrow anchor needed to get the data back
 */
void *
GNUNET_ESCROW_put (
  const struct GNUNET_IDENTITY_Ego *ego,
  enum GNUNET_ESCROW_Key_Escrow_Method method);


/**
 * Renew the escrow of the data related to the given escrow anchor
 * 
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * 
 * @return the escrow anchor needed to get the data back
 */
void *
GNUNET_ESCROW_renew (
  void *escrowAnchor,
  enum GNUNET_ESCROW_Key_Escrow_Method method);


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
GNUNET_ESCROW_get (
  void *escrowAnchor,
  char *egoName,
  enum GNUNET_ESCROW_Key_Escrow_Method method);


/**
 * Verify the escrowed data
 * 
 * @param ego the identity ego that was put into escrow
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * 
 * @return GNUNET_OK if the escrow could successfully by restored
 */
int
GNUNET_ESCROW_verify (
  const struct GNUNET_IDENTITY_Ego *ego,
  void *escrowAnchor,
  enum GNUNET_ESCROW_Key_Escrow_Method method);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_ESCROW_LIB_H */
#endif

/** @} */ /* end of group escrow */

/* end of gnunet_escrow_lib.h */
