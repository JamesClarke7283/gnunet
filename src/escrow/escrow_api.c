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

#include "gnunet_escrow_lib.h"


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
  switch (method)
  {
    case GNUNET_ESCROW_KEY_PLAINTEXT:
      break;
    case GNUNET_ESCROW_KEY_GNS:
      break;
    case GNUNET_ESCROW_KEY_ANASTASIS:
      break;
  }
  return NULL;
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
  return NULL;
}


/**
 * Get the escrowed data back
 * 
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * 
 * @return a new identity ego restored from the escrow
 */
const struct GNUNET_IDENTITY_Ego *
GNUNET_ESCROW_get (void *escrowAnchor,
                   enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  return NULL;
}


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
GNUNET_ESCROW_verify (const struct GNUNET_IDENTITY_Ego *ego,
                      void *escrowAnchor,
                      enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  return GNUNET_NO;
}
