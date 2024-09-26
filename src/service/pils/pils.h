/*
     This file is part of GNUnet.
     Copyright (C) 2024 GNUnet e.V.

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
 * @author ch3
 * @file service/pils/pils.h
 *
 * @brief Common type definitions for the peer identity lifecycle service and API.
 */
#ifndef PILS_H
#define PILS_H

#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * TODO
 */
struct GNUNET_PILS_PeerIdMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PILS_PEER_ID
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * TODO
   */
  struct GNUNET_PeerIdentity peer_id GNUNET_PACKED;

  /**
   * TODO
   */
  struct GNUNET_HashCode hash GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

#endif

