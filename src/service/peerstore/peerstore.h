/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

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
 * @file peerstore/peerstore.h
 * @brief IPC messages
 * @author Omar Tarabai
 */

#ifndef PEERSTORE_H_
#define PEERSTORE_H_

#include "gnunet_peerstore_service.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message carrying a PEERSTORE record message
 */
struct StoreRecordMessage
{
  /**
   * GNUnet message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_YES if peer id value set, #GNUNET_NO otherwise
   */
  uint16_t peer_set GNUNET_PACKED;

  /**
   * Size of the sub_system string
   * Allocated at position 0 after this struct
   */
  uint16_t sub_system_size GNUNET_PACKED;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Expiry time of entry
   */
  struct GNUNET_TIME_AbsoluteNBO expiry;

  /**
   * Size of the key string
   * Allocated at position 1 after this struct
   */
  uint16_t key_size GNUNET_PACKED;

  /**
   * Size of value blob
   * Allocated at position 2 after this struct
   */
  uint16_t value_size GNUNET_PACKED;

  /**
   * Request id.
   */
  uint32_t rid GNUNET_PACKED;

  /**
   * Options, needed only in case of a
   * store operation
   */
  uint32_t /* enum GNUNET_PEERSTORE_StoreOption */ options GNUNET_PACKED;

  /* Followed by key and value */
};

/**
 * Message carrying a PEERSTORE result message
 */
struct PeerstoreResultMessage
{
  /**
   * GNUnet message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Request id.
   */
  uint32_t rid GNUNET_PACKED;

  /**
   * Options, needed only in case of a
   * store operation
   */
  uint32_t result GNUNET_PACKED;

};

/**
 * Message carrying record key hash
 */
struct StoreKeyHashMessage
{
  /**
   * GNUnet message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Request id.
   */
  uint32_t rid GNUNET_PACKED;

  /**
   * Hash of a record key
   */
  struct GNUNET_HashCode keyhash;

};

GNUNET_NETWORK_STRUCT_END
#endif
