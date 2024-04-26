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
 *
 * @file include/gnunet_pils_service.h
 * Peer Identity Lifecycle Service; the API for managing Peer Identities
 *
 * Peer Identity management
 *
 */
#ifndef GNUNET_PILS_SERVICE_H
#define GNUNET_PILS_SERVICE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_util_lib.h"


/**
 * @brief A handler/callback to be called on the change of the peer id.
 *
 * TODO this might contain a reference (checksum, ...) to the addresses it was
 * based on in the future
 *
 * @param cls The closure given to #GNUNET_PILS_connect
 * @param peer_id The new peer id.
 * @param hash The hash of addresses the peer id is based on. This hash is also returned by #GNUNET_PILS_feed_address.
 */
typedef void (*GNUNET_PILS_PidChangeCallback) (
  struct void *cls,
  const struct GNUNET_PeerIdentity *peer_id,
  const struct GNUNET_HashCode *hash);


/**
 * @brief A handle for the PILS service.
 */
struct GNUNET_PILS_Handle;


/**
 * @brief Connect to the PILS service
 *
 * @param cfg configuration to use
 * @param cls closer for the callbacks/handlers
 * @param change_handler handler/callback called once the peer id changes
 *
 * @return Handle to the PILS service
 */
struct GNUNET_PILS_Handle *
GNUNET_PILS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     void *cls,
                     GNUNET_PILS_PidChangeCallback change_handler);



/**
 * @brief Disconnect from the PILS service
 *
 * @param handle handle to the PILS service (was returned by
 * #GNUNET_PILS_connect)
 */
void
GNUNET_PILS_disconnect (struct GNUNET_PILS_Handle *handle);


// TODO potentially provide function to update the change handler?


/**
 * @brief Sign data with the peer id
 *
 * TODO not sure whether this was the intended design from last meeting - this
 * is anyhow now following the design of #GNUNET_CRYPTO_sign_by_peer_identity
 *
 * @param handle handle to the PILS service
 * @param purpose what to sign (size, purpose and data)
 * @param sig where to write the signature
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
enum GNUNET_GenericReturnValue
GNUNET_PILS_sign_by_peer_identity (const struct GNUNET_PILS_Handle *handle,
                                   const struct
                                   GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                                   struct GNUNET_CRYPTO_EddsaSignature *sig);


/**
 * @brief Feed a set of addresses to pils so that it will generate a new peer
 * id based on the given set of addresses.
 *
 * THIS IS ONLY TO BE CALLED FROM CORE!
 *
 * The address representation will be canonicalized/sorted by pils before the
 * new peer id is generated.
 *
 * TODO potentially return a checksum or such, so that the caller can link the
 * 'job' to the 'outcome' (freshly generated peer id)
 * TODO pay attention to high frequency calling - kill previous requests
 *
 * @param handle the handle to the PILS service
 * @param num_addresses The number of addresses.
 * @param address Array of string representation of addresses.
 * @return hash over the given addresses - used to identify the corresponding
 *         peer id
 */
struct GNUNET_HashCode *
GNUNET_PILS_feed_address (const struct GNUNET_PILS_Handle *handle,
                          uint32_t num_addresses,
                          const char *address[static num_addresses]);

// TODO I don't remember did we also want to generate HELLOs here? I would
// weakly tend to do this in core

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PILS_SERVICE_H */
#endif

/* end of gnunet_pils_service.h */
