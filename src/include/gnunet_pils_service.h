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


// TODO do functions besides the subscriptions need connect/disconnect
// functionality?

/**
 * @brief A handle for subscriptions for peer id changes
 */
struct GNUNET_PILS_SubscriptionHandle;

/**
 * @brief Obtain the current GNUNET_PeerIdentity
 *
 * @return The current PeerIdentity
 *
 * TODO the functionality is duplicate to the subscription. We could
 * simply leave this convenience method out.
 * TODO rather return a pointer?
 */
struct GNUNET_PeerIdentity
GNUNET_PILS_obtain_pid (void);



/**
 * @brief A handler to be called on the change of the peer id.
 *
 * @param peer_id The new peer id.
 */
typedef void (*GNUNET_PILS_PidChangeHandler) (
  const struct GNUNET_PeerIdentity *peer_id);


/**
 * @brief Subscribe for changes of the peer id.
 *
 * @param handler The handler to be called on the change to a new peer id.
 *
 * @return A handle to cancle the subscription
 */
struct GNUNET_PILS_SubscriptionHandle *
GNUNET_PILS_pid_change_subscribe (GNUNET_PILS_PidChangeHandler handler);

/**
 * @brief Cancle a subscription on peer id changes.
 *
 * @param h the handle to the subscription.
 */
GNUNET_PILS_pid_subscription_cancle (struct GNUNET_PILS_SubscriptionHandle *h);


/**
 * @brief Sign data with the peer id.
 *
 * This should only be used on small amounts of data - hashes if a bigger
 * amount of data is to be signed.
 * TODO build convenience function for larger amounts of data that takes care
 *      about the hashing?
 *
 * @param data Pointer to the data
 * @param size Size of the data to be signed in bytes
 *
 * @return The signature of the provided data
 * TODO rather return a pointer to the hash?
 * TODO what kind of signature to uses - is this the right kind?
 * TODO should ther be the possibility to provide more specifics? (hash
 *      algorithm, parameters, seeds, salts, ...?)
 */
struct GNUNET_CRYPTO_Signature
GNUNET_PILS_pid_sign (const char *data, uint32_t size);


/**
 * @brief Feed (an) address(es) to pils so that it will generate a new peer id
 * based on the given address(es).
 *
 * THIS IS ONLY TO BE CALLED FROM CORE!
 *
 * The address(es) will be canonicalized/sorted before the new peer id is
 * generated.
 *
 * @param num_addresses The number of addresses.
 * @param address Array of string representation of addresses.
 * TODO rather give a single array with a specified separator?
 *
 * @return #GNUNET_OK if a new peer id was generated, GNUNET_SYSERR otherwise
 * TODO will we need a more specific return value?
 */
enum GNUNET_GenericReturnValue
GNUNET_PILS_feed_address (uint32_t num_addresses,
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
