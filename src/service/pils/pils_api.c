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
 * @file service/pils/pils_api.c
 * Peer Identity Lifecycle Service; the API for managing Peer Identities
 *
 * Peer Identity management
 *
 */
#include "platform.h"
//#include "gnunet_arm_service.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_pils_service.h"
#include "pils.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "pils-api", __VA_ARGS__)


/**
 * @brief A handle for the PILS service.
 */
struct GNUNET_PILS_Handle
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  GNUNET_PILS_PidChangeCallback pid_change_cb;
  void *pid_change_cb_cls;
  struct GNUNET_SCHEDULER_Task *reconnect_task;
  struct GNUNET_MQ_Handle *mq;
  // TODO
};


static void
handle_peer_id (void *cls, const struct GNUNET_PILS_PeerIdMessage *pid_msg)
{
  // TODO
}


static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  // TODO
}


/**
 * Try again to connect to peer identity lifecycle service
 *
 * @param cls the `struct GNUNET_PILS_Handle *`
 */
static void
reconnect (void *cls)
{
  struct GNUNET_PILS_Handle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] =
  {
    GNUNET_MQ_hd_fixed_size (peer_id,
                             GNUNET_MESSAGE_TYPE_PILS_PEER_ID,
                             struct GNUNET_PILS_PeerIdMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to peer identity lifecycle service.\n");
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connect (h->cfg, "pils", handlers, &mq_error_handler, h);
  if (NULL == h->mq)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect.\n");
    return;
  }
  // TODO
  //env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_PILS_START);
  //GNUNET_MQ_send (h->mq, env);
}


/**
 * @brief Connect to the PILS service
 *
 * @param cfg configuration to use
 * @param cls closer for the callbacks/handlers // FIXME
 * @param pid_change_cb handler/callback called once the peer id changes
 *
 * @return Handle to the PILS service
 */
struct GNUNET_PILS_Handle *
GNUNET_PILS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     void *cls,
                     GNUNET_PILS_PidChangeCallback pid_change_cb)
{
  struct GNUNET_PILS_Handle *h;

  h = GNUNET_new (struct GNUNET_PILS_Handle);
  h->cfg = cfg;
  h->pid_change_cb = pid_change_cb;
  h->pid_change_cb_cls = cls;
  reconnect (h);
  return h;
}



/**
 * @brief Disconnect from the PILS service
 *
 * @param handle handle to the PILS service (was returned by
 * #GNUNET_PILS_connect)
 */
void
GNUNET_PILS_disconnect (struct GNUNET_PILS_Handle *handle)
{
  GNUNET_assert (NULL != handle);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disonnecting from peer identity lifecycle service.\n");
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  if (NULL != handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }
  GNUNET_free (handle);
}


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
GNUNET_PILS_feed_addresses (const struct GNUNET_PILS_Handle *handle,
                            uint32_t num_addresses,
                            const char *address[static num_addresses]);

/* end of pils_api.c */

