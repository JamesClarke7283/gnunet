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
 * @file service/pils/gnunet-service-pils.c
 * @brief peer identity lifecycle service
 * @author ch3
 *
 * TODO
 * //The purpose of this service is to estimate the size of the network.
 * //Given a specified interval, each peer hashes the most recent
 * //timestamp which is evenly divisible by that interval.  This hash is
 * //compared in distance to the peer identity to choose an offset.  The
 * //closer the peer identity to the hashed timestamp, the earlier the
 * //peer sends out a "nearest peer" message.  The closest peer's
 * //message should thus be received before any others, which stops
 * //those peer from sending their messages at a later duration.  So
 * //every peer should receive the same nearest peer message, and from
 * //this can calculate the expected number of peers in the network.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
//#include "gnunet_statistics_service.h"
//#include "gnunet_core_service.h"
#include "gnunet_pils_service.h"
#include "pils.h"


//GNUNET_NETWORK_STRUCT_BEGIN
//
///**
// * Network size estimate reply; sent when "this"
// * peer's timer has run out before receiving a
// * valid reply from another peer.
// */
//struct GNUNET_NSE_FloodMessage
//{
//  /**
//   * Type: #GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD
//   */
//  struct GNUNET_MessageHeader header;
//
//  /**
//   * Number of hops this message has taken so far.
//   */
//  uint32_t hop_count GNUNET_PACKED;
//
//  /**
//   * Purpose.
//   */
//  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
//
//  /**
//   * The current timestamp value (which all
//   * peers should agree on).
//   */
//  struct GNUNET_TIME_AbsoluteNBO timestamp;
//
//  /**
//   * Number of matching bits between the hash
//   * of timestamp and the initiator's public
//   * key.
//   */
//  uint32_t matching_bits GNUNET_PACKED;
//
//  /**
//   * Public key of the originator.
//   */
//  struct GNUNET_PeerIdentity origin;
//
//  /**
//   * Proof of work, causing leading zeros when hashed with pkey.
//   */
//  uint64_t proof_of_work GNUNET_PACKED;
//
//  /**
//   * Signature (over range specified in purpose).
//   */
//  struct GNUNET_CRYPTO_EddsaSignature signature;
//};
//GNUNET_NETWORK_STRUCT_END

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

///**
// * Handle to the statistics service.
// */
//static struct GNUNET_STATISTICS_Handle *stats;

///**
// * Handle to the core service.
// */
//static struct GNUNET_CORE_Handle *core_api;

///**
// * Map of all connected peers.
// */
//static struct GNUNET_CONTAINER_MultiPeerMap *peers;
//
///**
// * The current network size estimate.  Number of bits matching on
// * average thus far.
// */
//static double current_size_estimate;
//
///**
// * The standard deviation of the last #HISTORY_SIZE network
// * size estimates.
// */
//static double current_std_dev = NAN;
//
///**
// * Current hop counter estimate (estimate for network diameter).
// */
//static uint32_t hop_count_max;
//
///**
// * Message for the next round, if we got any.
// */
//static struct GNUNET_NSE_FloodMessage next_message;
//
///**
// * Array of recent size estimate messages.
// */
//static struct GNUNET_NSE_FloodMessage size_estimate_messages[HISTORY_SIZE];
//
///**
// * Index of most recent estimate.
// */
//static unsigned int estimate_index;
//
///**
// * Number of valid entries in the history.
// */
//static unsigned int estimate_count;
//
///**
// * Task scheduled to update our flood message for the next round.
// */
//static struct GNUNET_SCHEDULER_Task *flood_task;
//
///**
// * Task scheduled to compute our proof.
// */
//static struct GNUNET_SCHEDULER_Task *proof_task;
//
///**
// * Notification context, simplifies client broadcasts.
// */
//static struct GNUNET_NotificationContext *nc;
//
///**
// * The next major time.
// */
//static struct GNUNET_TIME_Absolute next_timestamp;
//
///**
// * The current major time.
// */
//static struct GNUNET_TIME_Absolute current_timestamp;
//
///**
// * The private key of this peer.
// */
//static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;
//
///**
// * The peer identity of this peer.
// */
//static struct GNUNET_PeerIdentity my_identity;
//
///**
// * Proof of work for this peer.
// */
//static uint64_t my_proof;


/**
 * Handler for START message from client, triggers an
 * immediate current network estimate notification.
 * Also, we remember the client for updates upon future
 * estimate measurements.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_start (void *cls, const struct GNUNET_MessageHeader *message)
{
  //struct GNUNET_SERVICE_Client *client = cls;
  //struct GNUNET_MQ_Handle *mq;
  //struct GNUNET_NSE_ClientMessage em;
  //struct GNUNET_MQ_Envelope *env;

  //(void) message;
  //GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received START message from client\n");
  //mq = GNUNET_SERVICE_client_get_mq (client);
  //GNUNET_notification_context_add (nc, mq);
  //setup_estimate_message (&em);
  //env = GNUNET_MQ_msg_copy (&em.header);
  //GNUNET_MQ_send (mq, env);
  //GNUNET_SERVICE_client_continue (client);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  //(void) cls;
  //if (NULL != flood_task)
  //{
  //  GNUNET_SCHEDULER_cancel (flood_task);
  //  flood_task = NULL;
  //}
  //if (NULL != proof_task)
  //{
  //  GNUNET_SCHEDULER_cancel (proof_task);
  //  proof_task = NULL;
  //  write_proof ();  /* remember progress */
  //}
  //if (NULL != nc)
  //{
  //  GNUNET_notification_context_destroy (nc);
  //  nc = NULL;
  //}
  //if (NULL != core_api)
  //{
  //  GNUNET_CORE_disconnect (core_api);
  //  core_api = NULL;
  //}
  //if (NULL != stats)
  //{
  //  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  //  stats = NULL;
  //}
  //if (NULL != peers)
  //{
  //  GNUNET_CONTAINER_multipeermap_destroy (peers);
  //  peers = NULL;
  //}
  //if (NULL != my_private_key)
  //{
  //  GNUNET_free (my_private_key);
  //  my_private_key = NULL;
  //}
}


/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *c,
                   struct GNUNET_MQ_Handle *mq)
{
  (void) cls;
  (void) mq;
  return c;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *c,
                      void *internal_cls)
{
  //(void) cls;
  //GNUNET_assert (c == internal_cls);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN ("pils",
                     GNUNET_SERVICE_OPTION_NONE,
                     &run,
                     &client_connect_cb,
                     &client_disconnect_cb,
                     NULL,
                     GNUNET_MQ_hd_fixed_size (start,
                                              GNUNET_MESSAGE_TYPE_PILS_START,
                                              struct GNUNET_MessageHeader,
                                              NULL),
                     GNUNET_MQ_handler_end ());


/* end of gnunet-service-pils.c */
