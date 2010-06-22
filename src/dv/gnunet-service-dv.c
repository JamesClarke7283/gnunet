/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file dv/gnunet-service-dv.c
 * @brief the distance vector service, primarily handles gossip of nearby
 * peers and sending/receiving DV messages from core and decapsulating
 * them
 *
 * @author Christian Grothoff
 * @author Nathan Evans
 *
 * TODO: The gossip rates need to be worked out.  Probably many other things
 * as well.
 *
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_signal_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_crypto_lib.h"
#include "dv.h"

/**
 * For testing mostly, remember only the
 * shortest path to a distant neighbor.
 */
#define AT_MOST_ONE GNUNET_NO

#define USE_PEER_ID GNUNET_YES

/**
 * DV Service Context stuff goes here...
 */

/**
 * Handle to the core service api.
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * The identity of our peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * The configuration for this service.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The scheduler for this service.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * How often do we check about sending out more peer information (if
 * we are connected to no peers previously).
 */
#define GNUNET_DV_DEFAULT_SEND_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 500000)

/**
 * How long do we wait at most between sending out information?
 */
#define GNUNET_DV_MAX_SEND_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 500000)

/**
 * How long can we have not heard from a peer and
 * still have it in our tables?
 */
#define GNUNET_DV_PEER_EXPIRATION_TIME GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 1000))

/**
 * Priority for gossip.
 */
#define GNUNET_DV_DHT_GOSSIP_PRIORITY (GNUNET_EXTREME_PRIORITY / 10)

/**
 * How often should we check if expiration time has elapsed for
 * some peer?
 */
#define GNUNET_DV_MAINTAIN_FREQUENCY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5))

/**
 * How long to allow a message to be delayed?
 */
#define DV_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5))

/**
 * Priority to use for DV data messages.
 */
#define DV_PRIORITY 0

/**
 * The cost to a direct neighbor.  We used to use 0, but 1 makes more sense.
 */
#define DIRECT_NEIGHBOR_COST 1

/**
 * The default number of direct connections to store in DV (max)
 */
#define DEFAULT_DIRECT_CONNECTIONS 50

/**
 * The default size of direct + extended peers in DV (max)
 */
#define DEFAULT_DV_SIZE 100

/**
 * The default fisheye depth, from how many hops away will
 * we keep peers?
 */
#define DEFAULT_FISHEYE_DEPTH 4

/**
 * The client, the DV plugin connected to us.  Hopefully
 * this client will never change, although if the plugin dies
 * and returns for some reason it may happen.
 */
static struct GNUNET_SERVER_Client * client_handle;

/**
 * Task to run when we shut down, cleaning up all our trash
 */
static GNUNET_SCHEDULER_TaskIdentifier cleanup_task;

static size_t default_dv_priority = 0;

static char *my_short_id;

/**
 * Linked list of messages to send to clients.
 */
struct PendingMessage
{
  /**
   * Pointer to next item in the list
   */
  struct PendingMessage *next;

  /**
   * Pointer to previous item in the list
   */
  struct PendingMessage *prev;

  /**
   * The PeerIdentity to send to
   */
  struct GNUNET_PeerIdentity recipient;

  /**
   * The result of message sending.
   */
  struct GNUNET_DV_SendResultMessage *send_result;

  /**
   * Message importance level.
   */
  unsigned int importance;

  /**
   * Size of message.
   */
  unsigned int msg_size;

  /**
   * How long to wait before sending message.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Actual message to be sent; // avoid allocation
   */
  const struct GNUNET_MessageHeader *msg; // msg = (cast) &pm[1]; // memcpy (&pm[1], data, len);

};

/**
 * Transmit handle to the plugin.
 */
static struct GNUNET_CONNECTION_TransmitHandle * plugin_transmit_handle;

/**
 * Head of DLL for client messages
 */
static struct PendingMessage *plugin_pending_head;

/**
 * Tail of DLL for client messages
 */
static struct PendingMessage *plugin_pending_tail;

/**
 * Handle to the peerinfo service
 */
static struct GNUNET_PEERINFO_Handle *peerinfo_handle;

/**
 * Transmit handle to core service.
 */
static struct GNUNET_CORE_TransmitHandle * core_transmit_handle;

/**
 * Head of DLL for core messages
 */
static struct PendingMessage *core_pending_head;

/**
 * Tail of DLL for core messages
 */
static struct PendingMessage *core_pending_tail;


struct FastGossipNeighborList
{
  /**
   * Next element of DLL
   */
  struct FastGossipNeighborList *next;

  /**
   * Prev element of DLL
   */
  struct FastGossipNeighborList *prev;

  /**
   * The neighbor to gossip about
   */
  struct DistantNeighbor *about;
};

/**
 * Context created whenever a direct peer connects to us,
 * used to gossip other peers to it.
 */
struct NeighborSendContext
{
  /**
   * The peer we will gossip to.
   */
  struct DirectNeighbor *toNeighbor;

  /**
   * The task associated with this context.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Head of DLL of peers to gossip about
   * as fast as possible to this peer, for initial
   * set up.
   */
  struct FastGossipNeighborList *fast_gossip_list_head;

  /**
   * Tail of DLL of peers to gossip about
   * as fast as possible to this peer, for initial
   * set up.
   */
  struct FastGossipNeighborList *fast_gossip_list_tail;

};


/**
 * Struct to hold information for updating existing neighbors
 */
struct NeighborUpdateInfo
{
  /**
   * Cost
   */
  unsigned int cost;

  /**
   * The existing neighbor
   */
  struct DistantNeighbor *neighbor;

  /**
   * The referrer of the possibly existing peer
   */
  struct DirectNeighbor *referrer;

  /**
   * The time we heard about this peer
   */
  struct GNUNET_TIME_Absolute now;

  /**
   * Peer id this peer uses to refer to neighbor.
   */
  unsigned int referrer_peer_id;

};

/**
 * Struct where actual neighbor information is stored,
 * referenced by min_heap and max_heap.  Freeing dealt
 * with when items removed from hashmap.
 */
struct DirectNeighbor
{
  /**
   * Identity of neighbor.
   */
  struct GNUNET_PeerIdentity identity;

  /**
   * PublicKey of neighbor.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;

  /**
   * Head of DLL of nodes that this direct neighbor referred to us.
   */
  struct DistantNeighbor *referee_head;

  /**
   * Tail of DLL of nodes that this direct neighbor referred to us.
   */
  struct DistantNeighbor *referee_tail;

  /**
   * The sending context for gossiping peers to this neighbor.
   */
  struct NeighborSendContext *send_context;

  /**
   * Is this one of the direct neighbors that we are "hiding"
   * from DV?
   */
  int hidden;
};


/**
 * Struct where actual neighbor information is stored,
 * referenced by min_heap and max_heap.  Freeing dealt
 * with when items removed from hashmap.
 */
struct DistantNeighbor
{
  /**
   * We keep distant neighbor's of the same referrer in a DLL.
   */
  struct DistantNeighbor *next;

  /**
   * We keep distant neighbor's of the same referrer in a DLL.
   */
  struct DistantNeighbor *prev;

  /**
   * Node in min heap
   */
  struct GNUNET_CONTAINER_HeapNode *min_loc;

  /**
   * Node in max heap
   */
  struct GNUNET_CONTAINER_HeapNode *max_loc;

  /**
   * Identity of referrer (next hop towards 'neighbor').
   */
  struct DirectNeighbor *referrer;

  /**
   * Identity of neighbor.
   */
  struct GNUNET_PeerIdentity identity;

  /**
   * PublicKey of neighbor.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pkey;

  /**
   * Last time we received routing information from this peer
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * Cost to neighbor, used for actual distance vector computations
   */
  unsigned int cost;

  /**
   * Random identifier *we* use for this peer, to be used as shortcut
   * instead of sending full peer id for each message
   */
  unsigned int our_id;

  /**
   * Random identifier the *referrer* uses for this peer.
   */
  unsigned int referrer_id;

  /**
   * Is this one of the direct neighbors that we are "hiding"
   * from DV?
   */
  int hidden;

};

struct PeerIteratorContext
{
  /**
   * The actual context, to be freed later.
   */
  struct GNUNET_PEERINFO_IteratorContext *ic;

  /**
   * The neighbor about which we are concerned.
   */
  struct DirectNeighbor *neighbor;

  /**
   * The distant neighbor entry for this direct neighbor.
   */
  struct DistantNeighbor *distant;

};

/**
 * Context used for creating hello messages when
 * gossips are received.
 */
struct HelloContext
{
  /**
   * Identity of distant neighbor.
   */
  struct GNUNET_PeerIdentity distant_peer;

  /**
   * Identity of direct neighbor, via which we send this message.
   */
  const struct GNUNET_PeerIdentity *direct_peer;

  /**
   * How many addresses do we need to add (always starts at 1, then set to 0)
   */
  int addresses_to_add;

};

struct DV_SendContext
{
  /**
   * The distant peer (should always match)
   */
  struct GNUNET_PeerIdentity *distant_peer;

  /**
   * The direct peer, we need to verify the referrer of.
   */
  struct GNUNET_PeerIdentity *direct_peer;

  /**
   * The message to be sent
   */
  struct GNUNET_MessageHeader *message;

  /**
   * The pre-built send result message.  Simply needs to be queued
   * and freed once send has been called!
   */
  struct GNUNET_DV_SendResultMessage *send_result;

  /**
   * The size of the message being sent, may be larger
   * than message->header.size because it's multiple
   * messages packed into one!
   */
  size_t message_size;

  /**
   * How important is this message?
   */
  unsigned int importance;

  /**
   * Timeout for this message
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Unique ID for DV message
   */
  unsigned int uid;
};


/**
 * Map of PeerIdentifiers to 'struct GNUNET_dv_neighbor*'s for all
 * directly connected peers.
 */
static struct GNUNET_CONTAINER_MultiHashMap *direct_neighbors;

/**
 * Map of PeerIdentifiers to 'struct GNUNET_dv_neighbor*'s for
 * peers connected via DV (extended neighborhood).  Does ALSO
 * include any peers that are in 'direct_neighbors'; for those
 * peers, the cost will be zero and the referrer all zeros.
 */
static struct GNUNET_CONTAINER_MultiHashMap *extended_neighbors;

/**
 * We use the min heap (min refers to cost) to prefer
 * gossipping about peers with small costs.
 */
static struct GNUNET_CONTAINER_Heap *neighbor_min_heap;

/**
 * We use the max heap (max refers to cost) for general
 * iterations over all peers and to remove the most costly
 * connection if we have too many.
 */
static struct GNUNET_CONTAINER_Heap *neighbor_max_heap;

static unsigned long long fisheye_depth;

static unsigned long long max_table_size;


struct FindDestinationContext
{
  unsigned int tid;
  struct DistantNeighbor *dest;
};

struct FindIDContext
{
  unsigned int tid;
  struct GNUNET_PeerIdentity *dest;
  const struct GNUNET_PeerIdentity *via;
};

struct DisconnectContext
{
  /**
   * Distant neighbor to get pid from.
   */
  struct DistantNeighbor *distant;

  /**
   * Direct neighbor that disconnected.
   */
  struct DirectNeighbor *direct;
};

/**
 * We've been given a target ID based on the random numbers that
 * we assigned to our DV-neighborhood.  Find the entry for the
 * respective neighbor.
 */
static int
find_destination (void *cls,
                  struct GNUNET_CONTAINER_HeapNode *node,
                  void *element, GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindDestinationContext *fdc = cls;
  struct DistantNeighbor *dn = element;

  if (fdc->tid != dn->our_id)
    return GNUNET_YES;
  fdc->dest = dn;
  return GNUNET_NO;
}


/**
 * We've been given a target ID based on the random numbers that
 * we assigned to our DV-neighborhood.  Find the entry for the
 * respective neighbor.
 */
static int
find_specific_id (void *cls,
                  const GNUNET_HashCode *key,
                  void *value)
{
  struct FindIDContext *fdc = cls;
  struct DistantNeighbor *dn = value;

  if (memcmp(&dn->referrer->identity, fdc->via, sizeof(struct GNUNET_PeerIdentity)) == 0)
    {
      fdc->tid = dn->referrer_id;
      return GNUNET_NO;
    }
  return GNUNET_YES;
}

/**
 * Find a distant peer whose referrer_id matches what we're
 * looking for.  For looking up a peer we've gossipped about
 * but is now disconnected.  Need to do this because we don't
 * want to remove those that may be accessible via a different
 * route.
 */
static int find_distant_peer (void *cls,
                              const GNUNET_HashCode * key,
                              void *value)
{
  struct FindDestinationContext *fdc = cls;
  struct DistantNeighbor *distant = value;

  if (fdc->tid == distant->referrer_id)
    {
      fdc->dest = distant;
      return GNUNET_NO;
    }
  return GNUNET_YES;
}

/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
size_t transmit_to_plugin (void *cls,
                           size_t size, void *buf)
{
  char *cbuf = buf;
  struct PendingMessage *reply;
  size_t off;
  size_t msize;

  if (buf == NULL)
    {
      /* client disconnected */
#if DEBUG_DV
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s': buffer was NULL\n", "DHT");
#endif
      return 0;
    }
  plugin_transmit_handle = NULL;
  off = 0;
  while ( (NULL != (reply = plugin_pending_head)) &&
          (size >= off + (msize = ntohs (reply->msg->size))))
    {
#if DEBUG_DV
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "`%s' : transmit_notify (plugin) called with size %d\n", "dv service", msize);
#endif
      GNUNET_CONTAINER_DLL_remove (plugin_pending_head,
                                   plugin_pending_tail,
                                   reply);
      memcpy (&cbuf[off], reply->msg, msize);
      GNUNET_free (reply);
      off += msize;
    }

  if (plugin_pending_head != NULL)
    plugin_transmit_handle = GNUNET_SERVER_notify_transmit_ready (client_handle,
                                                                  ntohs(plugin_pending_head->msg->size),
                                                                  GNUNET_TIME_UNIT_FOREVER_REL,
                                                                  &transmit_to_plugin, NULL);

  return off;
}

/**
 * Send a message to the dv plugin.
 *
 * @param sender the direct sender of the message
 * @param message the message to send to the plugin
 *        (may be an encapsulated type)
 * @param message_size the size of the message to be sent
 * @param distant_neighbor the original sender of the message
 * @param cost the cost to the original sender of the message
 */
void send_to_plugin(const struct GNUNET_PeerIdentity * sender,
                    const struct GNUNET_MessageHeader *message,
                    size_t message_size,
                    struct GNUNET_PeerIdentity *distant_neighbor,
                    size_t cost)
{
  struct GNUNET_DV_MessageReceived *received_msg;
  struct PendingMessage *pending_message;
#if DEBUG_DV
  struct GNUNET_MessageHeader * packed_message_header;
  struct GNUNET_HELLO_Message *hello_msg;
  struct GNUNET_PeerIdentity hello_identity;
#endif
  char *sender_address;
  size_t sender_address_len;
  char *packed_msg_start;
  int size;

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "send_to_plugin called with peer %s as sender\n", GNUNET_i2s(distant_neighbor));
#endif

  if (memcmp(sender, distant_neighbor, sizeof(struct GNUNET_PeerIdentity)) != 0)
  {
    sender_address_len = sizeof(struct GNUNET_PeerIdentity) * 2;
    sender_address = GNUNET_malloc(sender_address_len);
    memcpy(sender_address, distant_neighbor, sizeof(struct GNUNET_PeerIdentity));
    memcpy(&sender_address[sizeof(struct GNUNET_PeerIdentity)], sender, sizeof(struct GNUNET_PeerIdentity));
  }
  else
  {
    sender_address_len = sizeof(struct GNUNET_PeerIdentity);
    sender_address = GNUNET_malloc(sender_address_len);
    memcpy(sender_address, sender, sizeof(struct GNUNET_PeerIdentity));
  }

  size = sizeof(struct GNUNET_DV_MessageReceived) + sender_address_len + message_size;
  received_msg = GNUNET_malloc(size);
  received_msg->header.size = htons(size);
  received_msg->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_DV_RECEIVE);
  received_msg->sender_address_len = htonl(sender_address_len);
  received_msg->distance = htonl(cost);
  received_msg->msg_len = htonl(message_size);
  /* Set the sender in this message to be the original sender! */
  memcpy(&received_msg->sender, distant_neighbor, sizeof(struct GNUNET_PeerIdentity));
  /* Copy the intermediate sender to the end of the message, this is how the transport identifies this peer */
  memcpy(&received_msg[1], sender_address, sender_address_len);
  GNUNET_free(sender_address);
  /* Copy the actual message after the sender */
  packed_msg_start = (char *)&received_msg[1];
  packed_msg_start = &packed_msg_start[sender_address_len];
  memcpy(packed_msg_start, message, message_size);
#if DEBUG_DV
  packed_message_header = (struct GNUNET_MessageHeader *)packed_msg_start;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "dv service created received message. sender_address_len %lu, packed message len %d, total len %d\n", sender_address_len, ntohl(received_msg->msg_len), ntohs(received_msg->header.size));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "dv packed message len %d, type %d\n", ntohs(packed_message_header->size), ntohs(packed_message_header->type));
  if (ntohs(packed_message_header->type) == GNUNET_MESSAGE_TYPE_HELLO)
  {
    hello_msg = (struct GNUNET_HELLO_Message *)packed_message_header;
    GNUNET_assert(GNUNET_OK == GNUNET_HELLO_get_id(hello_msg, &hello_identity));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Packed HELLO message is about peer %s\n", GNUNET_i2s(&hello_identity));
  }
#endif
  pending_message = GNUNET_malloc(sizeof(struct PendingMessage) + size);
  pending_message->msg = (struct GNUNET_MessageHeader *)&pending_message[1];
  memcpy(&pending_message[1], received_msg, size);
  GNUNET_free(received_msg);

  GNUNET_CONTAINER_DLL_insert_after(plugin_pending_head, plugin_pending_tail, plugin_pending_tail, pending_message);

  if (client_handle != NULL)
    {
      if (plugin_transmit_handle == NULL)
        {
          plugin_transmit_handle = GNUNET_SERVER_notify_transmit_ready (client_handle,
                                                                        size, GNUNET_TIME_UNIT_FOREVER_REL,
                                                                        &transmit_to_plugin, NULL);
        }
#if DEBUG_DV
      else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to queue message for plugin, must be one in progress already!!\n");
        }
#endif
    }
}


/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
size_t core_transmit_notify (void *cls,
                             size_t size, void *buf)
{
  char *cbuf = buf;
  struct PendingMessage *reply;
  struct PendingMessage *client_reply;
  size_t off;
  size_t msize;

  if (buf == NULL)
    {
      /* client disconnected */
#if DEBUG_DV
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s': buffer was NULL\n", "DHT");
#endif
      return 0;
    }

  core_transmit_handle = NULL;
  off = 0;
  reply = core_pending_head;
  if ( (reply != NULL) &&
          (size >= (msize = ntohs (reply->msg->size))))
    {
#if DEBUG_DV
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "`%s' : transmit_notify (core) called with size %d\n", "dv service", msize);
#endif
      GNUNET_CONTAINER_DLL_remove (core_pending_head,
                                   core_pending_tail,
                                   reply);
      if (reply->send_result != NULL) /* Will only be non-null if a real client asked for this send */
        {
          client_reply = GNUNET_malloc(sizeof(struct PendingMessage) + sizeof(struct GNUNET_DV_SendResultMessage));
          client_reply->msg = (struct GNUNET_MessageHeader *)&client_reply[1];
          memcpy(&client_reply[1], reply->send_result, sizeof(struct GNUNET_DV_SendResultMessage));
          GNUNET_free(reply->send_result);

          GNUNET_CONTAINER_DLL_insert_after(plugin_pending_head, plugin_pending_tail, plugin_pending_tail, client_reply);
          if (client_handle != NULL)
            {
              if (plugin_transmit_handle == NULL)
                {
                  plugin_transmit_handle = GNUNET_SERVER_notify_transmit_ready (client_handle,
                                                                                sizeof(struct GNUNET_DV_SendResultMessage),
                                                                                GNUNET_TIME_UNIT_FOREVER_REL,
                                                                                &transmit_to_plugin, NULL);
                }
              else
                {
                  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to queue message for plugin, must be one in progress already!!\n");
                }
            }
        }
      memcpy (&cbuf[off], reply->msg, msize);
      GNUNET_free (reply);
      off += msize;
    }
  reply = core_pending_head;
  if (reply != NULL)
    core_transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, reply->importance, reply->timeout, &reply->recipient, reply->msg_size, &core_transmit_notify, NULL);

  return off;
}


/**
 * Send a DV data message via DV.
 *
 * @param sender the original sender of the message
 * @param recipient the next hop recipient, may be our direct peer, maybe not
 * @param send_context the send context
 */
static int
send_message_via (const struct GNUNET_PeerIdentity *sender,
                  const struct GNUNET_PeerIdentity *recipient,
                  struct DV_SendContext *send_context)
{
  p2p_dv_MESSAGE_Data *toSend;
  unsigned int msg_size;
  unsigned int recipient_id;
  unsigned int sender_id;
  struct DistantNeighbor *source;
  struct PendingMessage *pending_message;
  struct FindIDContext find_context;
#if DEBUG_DV
  char shortname[5];
#endif

  msg_size = send_context->message_size + sizeof (p2p_dv_MESSAGE_Data);

  find_context.dest = send_context->distant_peer;
  find_context.via = recipient;
  find_context.tid = 0;
  //specific_neighbor = GNUNET_CONTAINER_multihashmap_get(extended_neighbors, &send_context->distant_peer->hashPubKey);

  //GNUNET_CONTAINER_multihashmap_iterate(extended_neighbors, &find_specific_id, &find_context);
  GNUNET_CONTAINER_multihashmap_get_multiple (extended_neighbors, &send_context->distant_peer->hashPubKey,
                                              &find_specific_id, &find_context);

  if (find_context.tid == 0)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s: find_specific_id failed to find peer!\n", my_short_id);
      /* target unknown to us, drop! */
      return GNUNET_SYSERR;
    }
  recipient_id = find_context.tid;

  if (0 == (memcmp (&my_identity,
                        sender, sizeof (struct GNUNET_PeerIdentity))))
  {
    sender_id = 0;
    source = GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                                    &sender->hashPubKey);
    if (source != NULL)
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s: send_message_via found %s, myself in extended peer list???\n", my_short_id, GNUNET_i2s(&source->identity));
  }
  else
  {
    source = GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                                &sender->hashPubKey);
    if (source == NULL)
      {
              /* sender unknown to us, drop! */
        return GNUNET_SYSERR;
      }
    sender_id = source->our_id;
  }

  pending_message = GNUNET_malloc(sizeof(struct PendingMessage) + msg_size);
  pending_message->msg = (struct GNUNET_MessageHeader *)&pending_message[1];
  pending_message->send_result = send_context->send_result;
  memcpy(&pending_message->recipient, recipient, sizeof(struct GNUNET_PeerIdentity));
  pending_message->msg_size = msg_size;
  pending_message->importance = send_context->importance;
  pending_message->timeout = send_context->timeout;
  toSend = (p2p_dv_MESSAGE_Data *)pending_message->msg;
  toSend->header.size = htons (msg_size);
  toSend->header.type = htons (GNUNET_MESSAGE_TYPE_DV_DATA);
  toSend->sender = htonl (sender_id);
  toSend->recipient = htonl (recipient_id);
#if DEBUG_DV_MESSAGES
  toSend->uid = send_context->uid; /* Still sent around in network byte order */
#else
  toSend->uid = htonl(0);
#endif

  memcpy (&toSend[1], send_context->message, send_context->message_size);

#if DEBUG_DV
  memcpy(&shortname, GNUNET_i2s(send_context->distant_peer), 4);
  shortname[4] = '\0';
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: Notifying core of send to destination `%s' via `%s' size %u\n", "DV", &shortname, GNUNET_i2s(recipient), msg_size);
#endif

  GNUNET_CONTAINER_DLL_insert_after (core_pending_head,
                                     core_pending_tail,
                                     core_pending_tail,
                                     pending_message);

  if (core_transmit_handle == NULL)
    core_transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, send_context->importance, send_context->timeout, recipient, msg_size, &core_transmit_notify, NULL);
  else
    {
#if DEBUG_DV
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "`%s': Failed to schedule pending transmission (must be one in progress!)\n", "dv service");
#endif
    }
  return GNUNET_YES;
}


/**
 * Context for finding the least cost peer to send to.
 * Transport selection can only go so far.
 */
struct FindLeastCostContext
{
  struct DistantNeighbor *target;
  unsigned int least_cost;
};


/**
 * Given a FindLeastCostContext, and a set
 * of peers that match the target, return the cheapest.
 *
 * @param cls closure, a struct FindLeastCostContext
 * @param key the key identifying the target peer
 * @param value the target peer
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int
find_least_cost_peer (void *cls,
                  const GNUNET_HashCode *key,
                  void *value)
{
  struct FindLeastCostContext *find_context = cls;
  struct DistantNeighbor *dn = value;

  if (dn->cost < find_context->least_cost)
    {
      find_context->target = dn;
    }
  if (dn->cost == DIRECT_NEIGHBOR_COST)
    return GNUNET_NO;
  return GNUNET_YES;
}

/**
 * Send a DV data message via DV.
 *
 * @param recipient the ultimate recipient of this message
 * @param sender the original sender of the message
 * @param specific_neighbor the specific neighbor to send this message via
 * @param message the packed message
 * @param message_size size of the message
 * @param importance what priority to send this message with
 * @param timeout how long to possibly delay sending this message
 */
static int
send_message (const struct GNUNET_PeerIdentity * recipient,
              const struct GNUNET_PeerIdentity * sender,
              const struct DistantNeighbor * specific_neighbor,
              const struct GNUNET_MessageHeader * message,
              size_t message_size,
              unsigned int importance,
              unsigned int uid,
              struct GNUNET_TIME_Relative timeout)
{
  p2p_dv_MESSAGE_Data *toSend;
  unsigned int msg_size;
  unsigned int cost;
  unsigned int recipient_id;
  unsigned int sender_id;
  struct DistantNeighbor *target;
  struct DistantNeighbor *source;
  struct PendingMessage *pending_message;
  struct FindLeastCostContext find_least_ctx;
#if DEBUG_DV_PEER_NUMBERS
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeerFrom;
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeerTo;
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeerVia;
#endif
  msg_size = message_size + sizeof (p2p_dv_MESSAGE_Data);

  find_least_ctx.least_cost = -1;
  find_least_ctx.target = NULL;
  /*
   * Need to find the least cost peer, lest the transport selection keep
   * picking the same DV route for the same destination which results
   * in messages looping forever.  Relatively cheap, we don't iterate
   * over all known peers, just those that apply.
   */
  GNUNET_CONTAINER_multihashmap_get_multiple (extended_neighbors,
                                                       &recipient->hashPubKey,  &find_least_cost_peer, &find_least_ctx);
  target = find_least_ctx.target;

  if (target == NULL)
    {
      /* target unknown to us, drop! */
      return GNUNET_SYSERR;
    }
  recipient_id = target->referrer_id;

  source = GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                      &sender->hashPubKey);
  if (source == NULL)
    {
      if (0 != (memcmp (&my_identity,
                        sender, sizeof (struct GNUNET_PeerIdentity))))
        {
          /* sender unknown to us, drop! */
          return GNUNET_SYSERR;
        }
      sender_id = 0;            /* 0 == us */
    }
  else
    {
      /* find out the number that we use when we gossip about
         the sender */
      sender_id = source->our_id;
    }

#if DEBUG_DV_PEER_NUMBERS
  GNUNET_CRYPTO_hash_to_enc (&source->identity.hashPubKey, &encPeerFrom);
  GNUNET_CRYPTO_hash_to_enc (&target->referrer->identity.hashPubKey, &encPeerVia);
  encPeerFrom.encoding[4] = '\0';
  encPeerVia.encoding[4] = '\0';
#endif
  if ((sender_id != 0) && (0 == memcmp(&source->identity, &target->referrer->identity, sizeof(struct GNUNET_PeerIdentity))))
    {
      return 0;
    }

  cost = target->cost;
  pending_message = GNUNET_malloc(sizeof(struct PendingMessage) + msg_size);
  pending_message->msg = (struct GNUNET_MessageHeader *)&pending_message[1];
  pending_message->send_result = NULL;
  pending_message->importance = importance;
  pending_message->timeout = timeout;
  memcpy(&pending_message->recipient, &target->referrer->identity, sizeof(struct GNUNET_PeerIdentity));
  pending_message->msg_size = msg_size;
  toSend = (p2p_dv_MESSAGE_Data *)pending_message->msg;
  toSend->header.size = htons (msg_size);
  toSend->header.type = htons (GNUNET_MESSAGE_TYPE_DV_DATA);
  toSend->sender = htonl (sender_id);
  toSend->recipient = htonl (recipient_id);
#if DEBUG_DV_MESSAGES
  toSend->uid = htonl(uid);
#else
  toSend->uid = htonl(0);
#endif

#if DEBUG_DV_PEER_NUMBERS
  GNUNET_CRYPTO_hash_to_enc (&target->identity.hashPubKey, &encPeerTo);
  encPeerTo.encoding[4] = '\0';
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: Sending DATA message. Sender id %u, source %s, destination %s, via %s\n", GNUNET_i2s(&my_identity), sender_id, &encPeerFrom, &encPeerTo, &encPeerVia);
#endif
  memcpy (&toSend[1], message, message_size);
  GNUNET_CONTAINER_DLL_insert_after (core_pending_head,
                                     core_pending_tail,
                                     core_pending_tail,
                                     pending_message);
#if DEBUG_DV
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: Notifying core of send size %d to destination `%s'\n", "DV SEND MESSAGE", msg_size, GNUNET_i2s(recipient));
#endif
  if (core_transmit_handle == NULL)
    core_transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, importance, timeout, &target->referrer->identity, msg_size, &core_transmit_notify, NULL);
  else
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: CORE ALREADY SENDING\n", "DV SEND MESSAGE", msg_size);
  return (int) cost;
}

#if USE_PEER_ID
struct CheckPeerContext
{
  /**
   * Peer we found
   */
  struct DistantNeighbor *peer;

  /**
   * Sender id to search for
   */
  unsigned int sender_id;
};

/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
int checkPeerID (void *cls,
                 const GNUNET_HashCode * key,
                 void *value)
{
  struct CheckPeerContext *ctx = cls;
  struct DistantNeighbor *distant = value;

  if (memcmp(key, &ctx->sender_id, sizeof(unsigned int)) == 0)
  {
    ctx->peer = distant;
    return GNUNET_NO;
  }
  return GNUNET_YES;

}
#endif

/**
 * Core handler for dv data messages.  Whatever this message
 * contains all we really have to do is rip it out of its
 * DV layering and give it to our pal the DV plugin to report
 * in with.
 *
 * @param cls closure
 * @param peer peer which sent the message (immediate sender)
 * @param message the message
 * @param latency the latency of the connection we received the message from
 * @param distance the distance to the immediate peer
 */
static int handle_dv_data_message (void *cls,
                             const struct GNUNET_PeerIdentity * peer,
                             const struct GNUNET_MessageHeader * message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance)
{
  const p2p_dv_MESSAGE_Data *incoming = (const p2p_dv_MESSAGE_Data *) message;
  const struct GNUNET_MessageHeader *packed_message;
  struct DirectNeighbor *dn;
  struct DistantNeighbor *pos;
  unsigned int sid;             /* Sender id */
  unsigned int tid;             /* Target id */
  struct GNUNET_PeerIdentity original_sender;
  struct GNUNET_PeerIdentity destination;
  struct FindDestinationContext fdc;
#if USE_PEER_ID
  struct CheckPeerContext checkPeerCtx;
#endif
  char *sender_id;
  char *direct_id;
  int ret;
  size_t packed_message_size;
  char *cbuf;
  size_t offset;

  packed_message_size = ntohs(incoming->header.size) - sizeof(p2p_dv_MESSAGE_Data);


#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives DATA message from %s size %d, packed size %d!\n", my_short_id, GNUNET_i2s(peer) , ntohs(incoming->header.size), packed_message_size);
#endif

  if (ntohs (incoming->header.size) <  sizeof (p2p_dv_MESSAGE_Data) + sizeof (struct GNUNET_MessageHeader))
    {

#if DEBUG_DV
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "`%s': Message sizes don't add up, total size %u, expected at least %u!\n", "dv service", ntohs(incoming->header.size), sizeof (p2p_dv_MESSAGE_Data) + sizeof (struct GNUNET_MessageHeader));
#endif
      return GNUNET_SYSERR;
    }

  dn = GNUNET_CONTAINER_multihashmap_get (direct_neighbors,
                                  &peer->hashPubKey);
  if (dn == NULL)
    {
#if DEBUG_DV
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: dn NULL!\n", "dv");
#endif
      return GNUNET_OK;
    }
  sid = ntohl (incoming->sender);
#if USE_PEER_ID
  if (sid != 0)
  {
    checkPeerCtx.sender_id = sid;
    checkPeerCtx.peer = NULL;
    GNUNET_CONTAINER_multihashmap_iterate(extended_neighbors, &checkPeerID, &checkPeerCtx);
    pos = checkPeerCtx.peer;
  }
  else
  {
    pos = GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                             &peer->hashPubKey);
  }
#else
  pos = dn->referee_head;
  while ((NULL != pos) && (pos->referrer_id != sid))
    pos = pos->next;
#endif

  if (pos == NULL)
    {
      direct_id = GNUNET_strdup(GNUNET_i2s(&dn->identity));
#if DEBUG_DV
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: unknown sender (%u), Message from %s!\n", GNUNET_i2s(&my_identity), ntohl(incoming->sender), direct_id);
#endif
      GNUNET_free(direct_id);
      pos = dn->referee_head;
      while ((NULL != pos) && (pos->referrer_id != sid))
      {
        sender_id = strdup(GNUNET_i2s(&pos->identity));
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "I know sender %u %s\n", pos->referrer_id, sender_id);
        GNUNET_free(sender_id);
        pos = pos->next;
      }

#if DEBUG_MESSAGE_DROP
      direct_id = GNUNET_strdup(GNUNET_i2s(&dn->identity));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: DROPPING MESSAGE type %d, unknown sender! Message immediately from %s!\n", GNUNET_i2s(&my_identity), ntohs(((struct GNUNET_MessageHeader *)&incoming[1])->type), direct_id);
      GNUNET_free(direct_id);
#endif
      /* unknown sender */
      return GNUNET_OK;
    }
  original_sender = pos->identity;
  tid = ntohl (incoming->recipient);
  if (tid == 0)
    {
      /* 0 == us */
      cbuf = (char *)&incoming[1];
      offset = 0;
      while(offset < packed_message_size)
        {
          packed_message = (struct GNUNET_MessageHeader *)&cbuf[offset];

#if DEBUG_DV_MESSAGES
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "%s: Receives %s message for me, uid %u, size %d type %d, cost %u from %s!\n", my_short_id, "DV DATA", ntohl(incoming->uid), ntohs(packed_message->size), ntohs(packed_message->type), pos->cost, GNUNET_i2s(&pos->identity));
#endif
          GNUNET_break_op (ntohs (packed_message->type) != GNUNET_MESSAGE_TYPE_DV_GOSSIP);
          GNUNET_break_op (ntohs (packed_message->type) != GNUNET_MESSAGE_TYPE_DV_DATA);
          if ( (ntohs (packed_message->type) != GNUNET_MESSAGE_TYPE_DV_GOSSIP) &&
              (ntohs (packed_message->type) != GNUNET_MESSAGE_TYPE_DV_DATA) )
          {
            GNUNET_assert(memcmp(peer, &pos->identity, sizeof(struct GNUNET_PeerIdentity)) != 0);
            send_to_plugin(peer, packed_message, ntohs(packed_message->size), &pos->identity, pos->cost);
          }
          offset += ntohs(packed_message->size);
        }

      return GNUNET_OK;
    }
  else
    {
      packed_message = (struct GNUNET_MessageHeader *)&incoming[1];
    }

  /* FIXME: this is the *only* per-request operation we have in DV
     that is O(n) in relation to the number of connected peers; a
     hash-table lookup could easily solve this (minor performance
     issue) */
  fdc.tid = tid;
  fdc.dest = NULL;
  GNUNET_CONTAINER_heap_iterate (neighbor_max_heap,
                                 &find_destination, &fdc);

#if DEBUG_DV
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: Receives %s message for someone else!\n", "dv", "DV DATA");
#endif

  if (fdc.dest == NULL)
    {
#if DEBUG_DV_MESSAGES
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: Receives %s message uid %u for someone we don't know (id %u)!\n", my_short_id, "DV DATA", ntohl(incoming->uid), tid);
#endif
    return GNUNET_OK;
    }
  destination = fdc.dest->identity;

  if (0 == memcmp (&destination, peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      /* FIXME: create stat: routing loop-discard! */
#if DEBUG_DV_PEER_NUMBERS
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "\n\n\nLoopy loo message\n\n\n");
#endif

#if DEBUG_DV_MESSAGES
      direct_id = GNUNET_strdup(GNUNET_i2s(&dn->identity));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: DROPPING MESSAGE uid %u type %d, routing loop! Message immediately from %s!\n", my_short_id, ntohl(incoming->uid), ntohs(packed_message->type), direct_id);
#endif
      return GNUNET_OK;
    }

  /* At this point we have a message, and we need to forward it on to the
   * next DV hop.
   */
  /* FIXME: Can't send message on, we have to behave.
   * We have to tell core we have a message for the next peer, and let
   * transport do transport selection on how to get this message to 'em */
  /*ret = send_message (&destination,
                      &original_sender,
                      packed_message, DV_PRIORITY, DV_DELAY);*/

#if DEBUG_DV_MESSAGES
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: FORWARD %s message for %s, uid %u, size %d type %d, cost %u!\n", my_short_id, "DV DATA", GNUNET_i2s(&destination), ntohl(incoming->uid), ntohs(packed_message->size), ntohs(packed_message->type), pos->cost);
#endif

  ret = send_message(&destination,
                     &original_sender,
                     NULL,
                     packed_message,
                     packed_message_size,
                     default_dv_priority,
                     ntohl(incoming->uid),
                     GNUNET_TIME_relative_get_forever());

  if (ret != GNUNET_SYSERR)
    return GNUNET_OK;
  else
    {
#if DEBUG_MESSAGE_DROP
      direct_id = GNUNET_strdup(GNUNET_i2s(&dn->identity));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: DROPPING MESSAGE type %d, forwarding failed! Message immediately from %s!\n", GNUNET_i2s(&my_identity), ntohs(((struct GNUNET_MessageHeader *)&incoming[1])->type), direct_id);
#endif
      return GNUNET_SYSERR;
    }
}

#if DEBUG_DV
/**
 * Iterator over hash map entries.
 *
 * @param cls closure (NULL)
 * @param key current key code
 * @param value value in the hash map (DistantNeighbor)
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
int print_neighbors (void *cls,
                     const GNUNET_HashCode * key,
                     void *value)
{
  struct DistantNeighbor *distant_neighbor = value;
  char my_shortname[5];
  char referrer_shortname[5];
  memcpy(&my_shortname, GNUNET_i2s(&my_identity), 4);
  my_shortname[4] = '\0';
  memcpy(&referrer_shortname, GNUNET_i2s(&distant_neighbor->referrer->identity), 4);
  referrer_shortname[4] = '\0';

  GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "`%s' %s: Peer `%s', distance %d, referrer `%s' pkey: %s\n", &my_shortname, "DV", GNUNET_i2s(&distant_neighbor->identity), distant_neighbor->cost, &referrer_shortname, distant_neighbor->pkey == NULL ? "no" : "yes");
  return GNUNET_YES;
}
#endif

/**
 *  Scheduled task which gossips about known direct peers to other connected
 *  peers.  Will run until called with reason shutdown.
 */
static void
neighbor_send_task (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighborSendContext *send_context = cls;
#if DEBUG_DV_GOSSIP_SEND
  char * encPeerAbout;
  char * encPeerTo;
#endif
  struct DistantNeighbor *about;
  struct DirectNeighbor *to;
  struct FastGossipNeighborList *about_list;

  p2p_dv_MESSAGE_NeighborInfo *message;
  struct PendingMessage *pending_message;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
#if DEBUG_DV_GOSSIP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Called with reason shutdown, shutting down!\n",
              GNUNET_i2s(&my_identity));
#endif
    return;
  }

  if (send_context->fast_gossip_list_head != NULL)
    {
      about_list = send_context->fast_gossip_list_head;
      about = about_list->about;
      GNUNET_CONTAINER_DLL_remove(send_context->fast_gossip_list_head,
                                  send_context->fast_gossip_list_tail,
                                  about_list);
      GNUNET_free(about_list);
    }
  else
    {
      /* FIXME: this may become a problem, because the heap walk has only one internal "walker".  This means
       * that if two neighbor_send_tasks are operating in lockstep (which is quite possible, given default
       * values for all connected peers) there may be a serious bias as to which peers get gossiped about!
       * Probably the *best* way to fix would be to have an opaque pointer to the walk position passed as
       * part of the walk_get_next call.  Then the heap would have to keep a list of walks, or reset the walk
       * whenever a modification has been detected.  Yuck either way.  Perhaps we could iterate over the heap
       * once to get a list of peers to gossip about and gossip them over time... But then if one goes away
       * in the mean time that becomes nasty.  For now we'll just assume that the walking is done
       * asynchronously enough to avoid major problems (-;
       *
       * NOTE: probably fixed once we decided send rate based on allowed bandwidth.
       */
      about = GNUNET_CONTAINER_heap_walk_get_next (neighbor_min_heap);
    }
  to = send_context->toNeighbor;

  if ((about != NULL) && (to != about->referrer /* split horizon */ ) &&
#if SUPPORT_HIDING
      (about->hidden == GNUNET_NO) &&
#endif
      (to != NULL) &&
      (0 != memcmp (&about->identity,
                        &to->identity, sizeof (struct GNUNET_PeerIdentity))) &&
      (about->pkey != NULL))
    {
#if DEBUG_DV_GOSSIP_SEND
      encPeerAbout = GNUNET_strdup(GNUNET_i2s(&about->identity));
      encPeerTo = GNUNET_strdup(GNUNET_i2s(&to->identity));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: Sending info about peer %s id %u to directly connected peer %s\n",
                  GNUNET_i2s(&my_identity),
                  encPeerAbout, about->our_id, encPeerTo);
      GNUNET_free(encPeerAbout);
      GNUNET_free(encPeerTo);
#endif
      pending_message = GNUNET_malloc(sizeof(struct PendingMessage) + sizeof(p2p_dv_MESSAGE_NeighborInfo));
      pending_message->msg = (struct GNUNET_MessageHeader *)&pending_message[1];
      pending_message->importance = default_dv_priority;
      pending_message->timeout = GNUNET_TIME_relative_get_forever();
      memcpy(&pending_message->recipient, &to->identity, sizeof(struct GNUNET_PeerIdentity));
      pending_message->msg_size = sizeof(p2p_dv_MESSAGE_NeighborInfo);
      message = (p2p_dv_MESSAGE_NeighborInfo *)pending_message->msg;
      message->header.size = htons (sizeof (p2p_dv_MESSAGE_NeighborInfo));
      message->header.type = htons (GNUNET_MESSAGE_TYPE_DV_GOSSIP);
      message->cost = htonl (about->cost);
      message->neighbor_id = htonl (about->our_id);

      memcpy (&message->pkey, about->pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
      memcpy (&message->neighbor,
              &about->identity, sizeof (struct GNUNET_PeerIdentity));

      GNUNET_CONTAINER_DLL_insert_after (core_pending_head,
                                         core_pending_tail,
                                         core_pending_tail,
                                         pending_message);

      if (core_transmit_handle == NULL)
        core_transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, default_dv_priority, GNUNET_TIME_relative_get_forever(), &to->identity, sizeof(p2p_dv_MESSAGE_NeighborInfo), &core_transmit_notify, NULL);

    }

  if (send_context->fast_gossip_list_head != NULL) /* If there are other peers in the fast list, schedule right away */
    {
#if DEBUG_DV_PEER_NUMBERS
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "DV SERVICE: still in fast send mode\n");
#endif
      send_context->task = GNUNET_SCHEDULER_add_now(sched, &neighbor_send_task, send_context);
    }
  else
    {
#if DEBUG_DV_PEER_NUMBERS
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "DV SERVICE: entering slow send mode\n");
#endif
      send_context->task = GNUNET_SCHEDULER_add_delayed(sched, GNUNET_DV_DEFAULT_SEND_INTERVAL, &neighbor_send_task, send_context);
    }

  return;
}


/**
 * Handle START-message.  This is the first message sent to us
 * by the client (can only be one!).
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_start (void *cls,
              struct GNUNET_SERVER_Client *client,
              const struct GNUNET_MessageHeader *message)
{

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' request from client\n", "START");
#endif

  client_handle = client;

  GNUNET_SERVER_client_keep(client_handle);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

#if UNSIMPLER
/**
 * Iterate over hash map entries for a distant neighbor,
 * if direct neighbor matches context call send message
 *
 * @param cls closure, a DV_SendContext
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
int send_iterator (void *cls,
                   const GNUNET_HashCode * key,
                   void *value)
{
  struct DV_SendContext *send_context = cls;
  struct DistantNeighbor *distant_neighbor = value;

  if (memcmp(distant_neighbor->referrer, send_context->direct_peer, sizeof(struct GNUNET_PeerIdentity)) == 0) /* They match, send and free */
    {
      send_message_via(&my_identity, distant_neighbor, send_context);
      return GNUNET_NO;
    }
  return GNUNET_YES;
}
#endif

/**
 * Service server's handler for message send requests (which come
 * bubbling up to us through the DV plugin).
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
void handle_dv_send_message (void *cls,
                             struct GNUNET_SERVER_Client * client,
                             const struct GNUNET_MessageHeader * message)
{
  struct GNUNET_DV_SendMessage *send_msg;
  struct GNUNET_DV_SendResultMessage *send_result_msg;
  struct PendingMessage *pending_message;
  size_t address_len;
  size_t message_size;
  struct GNUNET_PeerIdentity *destination;
  struct GNUNET_PeerIdentity *direct;
  struct GNUNET_MessageHeader *message_buf;
  char *temp_pos;
  int offset;
  static struct GNUNET_CRYPTO_HashAsciiEncoded dest_hash;
  struct DV_SendContext *send_context;
#if DEBUG_DV_MESSAGES
  char *cbuf;
  struct GNUNET_MessageHeader *packed_message;
#endif

  if (client_handle == NULL)
  {
    client_handle = client;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Setting initial client handle, never received `%s' message?\n", "dv", "START");
  }
  else if (client_handle != client)
  {
    client_handle = client;
    /* What should we do in this case, assert fail or just log the warning? */
#if DEBUG_DV
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: Setting client handle (was a different client!)!\n", "dv");
#endif
  }

  GNUNET_assert(ntohs(message->size) > sizeof(struct GNUNET_DV_SendMessage));
  send_msg = (struct GNUNET_DV_SendMessage *)message;

  address_len = ntohl(send_msg->addrlen);
  GNUNET_assert(address_len == sizeof(struct GNUNET_PeerIdentity) * 2);
  message_size = ntohl(send_msg->msgbuf_size);

  GNUNET_assert(ntohs(message->size) == sizeof(struct GNUNET_DV_SendMessage) + address_len + message_size);
  destination = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
  direct = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
  message_buf = GNUNET_malloc(message_size);

  temp_pos = (char *)&send_msg[1]; /* Set pointer to end of message */
  offset = 0; /* Offset starts at zero */

  memcpy(destination, &temp_pos[offset], sizeof(struct GNUNET_PeerIdentity));
  offset += sizeof(struct GNUNET_PeerIdentity);

  memcpy(direct, &temp_pos[offset], sizeof(struct GNUNET_PeerIdentity));
  offset += sizeof(struct GNUNET_PeerIdentity);


  memcpy(message_buf, &temp_pos[offset], message_size);
  if (memcmp(&send_msg->target, destination, sizeof(struct GNUNET_PeerIdentity)) != 0)
    {
      GNUNET_CRYPTO_hash_to_enc (&destination->hashPubKey, &dest_hash); /* GNUNET_i2s won't properly work, need to hash one ourselves */
      dest_hash.encoding[4] = '\0';
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s: asked to send message to `%s', but address is for `%s'!", "DV SERVICE", GNUNET_i2s(&send_msg->target), (const char *)&dest_hash.encoding);
    }

#if DEBUG_DV_MESSAGES
  cbuf = (char *)message_buf;
  offset = 0;
  while(offset < message_size)
    {
      packed_message = (struct GNUNET_MessageHeader *)&cbuf[offset];
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: DV PLUGIN SEND uid %u type %d to %s\n", my_short_id, ntohl(send_msg->uid), ntohs(packed_message->type), GNUNET_i2s(destination));
      offset += ntohs(packed_message->size);
    }
  /*GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: DV PLUGIN SEND uid %u type %d to %s\n", my_short_id, ntohl(send_msg->uid), ntohs(message_buf->type), GNUNET_i2s(destination));*/
#endif
  GNUNET_CRYPTO_hash_to_enc (&destination->hashPubKey, &dest_hash); /* GNUNET_i2s won't properly work, need to hash one ourselves */
  dest_hash.encoding[4] = '\0';
  send_context = GNUNET_malloc(sizeof(struct DV_SendContext));

  send_result_msg = GNUNET_malloc(sizeof(struct GNUNET_DV_SendResultMessage));
  send_result_msg->header.size = htons(sizeof(struct GNUNET_DV_SendResultMessage));
  send_result_msg->header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND_RESULT);
  send_result_msg->uid = send_msg->uid; /* No need to ntohl->htonl this */

  send_context->importance = ntohl(send_msg->priority);
  send_context->timeout = send_msg->timeout;
  send_context->direct_peer = direct;
  send_context->distant_peer = destination;
  send_context->message = message_buf;
  send_context->message_size = message_size;
  send_context->send_result = send_result_msg;
#if DEBUG_DV_MESSAGES
  send_context->uid = send_msg->uid;
#endif

  if (send_message_via(&my_identity, direct, send_context) != GNUNET_YES)
    {
      send_result_msg->result = htons(1);
      pending_message = GNUNET_malloc(sizeof(struct PendingMessage) + sizeof(struct GNUNET_DV_SendResultMessage));
      pending_message->msg = (struct GNUNET_MessageHeader *)&pending_message[1];
      memcpy(&pending_message[1], send_result_msg, sizeof(struct GNUNET_DV_SendResultMessage));
      GNUNET_free(send_result_msg);

      GNUNET_CONTAINER_DLL_insert_after(plugin_pending_head, plugin_pending_tail, plugin_pending_tail, pending_message);

      if (client_handle != NULL)
        {
          if (plugin_transmit_handle == NULL)
            {
              plugin_transmit_handle = GNUNET_SERVER_notify_transmit_ready (client_handle,
                                                                            sizeof(struct GNUNET_DV_SendResultMessage),
                                                                            GNUNET_TIME_UNIT_FOREVER_REL,
                                                                            &transmit_to_plugin, NULL);
            }
          else
            {
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to queue message for plugin, must be one in progress already!!\n");
            }
        }
      GNUNET_CRYPTO_hash_to_enc (&destination->hashPubKey, &dest_hash); /* GNUNET_i2s won't properly work, need to hash one ourselves */
      dest_hash.encoding[4] = '\0';
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s DV SEND failed to send message to destination `%s' via `%s'\n", my_short_id, (const char *)&dest_hash.encoding, GNUNET_i2s(direct));
    }

  /* In bizarro world GNUNET_SYSERR indicates that we succeeded */
#if UNSIMPLER
  if (GNUNET_SYSERR != GNUNET_CONTAINER_multihashmap_get_multiple(extended_neighbors, &destination->hashPubKey, &send_iterator, send_context))
    {
      send_result_msg->result = htons(1);
      pending_message = GNUNET_malloc(sizeof(struct PendingMessage) + sizeof(struct GNUNET_DV_SendResultMessage));
      pending_message->msg = (struct GNUNET_MessageHeader *)&pending_message[1];
      memcpy(&pending_message[1], send_result_msg, sizeof(struct GNUNET_DV_SendResultMessage));
      GNUNET_free(send_result_msg);

      GNUNET_CONTAINER_DLL_insert_after(plugin_pending_head, plugin_pending_tail, plugin_pending_tail, pending_message);

      if (client_handle != NULL)
        {
          if (plugin_transmit_handle == NULL)
            {
              plugin_transmit_handle = GNUNET_SERVER_notify_transmit_ready (client_handle,
                                                                            sizeof(struct GNUNET_DV_SendResultMessage),
                                                                            GNUNET_TIME_UNIT_FOREVER_REL,
                                                                            &transmit_to_plugin, NULL);
            }
          else
            {
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to queue message for plugin, must be one in progress already!!\n");
            }
        }
      GNUNET_CRYPTO_hash_to_enc (&destination->hashPubKey, &dest_hash); /* GNUNET_i2s won't properly work, need to hash one ourselves */
      dest_hash.encoding[4] = '\0';
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s DV SEND failed to send message to destination `%s' via `%s'\n", my_short_id, (const char *)&dest_hash.encoding, GNUNET_i2s(direct));
    }
#endif
  GNUNET_free(message_buf);
  GNUNET_free(send_context);
  GNUNET_free(direct);
  GNUNET_free(destination);

  GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

/** Forward declarations **/
static int handle_dv_gossip_message (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader *message,
                                     struct GNUNET_TIME_Relative latency,
                                     uint32_t distance);

static int handle_dv_disconnect_message (void *cls,
                                         const struct GNUNET_PeerIdentity *peer,
                                         const struct GNUNET_MessageHeader *message,
                                         struct GNUNET_TIME_Relative latency,
                                         uint32_t distance);
/** End forward declarations **/


/**
 * List of handlers for the messages understood by this
 * service.
 *
 * Hmm... will we need to register some handlers with core and
 * some handlers with our server here?  Because core should be
 * getting the incoming DV messages (from whichever lower level
 * transport) and then our server should be getting messages
 * from the dv_plugin, right?
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_dv_data_message, GNUNET_MESSAGE_TYPE_DV_DATA, 0},
  {&handle_dv_gossip_message, GNUNET_MESSAGE_TYPE_DV_GOSSIP, 0},
  {&handle_dv_disconnect_message, GNUNET_MESSAGE_TYPE_DV_DISCONNECT, 0},
  {NULL, 0, 0}
};

static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&handle_dv_send_message, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND, 0},
  {&handle_start, NULL, GNUNET_MESSAGE_TYPE_DV_START, 0},
  {NULL, NULL, 0, 0}
};

/**
 * Free a DistantNeighbor node, including removing it
 * from the referer's list.
 */
static void
distant_neighbor_free (struct DistantNeighbor *referee)
{
  struct DirectNeighbor *referrer;

  referrer = referee->referrer;
  if (referrer != NULL)
    {
      GNUNET_CONTAINER_DLL_remove (referrer->referee_head,
                         referrer->referee_tail, referee);
    }
  GNUNET_CONTAINER_heap_remove_node (neighbor_max_heap, referee->max_loc);
  GNUNET_CONTAINER_heap_remove_node (neighbor_min_heap, referee->min_loc);
  GNUNET_CONTAINER_multihashmap_remove_all (extended_neighbors,
                                    &referee->identity.hashPubKey);
  GNUNET_free_non_null (referee->pkey);
  GNUNET_free (referee);
}

/**
 * Free a DirectNeighbor node, including removing it
 * from the referer's list.
 */
static void
direct_neighbor_free (struct DirectNeighbor *direct)
{
  struct NeighborSendContext *send_context;
  struct FastGossipNeighborList *about_list;
  struct FastGossipNeighborList *prev_about;

  send_context = direct->send_context;

  if (send_context->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(sched, send_context->task);

  about_list = send_context->fast_gossip_list_head;
  while (about_list != NULL)
    {
      GNUNET_CONTAINER_DLL_remove(send_context->fast_gossip_list_head, send_context->fast_gossip_list_tail, about_list);
      prev_about = about_list;
      about_list = about_list->next;
      GNUNET_free(prev_about);
    }
  GNUNET_free(send_context);
  GNUNET_free(direct);
}

/**
 * Multihashmap iterator for sending out disconnect messages
 * for a peer.
 *
 * @param cls the peer that was disconnected
 * @param key key value stored under
 * @param value the direct neighbor to send disconnect to
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int schedule_disconnect_messages (void *cls,
                                    const GNUNET_HashCode * key,
                                    void *value)
{
  struct DisconnectContext *disconnect_context = cls;
  struct DirectNeighbor *disconnected = disconnect_context->direct;
  struct DirectNeighbor *notify = value;
  struct PendingMessage *pending_message;
  p2p_dv_MESSAGE_Disconnect *disconnect_message;

  if (memcmp(&notify->identity, &disconnected->identity, sizeof(struct GNUNET_PeerIdentity)) == 0)
    return GNUNET_YES; /* Don't send disconnect message to peer that disconnected! */

  pending_message = GNUNET_malloc(sizeof(struct PendingMessage) + sizeof(p2p_dv_MESSAGE_Disconnect));
  pending_message->msg = (struct GNUNET_MessageHeader *)&pending_message[1];
  pending_message->importance = default_dv_priority;
  pending_message->timeout = GNUNET_TIME_relative_get_forever();
  memcpy(&pending_message->recipient, &notify->identity, sizeof(struct GNUNET_PeerIdentity));
  pending_message->msg_size = sizeof(p2p_dv_MESSAGE_Disconnect);
  disconnect_message = (p2p_dv_MESSAGE_Disconnect *)pending_message->msg;
  disconnect_message->header.size = htons (sizeof (p2p_dv_MESSAGE_Disconnect));
  disconnect_message->header.type = htons (GNUNET_MESSAGE_TYPE_DV_DISCONNECT);
  disconnect_message->peer_id = htonl(disconnect_context->distant->our_id);

  GNUNET_CONTAINER_DLL_insert_after (core_pending_head,
                                     core_pending_tail,
                                     core_pending_tail,
                                     pending_message);

  if (core_transmit_handle == NULL)
    core_transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, default_dv_priority, GNUNET_TIME_relative_get_forever(), &notify->identity, sizeof(p2p_dv_MESSAGE_Disconnect), &core_transmit_notify, NULL);

  return GNUNET_YES;
}

/**
 * Multihashmap iterator for freeing extended neighbors.
 *
 * @param cls NULL
 * @param key key value stored under
 * @param value the distant neighbor to be freed
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int free_extended_neighbors (void *cls,
                                    const GNUNET_HashCode * key,
                                    void *value)
{
  struct DistantNeighbor *distant = value;
  distant_neighbor_free(distant);
  return GNUNET_YES;
}

/**
 * Multihashmap iterator for freeing direct neighbors.
 *
 * @param cls NULL
 * @param key key value stored under
 * @param value the direct neighbor to be freed
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int free_direct_neighbors (void *cls,
                                    const GNUNET_HashCode * key,
                                    void *value)
{
  struct DirectNeighbor *direct = value;
  direct_neighbor_free(direct);
  return GNUNET_YES;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#if DEBUG_DV
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "calling CORE_DISCONNECT\n");
  GNUNET_CONTAINER_multihashmap_iterate(extended_neighbors, &print_neighbors, NULL);
#endif
  GNUNET_CONTAINER_multihashmap_iterate(extended_neighbors, &free_extended_neighbors, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(extended_neighbors);
  GNUNET_CONTAINER_multihashmap_iterate(direct_neighbors, &free_direct_neighbors, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(direct_neighbors);

  GNUNET_CONTAINER_heap_destroy(neighbor_max_heap);
  GNUNET_CONTAINER_heap_destroy(neighbor_min_heap);

  GNUNET_CORE_disconnect (coreAPI);
  GNUNET_PEERINFO_disconnect(peerinfo_handle);

  GNUNET_free_non_null(my_short_id);
#if DEBUG_DV
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "CORE_DISCONNECT completed\n");
#endif
}

/**
 * To be called on core init/fail.
 */
void core_init (void *cls,
                struct GNUNET_CORE_Handle * server,
                const struct GNUNET_PeerIdentity *identity,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded * publicKey)
{

  if (server == NULL)
    {
      GNUNET_SCHEDULER_cancel(sched, cleanup_task);
      GNUNET_SCHEDULER_add_now(sched, &shutdown_task, NULL);
      return;
    }
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Core connection initialized, I am peer: %s\n", "dv", GNUNET_i2s(identity));
#endif
  memcpy(&my_identity, identity, sizeof(struct GNUNET_PeerIdentity));
  my_short_id = GNUNET_strdup(GNUNET_i2s(&my_identity));
  coreAPI = server;
}


#if PKEY_NO_NEIGHBOR_ON_ADD
/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int add_pkey_to_extended (void *cls,
                                 const GNUNET_HashCode * key,
                                 void *value)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pkey = cls;
  struct DistantNeighbor *distant_neighbor = value;

  if (distant_neighbor->pkey == NULL)
  {
    distant_neighbor->pkey = GNUNET_malloc(sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
    memcpy(distant_neighbor->pkey, pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  }

  return GNUNET_YES;
}
#endif

/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int update_matching_neighbors (void *cls,
                                      const GNUNET_HashCode * key,
                                      void *value)
{
  struct NeighborUpdateInfo * update_info = cls;
  struct DistantNeighbor *distant_neighbor = value;

  if (update_info->referrer == distant_neighbor->referrer) /* Direct neighbor matches, update it's info and return GNUNET_NO */
  {
    /* same referrer, cost change! */
    GNUNET_CONTAINER_heap_update_cost (neighbor_max_heap,
                                       update_info->neighbor->max_loc, update_info->cost);
    GNUNET_CONTAINER_heap_update_cost (neighbor_min_heap,
                                       update_info->neighbor->min_loc, update_info->cost);
    update_info->neighbor->last_activity = update_info->now;
    update_info->neighbor->cost = update_info->cost;
    update_info->neighbor->referrer_id = update_info->referrer_peer_id;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


/**
 * Iterate over all current direct peers, add DISTANT newly connected
 * peer to the fast gossip list for that peer so we get DV routing
 * information out as fast as possible!
 *
 * @param cls the newly connected neighbor we will gossip about
 * @param key the hashcode of the peer
 * @param value the direct neighbor we should gossip to
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO otherwise
 */
static int add_distant_all_direct_neighbors (void *cls,
                                     const GNUNET_HashCode * key,
                                     void *value)
{
  struct DirectNeighbor *direct = (struct DirectNeighbor *)value;
  struct DistantNeighbor *distant = (struct DistantNeighbor *)cls;
  struct NeighborSendContext *send_context = direct->send_context;
  struct FastGossipNeighborList *gossip_entry;
#if DEBUG_DV
  char *encPeerAbout;
  char *encPeerTo;
#endif

  if (distant == NULL)
    {
      return GNUNET_YES;
    }

  if (memcmp(&direct->identity, &distant->identity, sizeof(struct GNUNET_PeerIdentity)) == 0)
    {
      return GNUNET_YES; /* Don't gossip to a peer about itself! */
    }

#if SUPPORT_HIDING
  if (distant->hidden == GNUNET_YES)
    return GNUNET_YES; /* This peer should not be gossipped about (hidden) */
#endif
  gossip_entry = GNUNET_malloc(sizeof(struct FastGossipNeighborList));
  gossip_entry->about = distant;

  GNUNET_CONTAINER_DLL_insert_after(send_context->fast_gossip_list_head,
                                    send_context->fast_gossip_list_tail,
                                    send_context->fast_gossip_list_tail,
                                    gossip_entry);
#if DEBUG_DV
  encPeerAbout = GNUNET_strdup(GNUNET_i2s(&distant->identity));
  encPeerTo = GNUNET_strdup(GNUNET_i2s(&direct->identity));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: Fast send info about peer %s id %u for directly connected peer %s\n",
             GNUNET_i2s(&my_identity),
             encPeerAbout, distant->our_id, encPeerTo);
  GNUNET_free(encPeerAbout);
  GNUNET_free(encPeerTo);
#endif
  /*if (send_context->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(sched, send_context->task);*/

  send_context->task = GNUNET_SCHEDULER_add_now(sched, &neighbor_send_task, send_context);
  return GNUNET_YES;
}

/**
 * Handles when a peer is either added due to being newly connected
 * or having been gossiped about, also called when the cost for a neighbor
 * needs to be updated.
 *
 * @param peer identity of the peer whose info is being added/updated
 * @param pkey public key of the peer whose info is being added/updated
 * @param referrer_peer_id id to use when sending to 'peer'
 * @param referrer if this is a gossiped peer, who did we hear it from?
 * @param cost the cost of communicating with this peer via 'referrer'
 *
 * @return the added neighbor, the updated neighbor or NULL (neighbor
 *         not added)
 */
static struct DistantNeighbor *
addUpdateNeighbor (const struct GNUNET_PeerIdentity * peer, struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pkey,
                   unsigned int referrer_peer_id,
                   struct DirectNeighbor *referrer, unsigned int cost)
{
  struct DistantNeighbor *neighbor;
  struct DistantNeighbor *max;
  struct GNUNET_TIME_Absolute now;
  struct NeighborUpdateInfo *neighbor_update;
  unsigned int our_id;

#if DEBUG_DV_PEER_NUMBERS
  char *encAbout;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s Received sender id (%u)!\n", "DV SERVICE", referrer_peer_id);
#endif

  now = GNUNET_TIME_absolute_get ();
  neighbor = GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                                &peer->hashPubKey);
  neighbor_update = GNUNET_malloc(sizeof(struct NeighborUpdateInfo));
  neighbor_update->neighbor = neighbor;
  neighbor_update->cost = cost;
  neighbor_update->now = now;
  neighbor_update->referrer = referrer;
  neighbor_update->referrer_peer_id = referrer_peer_id;

  if (neighbor != NULL)
    {
#if USE_PEER_ID
      memcpy(&our_id, &neighbor->identity, sizeof(unsigned int));
#else
      our_id = neighbor->our_id;
#endif
    }
  else
    {
#if USE_PEER_ID
      memcpy(&our_id, peer, sizeof(unsigned int));
#else
      our_id = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, RAND_MAX - 1) + 1;
#endif
    }

  /* Either we do not know this peer, or we already do but via a different immediate peer */
  if ((neighbor == NULL) ||
      (GNUNET_CONTAINER_multihashmap_get_multiple(extended_neighbors,
                                                  &peer->hashPubKey,
                                                  &update_matching_neighbors,
                                                  neighbor_update) != GNUNET_SYSERR))
    {

#if AT_MOST_ONE
    if ((neighbor != NULL) && (cost < neighbor->cost)) /* New cost is less than old, remove old */
      {
        distant_neighbor_free(neighbor);
      }
    else if (neighbor != NULL) /* Only allow one DV connection to each peer */
      {
        return NULL;
      }
#endif
      /* new neighbor! */
      if (cost > fisheye_depth)
        {
          /* too costly */
          GNUNET_free(neighbor_update);
          return NULL;
        }

#if DEBUG_DV_PEER_NUMBERS
      encAbout = GNUNET_strdup(GNUNET_i2s(peer));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: %s Chose NEW id (%u) for peer %s!\n", GNUNET_i2s(&my_identity), "DV SERVICE", our_id, encAbout);
      GNUNET_free(encAbout);
#endif

      if (max_table_size <=
          GNUNET_CONTAINER_multihashmap_size (extended_neighbors))
        {
          /* remove most expensive entry */
          max = GNUNET_CONTAINER_heap_peek (neighbor_max_heap);
          GNUNET_assert(max != NULL);
          if (cost > max->cost)
            {
              /* new entry most expensive, don't create */
              GNUNET_free(neighbor_update);
              return NULL;
            }
          if (max->cost > 1)
            {
              /* only free if this is not a direct connection;
                 we could theoretically have more direct
                 connections than DV entries allowed total! */
              distant_neighbor_free (max);
            }
        }

      neighbor = GNUNET_malloc (sizeof (struct DistantNeighbor));
      GNUNET_CONTAINER_DLL_insert (referrer->referee_head,
                         referrer->referee_tail, neighbor);
      neighbor->max_loc = GNUNET_CONTAINER_heap_insert (neighbor_max_heap,
                                                        neighbor, cost);
      neighbor->min_loc = GNUNET_CONTAINER_heap_insert (neighbor_min_heap,
                                                        neighbor, cost);
      neighbor->referrer = referrer;
      memcpy (&neighbor->identity, peer, sizeof (struct GNUNET_PeerIdentity));
      if (pkey != NULL) /* pkey will be null on direct neighbor addition */
      {
        neighbor->pkey = GNUNET_malloc(sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
        memcpy (neighbor->pkey, pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
      }
      else
        neighbor->pkey = pkey;

      neighbor->last_activity = now;
      neighbor->cost = cost;
      neighbor->referrer_id = referrer_peer_id;
      neighbor->our_id = our_id;
      neighbor->hidden =
        (cost == DIRECT_NEIGHBOR_COST) ? (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 4) ==
                       0) : GNUNET_NO;

      GNUNET_CONTAINER_multihashmap_put (extended_neighbors, &peer->hashPubKey,
                                 neighbor,
                                 GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

    }
  else
    {
#if DEBUG_DV_GOSSIP
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: Already know peer %s distance %d, referrer id %d!\n", "dv", GNUNET_i2s(peer), cost, referrer_peer_id);
#endif
    }
#if DEBUG_DV
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: Size of extended_neighbors is %d\n", "dv", GNUNET_CONTAINER_multihashmap_size(extended_neighbors));
#endif

  GNUNET_free(neighbor_update);
  return neighbor;
}


static size_t
generate_hello_address (void *cls, size_t max, void *buf)
{
  struct HelloContext *hello_context = cls;
  char *addr_buffer;
  size_t offset;
  size_t size;
  size_t ret;
  char *addr1;
  char *addr2;

  if (hello_context->addresses_to_add == 0)
    return 0;

  /* Hello "address" will be concatenation of distant peer and direct peer identities */
  size = 2 * sizeof(struct GNUNET_PeerIdentity);
  GNUNET_assert(max >= size);

  addr_buffer = GNUNET_malloc(size);
  offset = 0;
  /* Copy the distant peer identity to buffer */
  memcpy(addr_buffer, &hello_context->distant_peer, sizeof(struct GNUNET_PeerIdentity));
  offset += sizeof(struct GNUNET_PeerIdentity);
  /* Copy the direct peer identity to buffer */
  memcpy(&addr_buffer[offset], hello_context->direct_peer, sizeof(struct GNUNET_PeerIdentity));
  addr1 = GNUNET_strdup(GNUNET_i2s(hello_context->direct_peer));
  addr2 = GNUNET_strdup(GNUNET_i2s(&hello_context->distant_peer));
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: GIVING HELLO %s%s%s to TRANSPORT\n", my_short_id,my_short_id, addr1, addr2);
  GNUNET_free(addr1);
  GNUNET_free(addr2);
  ret = GNUNET_HELLO_add_address ("dv",
                                  GNUNET_TIME_relative_to_absolute
                                  (GNUNET_TIME_UNIT_HOURS), addr_buffer, size,
                                  buf, max);

  hello_context->addresses_to_add--;

  GNUNET_free(addr_buffer);
  return ret;
}


/**
 * Core handler for dv disconnect messages.  These will be used
 * by us to tell transport via the dv plugin that a peer can
 * no longer be contacted by us via a certain address.  We should
 * then propagate these messages on, given that the distance to
 * the peer indicates we would have gossiped about it to others.
 *
 * @param cls closure
 * @param peer peer which sent the message (immediate sender)
 * @param message the message
 * @param latency the latency of the connection we received the message from
 * @param distance the distance to the immediate peer
 */
static int handle_dv_disconnect_message (void *cls,
                                         const struct GNUNET_PeerIdentity *peer,
                                         const struct GNUNET_MessageHeader *message,
                                         struct GNUNET_TIME_Relative latency,
                                         uint32_t distance)
{
  struct DirectNeighbor *referrer;
  struct DistantNeighbor *distant;
  p2p_dv_MESSAGE_Disconnect *enc_message = (p2p_dv_MESSAGE_Disconnect *)message;

  if (ntohs (message->size) < sizeof (p2p_dv_MESSAGE_Disconnect))
    {
      return GNUNET_SYSERR;     /* invalid message */
    }

  referrer = GNUNET_CONTAINER_multihashmap_get (direct_neighbors,
                                                &peer->hashPubKey);
  if (referrer == NULL)
    return GNUNET_OK;

  distant = referrer->referee_head;
  while (distant != NULL)
    {
      if (distant->referrer_id == ntohl(enc_message->peer_id))
        {
          distant_neighbor_free(distant);
        }
      distant = referrer->referee_head;
    }

  return GNUNET_OK;
}


/**
 * Core handler for dv gossip messages.  These will be used
 * by us to create a HELLO message for the newly peer containing
 * which direct peer we can connect through, and what the cost
 * is.  This HELLO will then be scheduled for validation by the
 * transport service so that it can be used by all others.
 *
 * @param cls closure
 * @param peer peer which sent the message (immediate sender)
 * @param message the message
 * @param latency the latency of the connection we received the message from
 * @param distance the distance to the immediate peer
 */
static int handle_dv_gossip_message (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader *message,
                                     struct GNUNET_TIME_Relative latency,
                                     uint32_t distance)
{
  struct HelloContext *hello_context;
  struct GNUNET_HELLO_Message *hello_msg;
  struct DirectNeighbor *referrer;
  p2p_dv_MESSAGE_NeighborInfo *enc_message = (p2p_dv_MESSAGE_NeighborInfo *)message;

  if (ntohs (message->size) < sizeof (p2p_dv_MESSAGE_NeighborInfo))
    {
      return GNUNET_SYSERR;     /* invalid message */
    }

#if DEBUG_DV_GOSSIP_RECEIPT
  char * encPeerAbout;
  char * encPeerFrom;

  encPeerAbout = GNUNET_strdup(GNUNET_i2s(&enc_message->neighbor));
  encPeerFrom = GNUNET_strdup(GNUNET_i2s(peer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Received %s message from peer %s about peer %s id %u distance %d!\n", GNUNET_i2s(&my_identity), "DV GOSSIP", encPeerFrom, encPeerAbout, ntohl(enc_message->neighbor_id), ntohl (enc_message->cost) + 1);
  GNUNET_free(encPeerAbout);
  GNUNET_free(encPeerFrom);
#endif

  referrer = GNUNET_CONTAINER_multihashmap_get (direct_neighbors,
                                                &peer->hashPubKey);
  if (referrer == NULL)
    return GNUNET_OK;

  addUpdateNeighbor (&enc_message->neighbor, &enc_message->pkey,
                     ntohl (enc_message->neighbor_id),
                     referrer, ntohl (enc_message->cost) + 1);

  hello_context = GNUNET_malloc(sizeof(struct HelloContext));
  hello_context->direct_peer = peer;
  memcpy(&hello_context->distant_peer, &enc_message->neighbor, sizeof(struct GNUNET_PeerIdentity));
  hello_context->addresses_to_add = 1;
  hello_msg = GNUNET_HELLO_create(&enc_message->pkey, &generate_hello_address, hello_context);
  GNUNET_assert(memcmp(hello_context->direct_peer, &hello_context->distant_peer, sizeof(struct GNUNET_PeerIdentity)) != 0);
  send_to_plugin(hello_context->direct_peer, GNUNET_HELLO_get_header(hello_msg), GNUNET_HELLO_size(hello_msg), &hello_context->distant_peer, ntohl(enc_message->cost) + 1);
  GNUNET_free(hello_context);
  GNUNET_free(hello_msg);
  return GNUNET_OK;
}


/**
 * Iterate over all currently known peers, add them to the
 * fast gossip list for this peer so we get DV routing information
 * out as fast as possible!
 *
 * @param cls the direct neighbor we will gossip to
 * @param key the hashcode of the peer
 * @param value the distant neighbor we should add to the list
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO otherwise
 */
static int add_all_extended_peers (void *cls,
                                   const GNUNET_HashCode * key,
                                   void *value)
{
  struct NeighborSendContext *send_context = (struct NeighborSendContext *)cls;
  struct DistantNeighbor *distant = (struct DistantNeighbor *)value;
  struct FastGossipNeighborList *gossip_entry;

  if (memcmp(&send_context->toNeighbor->identity, &distant->identity, sizeof(struct GNUNET_PeerIdentity)) == 0)
    return GNUNET_YES; /* Don't gossip to a peer about itself! */

#if SUPPORT_HIDING
  if (distant->hidden == GNUNET_YES)
    return GNUNET_YES; /* This peer should not be gossipped about (hidden) */
#endif
  gossip_entry = GNUNET_malloc(sizeof(struct FastGossipNeighborList));
  gossip_entry->about = distant;

  GNUNET_CONTAINER_DLL_insert_after(send_context->fast_gossip_list_head,
                                    send_context->fast_gossip_list_tail,
                                    send_context->fast_gossip_list_tail,
                                    gossip_entry);

  return GNUNET_YES;
}

#if INSANE_GOSSIP
/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int gossip_all_to_all_iterator (void *cls,
                                      const GNUNET_HashCode * key,
                                      void *value)
{
  struct DirectNeighbor *direct = value;

  GNUNET_CONTAINER_multihashmap_iterate (extended_neighbors, &add_all_extended_peers, direct->send_context);

  if (direct->send_context->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(sched, direct->send_context->task);

  direct->send_context->task = GNUNET_SCHEDULER_add_now(sched, &neighbor_send_task, direct->send_context);
  return GNUNET_YES;
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
gossip_all_to_all (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CONTAINER_multihashmap_iterate (direct_neighbors, &gossip_all_to_all_iterator, NULL);

  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5),
                                &gossip_all_to_all,
                                NULL);

}
#endif
/**
 * Iterate over all current direct peers, add newly connected peer
 * to the fast gossip list for that peer so we get DV routing
 * information out as fast as possible!
 *
 * @param cls the newly connected neighbor we will gossip about
 * @param key the hashcode of the peer
 * @param value the direct neighbor we should gossip to
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO otherwise
 */
static int add_all_direct_neighbors (void *cls,
                                     const GNUNET_HashCode * key,
                                     void *value)
{
  struct DirectNeighbor *direct = (struct DirectNeighbor *)value;
  struct DirectNeighbor *to = (struct DirectNeighbor *)cls;
  struct DistantNeighbor *distant;
  struct NeighborSendContext *send_context = direct->send_context;
  struct FastGossipNeighborList *gossip_entry;
  char *direct_id;


  distant = GNUNET_CONTAINER_multihashmap_get(extended_neighbors, &to->identity.hashPubKey);
  if (distant == NULL)
    {
      return GNUNET_YES;
    }

  if (memcmp(&direct->identity, &to->identity, sizeof(struct GNUNET_PeerIdentity)) == 0)
    {
      return GNUNET_YES; /* Don't gossip to a peer about itself! */
    }

#if SUPPORT_HIDING
  if (distant->hidden == GNUNET_YES)
    return GNUNET_YES; /* This peer should not be gossipped about (hidden) */
#endif
  direct_id = GNUNET_strdup(GNUNET_i2s(&direct->identity));
#if DEBUG_DV_GOSSIP
  GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s: adding peer %s to fast send list for %s\n", my_short_id, GNUNET_i2s(&distant->identity), direct_id);
#endif
  GNUNET_free(direct_id);
  gossip_entry = GNUNET_malloc(sizeof(struct FastGossipNeighborList));
  gossip_entry->about = distant;

  GNUNET_CONTAINER_DLL_insert_after(send_context->fast_gossip_list_head,
                                    send_context->fast_gossip_list_tail,
                                    send_context->fast_gossip_list_tail,
                                    gossip_entry);
  if (send_context->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(sched, send_context->task);

  send_context->task = GNUNET_SCHEDULER_add_now(sched, &neighbor_send_task, send_context);
  //tc.reason = GNUNET_SCHEDULER_REASON_TIMEOUT;
  //neighbor_send_task(send_context, &tc);
  return GNUNET_YES;
}

/**
 * Type of an iterator over the hosts.  Note that each
 * host will be called with each available protocol.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param trust amount of trust we have in the peer
 */
static void
process_peerinfo (void *cls,
                  const struct GNUNET_PeerIdentity *peer,
                  const struct GNUNET_HELLO_Message *hello, uint32_t trust)
{
  struct PeerIteratorContext *peerinfo_iterator = cls;
  struct DirectNeighbor *neighbor = peerinfo_iterator->neighbor;
  struct DistantNeighbor *distant = peerinfo_iterator->distant;
#if DEBUG_DV_PEER_NUMBERS
  char *neighbor_pid;
#endif
  int sent;

  if (peer == NULL) /* && (neighbor->pkey == NULL))*/
    {
      if (distant->pkey == NULL) /* FIXME: Reschedule? */
        {
#if DEBUG_DV
          GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Failed to get peerinfo information for this peer, retrying!\n");
#endif
          peerinfo_iterator->ic = GNUNET_PEERINFO_iterate(peerinfo_handle,
                                                          &peerinfo_iterator->neighbor->identity,
                                                          0,
                                                          GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3),
                                                          &process_peerinfo,
                                                          peerinfo_iterator);
        }
      else
        {
          GNUNET_free(peerinfo_iterator);
        }
      return;
    }

  if (memcmp(&neighbor->identity, peer, sizeof(struct GNUNET_PeerIdentity) != 0))
    return;

  if ((hello != NULL) && (GNUNET_HELLO_get_key (hello, &neighbor->pkey) == GNUNET_OK))
    {
      if (distant->pkey == NULL)
        {
          distant->pkey = GNUNET_malloc(sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
          memcpy(distant->pkey, &neighbor->pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
        }

      /* Why do it this way, now we have the distant neighbor! */
      /*GNUNET_CONTAINER_multihashmap_get_multiple(extended_neighbors,
                                                 &peer->hashPubKey,
                                                 &add_pkey_to_extended,
                                                 &neighbor->pkey);*/

      sent = GNUNET_CONTAINER_multihashmap_iterate (extended_neighbors, &add_all_extended_peers, neighbor->send_context);

#if DEBUG_DV_PEER_NUMBERS
      neighbor_pid = GNUNET_strdup(GNUNET_i2s(&neighbor->identity));
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: Gossipped %d extended peers to %s\n", GNUNET_i2s(&my_identity), sent, neighbor_pid);
#endif
      sent = GNUNET_CONTAINER_multihashmap_iterate (direct_neighbors, &add_all_direct_neighbors, neighbor);
#if DEBUG_DV_PEER_NUMBERS
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "%s: Gossipped about %s to %d direct peers\n", GNUNET_i2s(&my_identity), neighbor_pid, sent);
      GNUNET_free(neighbor_pid);
#endif
      neighbor->send_context->task = GNUNET_SCHEDULER_add_now(sched, &neighbor_send_task, neighbor->send_context);
    }
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with peer
 * @param distance reported distance (DV) to peer
 */
void handle_core_connect (void *cls,
                          const struct GNUNET_PeerIdentity * peer,
                          struct GNUNET_TIME_Relative latency,
                          uint32_t distance)
{
  struct DirectNeighbor *neighbor;
  struct DistantNeighbor *about;
  struct PeerIteratorContext *peerinfo_iterator;
  int sent;
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives core connect message for peer %s distance %d!\n", "dv", GNUNET_i2s(peer), distance);
#endif

  if ((distance == DIRECT_NEIGHBOR_COST) && (GNUNET_CONTAINER_multihashmap_get(direct_neighbors, &peer->hashPubKey) == NULL))
  {
    peerinfo_iterator = GNUNET_malloc(sizeof(struct PeerIteratorContext));
    neighbor = GNUNET_malloc (sizeof (struct DirectNeighbor));
    neighbor->send_context = GNUNET_malloc(sizeof(struct NeighborSendContext));
    neighbor->send_context->toNeighbor = neighbor;
    memcpy (&neighbor->identity, peer, sizeof (struct GNUNET_PeerIdentity));

    GNUNET_assert(GNUNET_SYSERR != GNUNET_CONTAINER_multihashmap_put (direct_neighbors,
                               &peer->hashPubKey,
                               neighbor, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    about = addUpdateNeighbor (peer, NULL, 0, neighbor, DIRECT_NEIGHBOR_COST);
    peerinfo_iterator->distant = about;
    peerinfo_iterator->neighbor = neighbor;
    peerinfo_iterator->ic = GNUNET_PEERINFO_iterate (peerinfo_handle,
                                                     peer,
                                                     0,
                                                     GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3),
                                                     &process_peerinfo,
                                                     peerinfo_iterator);

    if ((about != NULL) && (about->pkey == NULL))
      {
#if DEBUG_DV
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Newly added peer %s has NULL pkey!\n", GNUNET_i2s(peer));
#endif
      }
    else if (about != NULL)
      {
        GNUNET_free(peerinfo_iterator);
      }
  }
  else
  {
    about = GNUNET_CONTAINER_multihashmap_get(extended_neighbors, &peer->hashPubKey);
    if ((GNUNET_CONTAINER_multihashmap_get(direct_neighbors, &peer->hashPubKey) == NULL) && (about != NULL))
      sent = GNUNET_CONTAINER_multihashmap_iterate(direct_neighbors, &add_distant_all_direct_neighbors, about);
#if DEBUG_DV
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: Distance (%d) greater than %d or already know about peer (%s), not re-adding!\n", "dv", distance, DIRECT_NEIGHBOR_COST, GNUNET_i2s(peer));
#endif
    return;
  }
}

/**
 * Method called whenever a given peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
void handle_core_disconnect (void *cls,
                             const struct GNUNET_PeerIdentity * peer)
{
  struct DirectNeighbor *neighbor;
  struct DistantNeighbor *referee;
  struct FindDestinationContext fdc;
  struct DisconnectContext disconnect_context;

#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Receives core peer disconnect message!\n", "dv");
#endif

  neighbor =
    GNUNET_CONTAINER_multihashmap_get (direct_neighbors, &peer->hashPubKey);
  if (neighbor == NULL)
    {
      return;
    }
  while (NULL != (referee = neighbor->referee_head))
    distant_neighbor_free (referee);

  fdc.dest = NULL;
  fdc.tid = 0;

  GNUNET_CONTAINER_multihashmap_iterate (extended_neighbors, &find_distant_peer, &fdc);

  if (fdc.dest != NULL)
    {
      disconnect_context.direct = neighbor;
      disconnect_context.distant = fdc.dest;
      GNUNET_CONTAINER_multihashmap_iterate (direct_neighbors, &schedule_disconnect_messages, &disconnect_context);
    }

  GNUNET_assert (neighbor->referee_tail == NULL);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_remove (direct_neighbors,
                                        &peer->hashPubKey, neighbor))
    {
      GNUNET_break(0);
    }
  if ((neighbor->send_context != NULL) && (neighbor->send_context->task != GNUNET_SCHEDULER_NO_TASK))
    GNUNET_SCHEDULER_cancel(sched, neighbor->send_context->task);
  GNUNET_free (neighbor);
}


/**
 * Process dv requests.
 *
 * @param cls closure
 * @param scheduler scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *scheduler,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  unsigned long long max_hosts;
  sched = scheduler;
  cfg = c;

  /* FIXME: Read from config, or calculate, or something other than this! */
  max_hosts = DEFAULT_DIRECT_CONNECTIONS;
  max_table_size = DEFAULT_DV_SIZE;
  fisheye_depth = DEFAULT_FISHEYE_DEPTH;

  if (GNUNET_CONFIGURATION_have_value(cfg, "dv", "max_direct_connections"))
    GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_number(cfg, "dv", "max_direct_connections", &max_hosts));

  if (GNUNET_CONFIGURATION_have_value(cfg, "dv", "max_total_connections"))
    GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_number(cfg, "dv", "max_total_connections", &max_table_size));


  if (GNUNET_CONFIGURATION_have_value(cfg, "dv", "fisheye_depth"))
    GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_number(cfg, "dv", "fisheye_depth", &fisheye_depth));

  neighbor_min_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  neighbor_max_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);

  direct_neighbors = GNUNET_CONTAINER_multihashmap_create (max_hosts);
  extended_neighbors =
    GNUNET_CONTAINER_multihashmap_create (max_table_size * 3);

  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  coreAPI =
  GNUNET_CORE_connect (sched,
                       cfg,
                       GNUNET_TIME_relative_get_forever(),
                       NULL, /* FIXME: anything we want to pass around? */
                       &core_init,
                       &handle_core_connect,
                       &handle_core_disconnect,
                       NULL,
                       GNUNET_NO,
                       NULL,
                       GNUNET_NO,
                       core_handlers);

  if (coreAPI == NULL)
    return;

   peerinfo_handle = GNUNET_PEERINFO_connect(sched, cfg);

   if (peerinfo_handle == NULL)
     {
       GNUNET_CORE_disconnect(coreAPI);
       return;
     }

  /* Scheduled the task to clean up when shutdown is called */
  cleanup_task = GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
#if INSANE_GOSSIP
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5),
                                &gossip_all_to_all,
                                NULL);
#endif
}


/**
 * The main function for the dv service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "dv",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}
