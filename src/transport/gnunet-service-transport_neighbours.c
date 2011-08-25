/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
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
 * @file transport/gnunet-service-transport_neighbours.c
 * @brief neighbour management
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_constants.h"
#include "transport.h"


/**
 * Size of the neighbour hash map.
 */
#define NEIGHBOUR_TABLE_SIZE 256

/**
 * How often must a peer violate bandwidth quotas before we start
 * to simply drop its messages?
 */
#define QUOTA_VIOLATION_DROP_THRESHOLD 10


/**
 * Entry in neighbours. 
 */
struct NeighbourMapEntry;


/**
 * For each neighbour we keep a list of messages
 * that we still want to transmit to the neighbour.
 */
struct MessageQueue
{

  /**
   * This is a doubly linked list.
   */
  struct MessageQueue *next;

  /**
   * This is a doubly linked list.
   */
  struct MessageQueue *prev;

  /**
   * Once this message is actively being transmitted, which
   * neighbour is it associated with?
   */
  struct NeighbourMapEntry *n;

  /**
   * Function to call once we're done.
   */
  GST_NeighbourSendContinuation cont;

  /**
   * Closure for 'cont'
   */
  void *cont_cls;

  /**
   * The message(s) we want to transmit, GNUNET_MessageHeader(s)
   * stuck together in memory.  Allocated at the end of this struct.
   */
  const char *message_buf;

  /**
   * Size of the message buf
   */
  size_t message_buf_size;

  /**
   * At what time should we fail?
   */
  struct GNUNET_TIME_Absolute timeout;

};


/**
 * Entry in neighbours. 
 */
struct NeighbourMapEntry
{

  /**
   * Head of list of messages we would like to send to this peer;
   * must contain at most one message per client.
   */
  struct MessageQueue *messages_head;

  /**
   * Tail of list of messages we would like to send to this peer; must
   * contain at most one message per client.
   */
  struct MessageQueue *messages_tail;

  /**
   * Context for address suggestion.
   * NULL after we are connected.
   */
  struct GNUNET_ATS_SuggestionContext *asc;

  /**
   * Performance data for the peer.
   */
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  /**
   * Are we currently trying to send a message? If so, which one?
   */
  struct MessageQueue *is_active;

  /**
   * Active session for communicating with the peer.
   */
  struct Session *session;

  /**
   * Name of the plugin we currently use.
   */
  char *plugin_name;

  /**
   * Address used for communicating with the peer, NULL for inbound connections.
   */
  void *addr;

  /**
   * Number of bytes in 'addr'.
   */
  size_t addrlen;

  /**
   * Identity of this neighbour.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * ID of task scheduled to run when this peer is about to
   * time out (will free resources associated with the peer).
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * ID of task scheduled to run when we should try transmitting
   * the head of the message queue.  
   */
  GNUNET_SCHEDULER_TaskIdentifier transmission_task;

  /**
   * Tracker for inbound bandwidth.
   */
  struct GNUNET_BANDWIDTH_Tracker in_tracker;

  /**
   * How often has the other peer (recently) violated the inbound
   * traffic limit?  Incremented by 10 per violation, decremented by 1
   * per non-violation (for each time interval).
   */
  unsigned int quota_violation_count;

  /**
   * Number of values in 'ats' array.
   */
  unsigned int ats_count;

  /**
   * Are we already in the process of disconnecting this neighbour?
   */
  int in_disconnect;

  /**
   * Do we currently consider this neighbour connected? (as far as
   * the connect/disconnect callbacks are concerned)?
   */
  int is_connected;

};


/**
 * All known neighbours and their HELLOs.
 */
static struct GNUNET_CONTAINER_MultiHashMap *neighbours;

/**
 * Closure for connect_notify_cb and disconnect_notify_cb
 */
static void *callback_cls;

/**
 * Function to call when we connected to a neighbour.
 */
static GNUNET_TRANSPORT_NotifyConnect connect_notify_cb;

/**
 * Function to call when we disconnected from a neighbour.
 */
static GNUNET_TRANSPORT_NotifyDisconnect disconnect_notify_cb;


/**
 * Lookup a neighbour entry in the neighbours hash map.
 *
 * @param pid identity of the peer to look up
 * @return the entry, NULL if there is no existing record
 */
static struct NeighbourMapEntry *
lookup_neighbour (const struct GNUNET_PeerIdentity *pid)
{
  return GNUNET_CONTAINER_multihashmap_get (neighbours, &pid->hashPubKey);
}


/**
 * Task invoked to start a transmission to another peer.
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param tc scheduler context
 */
static void
transmission_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * We're done with our transmission attempt, continue processing.
 *
 * @param cls the 'struct MessageQueue' of the message
 * @param receiver intended receiver
 * @param success whether it worked or not
 */
static void
transmit_send_continuation (void *cls,
                            const struct GNUNET_PeerIdentity *receiver,
                            int success)
{
  struct MessageQueue *mq;
  struct NeighbourMapEntry *n;

  mq = cls;
  n = mq->n;
  if (NULL != n)
  {
    GNUNET_assert (n->is_active == mq);
    n->is_active = NULL;
    GNUNET_assert (n->transmission_task == GNUNET_SCHEDULER_NO_TASK);
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
  }
  if (NULL != mq->cont)
    mq->cont (mq->cont_cls, success);
  GNUNET_free (mq);
}


/**
 * Check the ready list for the given neighbour and if a plugin is
 * ready for transmission (and if we have a message), do so!
 *
 * @param neighbour target peer for which to transmit
 */
static void
try_transmission_to_peer (struct NeighbourMapEntry *n)
{
  struct MessageQueue *mq;
  struct GNUNET_TIME_Relative timeout;
  ssize_t ret;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  if (n->is_active != NULL)
    return;                     /* transmission already pending */
  if (n->transmission_task != GNUNET_SCHEDULER_NO_TASK)
    return;                     /* currently waiting for bandwidth */
  mq = n->messages_head;
  while (NULL != (mq = n->messages_head))
  {
    timeout = GNUNET_TIME_absolute_get_remaining (mq->timeout);
    if (timeout.rel_value > 0)
      break;
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);     /* timeout */
  }
  if (NULL == mq)
    return;                     /* no more messages */

  papi = GST_plugins_find (n->plugin_name);
  if (papi == NULL)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
  n->is_active = mq;
  mq->n = n;


  ret =
      papi->send (papi->cls, &n->id, mq->message_buf, mq->message_buf_size,
                  0 /* priority -- remove from plugin API? */ ,
                  timeout, n->session, n->addr, n->addrlen, GNUNET_YES,
                  &transmit_send_continuation, mq);
  if (ret == -1)
  {
    /* failure, but 'send' would not call continuation in this case,
     * so we need to do it here! */
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
  }
}


/**
 * Task invoked to start a transmission to another peer.
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param tc scheduler context
 */
static void
transmission_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;

  n->transmission_task = GNUNET_SCHEDULER_NO_TASK;
  try_transmission_to_peer (n);
}


/**
 * Initialize the neighbours subsystem.
 *
 * @param cls closure for callbacks
 * @param connect_cb function to call if we connect to a peer
 * @param disconnect_cb function to call if we disconnect from a peer
 */
void
GST_neighbours_start (void *cls, GNUNET_TRANSPORT_NotifyConnect connect_cb,
                      GNUNET_TRANSPORT_NotifyDisconnect disconnect_cb)
{
  callback_cls = cls;
  connect_notify_cb = connect_cb;
  disconnect_notify_cb = disconnect_cb;
  neighbours = GNUNET_CONTAINER_multihashmap_create (NEIGHBOUR_TABLE_SIZE);
}


/**
 * Disconnect from the given neighbour, clean up the record.
 *
 * @param n neighbour to disconnect from
 */
static void
disconnect_neighbour (struct NeighbourMapEntry *n)
{
  struct MessageQueue *mq;

  if (GNUNET_YES == n->in_disconnect)
    return;
  n->in_disconnect = GNUNET_YES;
  while (NULL != (mq = n->messages_head))
  {
    GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
    mq->cont (mq->cont_cls, GNUNET_SYSERR);
    GNUNET_free (mq);
  }
  if (NULL != n->is_active)
  {
    n->is_active->n = NULL;
    n->is_active = NULL;
  }
  if (GNUNET_YES == n->is_connected)
  {
    n->is_connected = GNUNET_NO;
    disconnect_notify_cb (callback_cls, &n->id);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (neighbours,
                                                       &n->id.hashPubKey, n));
  if (GNUNET_SCHEDULER_NO_TASK != n->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (n->timeout_task);
    n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != n->transmission_task)
  {
    GNUNET_SCHEDULER_cancel (n->timeout_task);
    n->transmission_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != n->asc)
  {
    GNUNET_ATS_suggest_address_cancel (n->asc);
    n->asc = NULL;
  }
  GNUNET_array_grow (n->ats, n->ats_count, 0);
  if (NULL != n->plugin_name)
  {
    GNUNET_free (n->plugin_name);
    n->plugin_name = NULL;
  }
  if (NULL != n->addr)
  {
    GNUNET_free (n->addr);
    n->addr = NULL;
    n->addrlen = 0;
  }
  n->session = NULL;
  GNUNET_free (n);
}


/**
 * Peer has been idle for too long. Disconnect.
 *
 * @param cls the 'struct NeighbourMapEntry' of the neighbour that went idle
 * @param tc scheduler context
 */
static void
neighbour_timeout_task (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;

  n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  disconnect_neighbour (n);
}


/**
 * Disconnect from the given neighbour.
 *
 * @param cls unused
 * @param key hash of neighbour's public key (not used)
 * @param value the 'struct NeighbourMapEntry' of the neighbour
 */
static int
disconnect_all_neighbours (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct NeighbourMapEntry *n = value;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting peer `%4s', %s\n",
              GNUNET_i2s (&n->id), "SHUTDOWN_TASK");
#endif
  disconnect_neighbour (n);
  return GNUNET_OK;
}


/**
 * Cleanup the neighbours subsystem.
 */
void
GST_neighbours_stop ()
{
  GNUNET_CONTAINER_multihashmap_iterate (neighbours, &disconnect_all_neighbours,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (neighbours);
  neighbours = NULL;
  callback_cls = NULL;
  connect_notify_cb = NULL;
  disconnect_notify_cb = NULL;
}


/**
 * For an existing neighbour record, set the active connection to
 * the given address.
 *
 * @param peer identity of the peer to switch the address for
 * @param plugin_name name of transport that delivered the PONG
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param address_len number of bytes in address
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
void
GST_neighbours_switch_to_address (const struct GNUNET_PeerIdentity *peer,
                                  const char *plugin_name, const void *address,
                                  size_t address_len, struct Session *session,
                                  const struct GNUNET_TRANSPORT_ATS_Information
                                  *ats, uint32_t ats_count)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_MessageHeader connect_msg;

  n = lookup_neighbour (peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    return;
  }

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "SWITCH! Peer `%4s' switches to plugin `%s' address '%s' session %X\n",
              GNUNET_i2s (peer), plugin_name,
              (address_len == 0) ? "<inbound>" : GST_plugins_a2s (plugin_name,
                                                                  address,
                                                                  address_len),
              session);
#endif

  GNUNET_free_non_null (n->addr);
  n->addr = GNUNET_malloc (address_len);
  memcpy (n->addr, address, address_len);
  n->addrlen = address_len;
  n->session = session;
  GNUNET_array_grow (n->ats, n->ats_count, ats_count);
  memcpy (n->ats, ats,
          ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  GNUNET_free_non_null (n->plugin_name);
  n->plugin_name = GNUNET_strdup (plugin_name);
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                    &neighbour_timeout_task, n);
  connect_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  connect_msg.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  GST_neighbours_send (peer, &connect_msg, sizeof (connect_msg),
                       GNUNET_TIME_UNIT_FOREVER_REL, NULL, NULL);
}


/**
 * Try to connect to the target peer using the given address
 *
 * @param cls the 'struct NeighbourMapEntry' of the target
 * @param target identity of the target peer
 * @param plugin_name name of the plugin
 * @param plugin_address binary address
 * @param plugin_address_len length of address
 * @param bandwidth available bandwidth
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in 'ats'
 */
static void
try_connect_using_address (void *cls, const struct GNUNET_PeerIdentity *target,
                           const char *plugin_name, const void *plugin_address,
                           size_t plugin_address_len, struct Session *session,
                           struct GNUNET_BANDWIDTH_Value32NBO bandwidth,
                           const struct GNUNET_TRANSPORT_ATS_Information *ats,
                           uint32_t ats_count)
{
  struct NeighbourMapEntry *n = cls;

  n->asc = NULL;
  GST_neighbours_switch_to_address (target, plugin_name, plugin_address,
                                    plugin_address_len, session, ats,
                                    ats_count);
  if (GNUNET_YES == n->is_connected)
    return;
  n->is_connected = GNUNET_YES;
  connect_notify_cb (callback_cls, target, n->ats, n->ats_count);
}


/**
 * Try to create a connection to the given target (eventually).
 *
 * @param target peer to try to connect to
 */
void
GST_neighbours_try_connect (const struct GNUNET_PeerIdentity *target)
{
  struct NeighbourMapEntry *n;

  GNUNET_assert (0 !=
                 memcmp (target, &GST_my_identity,
                         sizeof (struct GNUNET_PeerIdentity)));
  n = lookup_neighbour (target);
  if ((NULL != n) && (GNUNET_YES == n->is_connected))
    return;                     /* already connected */
  if (n == NULL)
  {
    n = GNUNET_malloc (sizeof (struct NeighbourMapEntry));
    n->id = *target;
    GNUNET_BANDWIDTH_tracker_init (&n->in_tracker,
                                   GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
                                   MAX_BANDWIDTH_CARRY_S);
    n->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                      &neighbour_timeout_task, n);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (neighbours,
                                                      &n->id.hashPubKey, n,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  if (n->asc != NULL)
    return;                     /* already trying */
  n->asc =
      GNUNET_ATS_suggest_address (GST_ats, target, &try_connect_using_address,
                                  n);
}


/**
 * Test if we're connected to the given peer.
 * 
 * @param target peer to test
 * @return GNUNET_YES if we are connected, GNUNET_NO if not
 */
int
GST_neighbours_test_connected (const struct GNUNET_PeerIdentity *target)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (target);
  if ((NULL == n) || (n->is_connected != GNUNET_YES))
    return GNUNET_NO;           /* not connected */
  return GNUNET_YES;
}


/**
 * A session was terminated. Take note.
 *
 * @param peer identity of the peer where the session died
 * @param session session that is gone
 */
void
GST_neighbours_session_terminated (const struct GNUNET_PeerIdentity *peer,
                                   struct Session *session)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (peer);
  if (NULL == n)
    return;
  if (session != n->session)
    return;                     /* doesn't affect us */
  n->session = NULL;
  if (GNUNET_YES != n->is_connected)
    return;                     /* not connected anymore anyway, shouldn't matter */

  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                    &neighbour_timeout_task, n);
  /* try QUICKLY to re-establish a connection, reduce timeout! */
  if (NULL != n->ats)
  {
    /* how can this be!? */
    //GNUNET_break (0);
    return;
  }
  n->asc =
      GNUNET_ATS_suggest_address (GST_ats, peer, &try_connect_using_address, n);
}


/**
 * Transmit a message to the given target using the active connection.
 *
 * @param target destination
 * @param msg message to send
 * @param msg_size number of bytes in msg
 * @param timeout when to fail with timeout
 * @param cont function to call when done
 * @param cont_cls closure for 'cont'
 */
void
GST_neighbours_send (const struct GNUNET_PeerIdentity *target, const void *msg,
                     size_t msg_size, struct GNUNET_TIME_Relative timeout,
                     GST_NeighbourSendContinuation cont, void *cont_cls)
{
  struct NeighbourMapEntry *n;
  struct MessageQueue *mq;

  n = lookup_neighbour (target);
  if ((n == NULL) || (GNUNET_YES != n->is_connected))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# SET QUOTA messages ignored (no such peer)"),
                              1, GNUNET_NO);
#if DEBUG_TRANSPORT
    if (n == NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send message to peer `%s': unknown neighbor",
                  GNUNET_i2s (target));
    if (GNUNET_YES != n->is_connected)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send message to peer `%s': not connected\n",
                  GNUNET_i2s (target));
#endif
    if (NULL != cont)
      cont (cont_cls, GNUNET_SYSERR);
    return;
  }
  GNUNET_assert (msg_size >= sizeof (struct GNUNET_MessageHeader));
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# bytes in message queue for other peers"),
                            msg_size, GNUNET_NO);
  mq = GNUNET_malloc (sizeof (struct MessageQueue) + msg_size);
  mq->cont = cont;
  mq->cont_cls = cont_cls;
  /* FIXME: this memcpy can be up to 7% of our total runtime! */
  memcpy (&mq[1], msg, msg_size);
  mq->message_buf = (const char *) &mq[1];
  mq->message_buf_size = msg_size;
  mq->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  GNUNET_CONTAINER_DLL_insert_tail (n->messages_head, n->messages_tail, mq);
  if ((GNUNET_SCHEDULER_NO_TASK == n->transmission_task) &&
      (NULL == n->is_active))
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
}


/**
 * We have received a message from the given sender.  How long should
 * we delay before receiving more?  (Also used to keep the peer marked
 * as live).
 *
 * @param sender sender of the message
 * @param size size of the message
 * @param do_forward set to GNUNET_YES if the message should be forwarded to clients
 *                   GNUNET_NO if the neighbour is not connected or violates the quota
 * @return how long to wait before reading more from this sender
 */
struct GNUNET_TIME_Relative
GST_neighbours_calculate_receive_delay (const struct GNUNET_PeerIdentity
                                        *sender, ssize_t size, int *do_forward)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_TIME_Relative ret;

  n = lookup_neighbour (sender);
  if (n == NULL)
  {
    *do_forward = GNUNET_NO;
    return GNUNET_TIME_UNIT_ZERO;
  }
  if (GNUNET_YES == GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker, size))
  {
    n->quota_violation_count++;
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Bandwidth quota (%u b/s) violation detected (total of %u).\n",
                n->in_tracker.available_bytes_per_s__,
                n->quota_violation_count);
#endif
    /* Discount 32k per violation */
    GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker, -32 * 1024);
  }
  else
  {
    if (n->quota_violation_count > 0)
    {
      /* try to add 32k back */
      GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker, 32 * 1024);
      n->quota_violation_count--;
    }
  }
  if (n->quota_violation_count > QUOTA_VIOLATION_DROP_THRESHOLD)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# bandwidth quota violations by other peers"),
                              1, GNUNET_NO);
    *do_forward = GNUNET_NO;
    return GNUNET_CONSTANTS_QUOTA_VIOLATION_TIMEOUT;
  }
  *do_forward = GNUNET_YES;
  ret = GNUNET_BANDWIDTH_tracker_get_delay (&n->in_tracker, 0);
  if (ret.rel_value > 0)
  {
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Throttling read (%llu bytes excess at %u b/s), waiting %llu ms before reading more.\n",
                (unsigned long long) n->in_tracker.
                consumption_since_last_update__,
                (unsigned int) n->in_tracker.available_bytes_per_s__,
                (unsigned long long) ret.rel_value);
#endif
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# ms throttling suggested"),
                              (int64_t) ret.rel_value, GNUNET_NO);
  }
  return ret;
}


/**
 * Keep the connection to the given neighbour alive longer,
 * we received a KEEPALIVE (or equivalent).
 *
 * @param neighbour neighbour to keep alive
 */
void
GST_neighbours_keepalive (const struct GNUNET_PeerIdentity *neighbour)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (neighbour);
  if (NULL == n)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# KEEPALIVE messages discarded (not connected)"),
                              1, GNUNET_NO);
    return;
  }
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                    &neighbour_timeout_task, n);
}


/**
 * Change the incoming quota for the given peer.
 *
 * @param neighbour identity of peer to change qutoa for
 * @param quota new quota 
 */
void
GST_neighbours_set_incoming_quota (const struct GNUNET_PeerIdentity *neighbour,
                                   struct GNUNET_BANDWIDTH_Value32NBO quota)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (neighbour);
  if (n == NULL)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# SET QUOTA messages ignored (no such peer)"),
                              1, GNUNET_NO);
    return;
  }
  GNUNET_BANDWIDTH_tracker_update_quota (&n->in_tracker, quota);
  if (0 != ntohl (quota.value__))
    return;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting peer `%4s' due to `%s'\n",
              GNUNET_i2s (&n->id), "SET_QUOTA");
#endif
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# disconnects due to quota of 0"), 1,
                            GNUNET_NO);
  disconnect_neighbour (n);
}


/**
 * Closure for the neighbours_iterate function.
 */
struct IteratorContext
{
  /**
   * Function to call on each connected neighbour.
   */
  GST_NeighbourIterator cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;
};


/**
 * Call the callback from the closure for each connected neighbour.
 *
 * @param cls the 'struct IteratorContext'
 * @param key the hash of the public key of the neighbour
 * @param value the 'struct NeighbourMapEntry'
 * @return GNUNET_OK (continue to iterate)
 */
static int
neighbours_iterate (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct IteratorContext *ic = cls;
  struct NeighbourMapEntry *n = value;

  if (GNUNET_YES != n->is_connected)
    return GNUNET_OK;
  GNUNET_assert (n->ats_count > 0);
  ic->cb (ic->cb_cls, &n->id, n->ats, n->ats_count - 1);
  return GNUNET_OK;
}


/**
 * Iterate over all connected neighbours.
 *
 * @param cb function to call 
 * @param cb_cls closure for cb
 */
void
GST_neighbours_iterate (GST_NeighbourIterator cb, void *cb_cls)
{
  struct IteratorContext ic;

  ic.cb = cb;
  ic.cb_cls = cb_cls;
  GNUNET_CONTAINER_multihashmap_iterate (neighbours, &neighbours_iterate, &ic);
}


/**
 * If we have an active connection to the given target, it must be shutdown.
 *
 * @param target peer to disconnect from
 */
void
GST_neighbours_force_disconnect (const struct GNUNET_PeerIdentity *target)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_MessageHeader disconnect_msg;

  n = lookup_neighbour (target);
  if (NULL == n)
    return;                     /* not active */
  if (GNUNET_YES == n->is_connected)
  {
    /* we're actually connected, send DISCONNECT message */
    disconnect_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
    disconnect_msg.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
    papi = GST_plugins_find (n->plugin_name);
    if (papi != NULL)
      papi->send (papi->cls, target, (const void *) &disconnect_msg,
                  sizeof (struct GNUNET_MessageHeader),
                  UINT32_MAX /* priority */ ,
                  GNUNET_TIME_UNIT_FOREVER_REL, n->session, n->addr, n->addrlen,
                  GNUNET_YES, NULL, NULL);
  }
  disconnect_neighbour (n);
}


/* end of file gnunet-service-transport_neighbours.c */
