/*
     This file is part of GNUnet.
     Copyright (C) 2023 GNUnet e.V.

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
 * @addtogroup Core
 * @{
 *
 * @author Julius Bünger
 *
 * @file
 * Implementation of the dummy core underlay that uses unix domain sockets
 *
 * @defgroup CORE
 * Secure Communication with other peers
 *
 * @see [Documentation](https://gnunet.org/core-service) TODO
 *
 * @{
 */

// TODO actually implement rate-limiting

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "gnunet_core_underlay_dummy.h"
#include "gnunet_util_lib.h"
#include "gnunet_scheduler_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "core-underlay-dummy", __VA_ARGS__)

#define SOCK_NAME_BASE "/tmp/gnunet-core-underlay-dummy-socket"
#define SOCK_EXTENSION ".sock"
#define BUFF_SIZE 8192
#define BACKLOG 10


/**
 * @brief Closure used for the #peer_connect_task
 */
struct PeerConnectCls
{
  /**
   * @brief Linked list next
   */
  struct PeerConnectCls *next;

  /**
   * @brief Linked list previous
   */
  struct PeerConnectCls *prev;

  /**
   * @brief The handle for the service
   */
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;

  /**
   * @brief The file name to connect to
   */
  char *sock_name;

  /**
   * Task to connect to another peer.
   */
  struct GNUNET_SCHEDULER_Task *peer_connect_task;
};


struct QueuedMessage
{
  struct QueuedMessage *next;
  struct QueuedMessage *prev;

  struct GNUNET_MessageHeader *msg;
};


/**
 * @brief Used to keep track of context of peer
 */
struct Connection
{
  /**
   * @brief Linked list next
   */
  struct Connection *next;

  /**
   * @brief Linked list previous
   */
  struct Connection *prev;

  /**
   * Message queue towards the connected peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Handlers for mq
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Closure for the mq towards the client.
   */
  void *cls_mq;

  /**
   * Socket for the connected peer.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Address of the connected peer.
   */
  char *peer_addr;

  /**
   * Task waiting for incoming messages.
   */
  struct GNUNET_SCHEDULER_Task *recv_task;

  /**
   * Task waiting until the socket becomes ready to be written to.
   */
  struct GNUNET_SCHEDULER_Task *write_task;

  /**
   * Task to notify the client about an open connection
   */
  struct GNUNET_SCHEDULER_Task *notify_connect_task;

  /**
   * Queued messages in a DLL
   */
  struct QueuedMessage *queued_messages_head;
  struct QueuedMessage *queued_messages_tail;

  /**
   * @brief Handle to the service
   */
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *handle;
};


/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_UNDERLAY_DUMMY_Handle
{
  /**
   * Callback (from/to client) to call when another peer connects.
   */
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect notify_connect;

  /**
   * Callback (from/to client) to call when a peer disconnects.
   */
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect notify_disconnect;

  /**
   * Callback (from/to client) to call when our address changes.
   */
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyAddressChange notify_address_change;

  /**
   * Array of message handlers given by the client. Don't use for handling of
   * messages - this discards the per-mq-cls;
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Closure for handlers given by the client
   * (#notify_connect, #notify_disconnect, #notify_address_change)
   * TODO what's the doxygen way of linking to other members of this struct?
   */
  void *cls;

  /**
   * Name of the listening socket.
   */
  char *sock_name;

  /**
   * Socket on which we listen for incoming connections.
   */
  struct GNUNET_NETWORK_Handle *sock_listen;

  /**
   * Hash over the current address(es).
   */
  struct GNUNET_HashCode network_location_hash;

  /**
   * FIXME honestly I forgot what was planned for this. Look it up in notes!
   */
  uint64_t network_generation_id;

  /**
   * Task that waits for incoming connections
   */
  struct GNUNET_SCHEDULER_Task *listen_task;

  /**
   * Task to notify core about address changes.
   */
  struct GNUNET_SCHEDULER_Task *notify_address_change_task;

  /**
   * Task to discover other peers.
   */
  struct GNUNET_SCHEDULER_Task *peer_discovery_task;

  /**
   * @brief Head of linked list with peer connect closures
   */
  struct PeerConnectCls *peer_connect_cls_head;

  /**
   * @brief Tail of linked list with peer connect closures
   */
  struct PeerConnectCls *peer_connect_cls_tail;

  /**
   * @brief Head of linked list with peer connect closures
   */
  struct Connection *connections_head;

  /**
   * @brief Tail of linked list with peer connect closures
   */
  struct Connection *connections_tail;
};


/*****************************************************************************
 * Connection-related functions                                              *
 ****************************************************************************/

/**
 * @brief Destroy a connection
 *
 * cancel all tasks, remove its memory,
 * close sockets, remove it from the DLL, ...
 *
 * @param connection The #Connection to destroy
 */
static void
connection_destroy (struct Connection *connection)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection_destroy\n");
  if (NULL != connection->handle->notify_disconnect)
  {
    connection->handle->notify_disconnect (
        connection->handle->cls, connection->cls_mq);
  }
  if (NULL != connection->notify_connect_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling notify connect task\n");
    GNUNET_SCHEDULER_cancel (connection->notify_connect_task);
  }
  if (NULL != connection->write_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling write task\n");
    GNUNET_SCHEDULER_cancel (connection->write_task);
  }
  if (NULL != connection->recv_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling recv task\n");
    GNUNET_SCHEDULER_cancel (connection->recv_task);
  }
  if (NULL != connection->sock)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "closing socket\n");
    GNUNET_NETWORK_socket_close (connection->sock);
    // FIXME rather use GNUNET_NETWORK_socket_shutdown()?
    // like this:
    // LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down socket\n");
    // if ((NULL != connection->sock) &&
    //     (GNUNET_YES != GNUNET_NETWORK_socket_shutdown (connection->sock,
    //                                                    SHUT_RDWR)))
    // {
    //   LOG (GNUNET_ERROR_TYPE_ERROR, "Faild to shutdown socket operations\n");
    // }
  }
  GNUNET_free (connection->peer_addr);
  for (struct QueuedMessage *msg_iter = connection->queued_messages_head;
       NULL != connection->queued_messages_head;
       )
  {
    struct QueuedMessage *msg_tmp = msg_iter;
    msg_iter = msg_tmp->next;
    GNUNET_free (msg_tmp->msg);
    GNUNET_CONTAINER_DLL_remove (connection->queued_messages_head,
                                 connection->queued_messages_tail,
                                 msg_tmp);
    GNUNET_free (msg_tmp);
  }
  // TODO what else?
  GNUNET_CONTAINER_DLL_remove (connection->handle->connections_head,
                               connection->handle->connections_tail,
                               connection);
  GNUNET_free (connection);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection_destroy - end\n");
}

/*****************************************************************************
 * Connection-related functions (end)                                        *
 ****************************************************************************/


/**
 * @brief Callback scheduled to run when there is something to read from the
 * socket. Reads the data from the socket and passes it to the message queue.
 *
 * @param cls Closure: Information for this socket
 */
static void
do_read (void *cls)
{
  struct Connection *connection = cls;

  ssize_t ret;
  char buf[65536] GNUNET_ALIGN;
  struct GNUNET_MessageHeader *msg;

  connection->recv_task = NULL;
  GNUNET_assert (NULL != connection->sock);
  ret = GNUNET_NETWORK_socket_recv (connection->sock,
                                    &buf,
                                    sizeof(buf));
  if (0 > ret)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Error reading from socket\n");
    GNUNET_MQ_destroy (connection->mq); // This triggers mq_destroy_impl()
    return;
  }
  if (0 == ret)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "Other peer closed connection\n");
    GNUNET_MQ_destroy (connection->mq); // This triggers mq_destroy_impl()
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Read %d bytes\n", (int) ret);
  GNUNET_assert (2 <= ret);
  msg = GNUNET_malloc (ret);
  GNUNET_memcpy (msg, buf, ret);
  GNUNET_MQ_handle_message (connection->handlers, msg);
  // TODO do proper rate limiting in sync with
}


/**
 * @brief Callback scheduled to run once the socket is ready for writing.
 * Writes the message to the socket.
 *
 * @param cls Closure: The handle of the underlay dummy
 */
static void
write_cb (void *cls)
{
  ssize_t sent;
  struct Connection *connection = cls;

  connection->write_task = NULL;
  GNUNET_assert (NULL != connection->sock);
  //{
  //  // XXX only for debugging purposes
  //  // this shows everything works as expected

  //  struct GNUNET_UNDERLAY_DUMMY_Message
  //  {
  //    struct GNUNET_MessageHeader header;
  //    // The following will be used for debugging
  //    uint64_t id; // id of the message
  //    uint64_t batch; // first batch of that peer (for this test 0 or 1)
  //    uint64_t peer; // number of sending peer (for this test 0 or 1)
  //  };



  //  struct GNUNET_UNDERLAY_DUMMY_Message *msg_dbg = connection->msg_next;
  //  LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - id: %u, batch: %u, peer: %u\n",
  //       GNUNET_ntohll (msg_dbg->id),
  //       GNUNET_ntohll (msg_dbg->batch),
  //       GNUNET_ntohll (msg_dbg->peer));
  //  //LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - size: %u\n",
  //  //     ntohs (connection->msg_next->size));
  //  //LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - (sanity) size msghdr: %u\n",
  //  //     sizeof (struct GNUNET_MessageHeader));
  //  //LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - (sanity) size msg field: %u\n",
  //  //     sizeof (msg_dbg->id));
  //}
  GNUNET_assert (NULL != connection->queued_messages_head);
  sent = GNUNET_NETWORK_socket_send (
      connection->sock,
      connection->queued_messages_head->msg,
      ntohs (connection->queued_messages_head->msg->size));
  if (GNUNET_SYSERR == sent)
  {
    //LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to send message\n");
    LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to send message: %s\n", strerror(errno));
    if (EPIPE == errno)
    {
      /* Tear down the connection */
      GNUNET_MQ_destroy (connection->mq); // This triggers mq_destroy_impl()
      return;
    }
    LOG (GNUNET_ERROR_TYPE_ERROR, "Retrying (due to failure)\n");
    /* retry */
    connection->write_task =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      connection->sock,
                                      &write_cb,
                                      connection);
    return; // TODO proper handling - don't try to resend on certain errors
            // (e.g. EPIPE)
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Successfully sent message\n");
  {
    struct QueuedMessage *tmp_msg = connection->queued_messages_head;
    GNUNET_free (tmp_msg->msg);
    GNUNET_CONTAINER_DLL_remove (connection->queued_messages_head,
                                 connection->queued_messages_tail,
                                 tmp_msg);
    GNUNET_free (tmp_msg);
  }
  // TODO reschedule for the next round. With the current implementation of the
  // single message buffer, this doesn't make sense
  //h->write_task = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
  //                                             sock_listen,
  //                                             &write_cb,
  //                                             NULL);
  GNUNET_MQ_impl_send_continue (connection->mq);
}


/**
 * @brief Callback called from the MQ to send a message over a socket.
 * Schedules the sending of the message once the socket is ready.
 *
 * @param mq The message queue
 * @param msg The message to send
 * @param impl_state The handle of the underlay dummy
 */
static void
mq_send_impl (struct GNUNET_MQ_Handle *mq,
              const struct GNUNET_MessageHeader *msg,
              void *impl_state)
{
  struct Connection *connection = impl_state;
  uint16_t msg_size = ntohs (msg->size);
  struct QueuedMessage *q_msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "from mq_send_impl\n");
  //{
  //  // XXX only for debugging purposes
  //  // this shows everything works as expected

  //  struct GNUNET_UNDERLAY_DUMMY_Message
  //  {
  //    struct GNUNET_MessageHeader header;
  //    // The following will be used for debugging
  //    uint64_t id; // id of the message
  //    uint64_t batch; // first batch of that peer (for this test 0 or 1)
  //    uint64_t peer; // number of sending peer (for this test 0 or 1)
  //  };

  //  struct GNUNET_UNDERLAY_DUMMY_Message *msg_dbg = msg;
  //  LOG (GNUNET_ERROR_TYPE_DEBUG, "id: %u, batch: %u, peer: %u\n",
  //       GNUNET_ntohll (msg_dbg->id),
  //       GNUNET_ntohll (msg_dbg->batch),
  //       GNUNET_ntohll (msg_dbg->peer));
  //}
  {
  }
  q_msg = GNUNET_new (struct QueuedMessage);
  q_msg->msg = GNUNET_malloc (msg_size);
  memset (q_msg->msg, 0, msg_size);
  GNUNET_memcpy (q_msg->msg, msg, msg_size);
  GNUNET_CONTAINER_DLL_insert_tail (connection->queued_messages_head,
                                    connection->queued_messages_tail,
                                    q_msg);
  if (NULL == connection->write_task)
  {
    connection->write_task =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      connection->sock,
                                      &write_cb,
                                      connection);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Scheduled sending of message\n");
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Found write task with no message to send!\n");
  }
}


/**
 * @brief Callback to destroy the message queue
 *
 * @param mq message queue to destroy
 * @param impl_state The handle of the underlay dummy
 */
static void
mq_destroy_impl (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Connection *connection = impl_state;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "mq_destroy_impl\n");
  connection_destroy (connection);
}


/**
 * @brief Callback to cancel sending a message.
 *
 * @param mq The message queue the message was supposed to be sent over.
 * @param impl_state The handle of the underlay dummy
 */
static void
mq_cancel_impl (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Connection *connection = impl_state;

  for (struct QueuedMessage *msg_iter = connection->queued_messages_head;
       NULL != connection->queued_messages_head;
       )
  {
    struct QueuedMessage *msg_tmp = msg_iter;
    msg_iter = msg_tmp->next;
    GNUNET_free (msg_tmp->msg);
    GNUNET_CONTAINER_DLL_remove (connection->queued_messages_head,
                                 connection->queued_messages_tail,
                                 msg_tmp);
    GNUNET_free (msg_tmp);
  }
  if (NULL != connection->write_task)
  {
    GNUNET_SCHEDULER_cancel (connection->write_task);
    connection->write_task = NULL;
  }
  // TODO anything left to clean?
}


/**
 * @brief Handle mq errors
 *
 * This is currently a stub that only logs.
 *
 * @param cls closure is unused
 * @param error the kind of error
 */
static void
mq_error_handler_impl (void *cls, enum GNUNET_MQ_Error error)
{
  LOG (GNUNET_ERROR_TYPE_ERROR, "mq_error_handler_impl: %u\n", error);
}


/**
 * @brief Set the closures for mq handlers
 *
 * This is a utility function that sets the closures of the given mq handlers
 * to a given closure
 *
 * @param handlers the list of handlers
 * @param handlers_cls the new closure for the handlers
 */
static void
set_handlers_closure (struct GNUNET_MQ_MessageHandler *handlers,
                      void *handlers_cls)
{
  GNUNET_assert (NULL != handlers);

  for (unsigned int i = 0; NULL != handlers[i].cb; i++)
    handlers[i].cls = handlers_cls;
}


/**
 * @brief Notify the api caller about a new connection.
 *
 * This connection could either be initiated by us or the connecting peer.
 * The function is supposed to be called through the scheduler.
 *
 * @param cls
 */
static void
do_notify_connect (void *cls)
{
  struct Connection *connection = cls;
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = connection->handle;
  void *cls_mq;

  connection->notify_connect_task = NULL;
  cls_mq =
    h->notify_connect(h->cls, // FIXME global cls or per connection? - seems global
                      1,
                      (const char **) &connection->peer_addr,
                      connection->mq);
  connection->handlers = GNUNET_MQ_copy_handlers (h->handlers);
  set_handlers_closure (connection->handlers, h->cls);
  if (NULL != cls_mq)
  {
    connection->cls_mq = cls_mq;
    //GNUNET_MQ_set_handlers_closure (connection->mq, connection->cls_mq);
    set_handlers_closure (connection->handlers, connection->cls_mq);
  }
}


/**
 * Accept a connection on the dummy's socket
 *
 * @param cls the hanlde to the dummy passed as closure
 */
static void
do_accept (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  struct Connection *connection;
  struct GNUNET_NETWORK_Handle *sock;
  struct sockaddr_un addr_other;
  struct sockaddr *addr_other_p;
  void *cls_mq;
  socklen_t addr_other_len = sizeof(addr_other);
  memset (&addr_other, 0, sizeof (addr_other));

  h->listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  h->sock_listen,
                                                  do_accept,
                                                  h);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Handling incoming connection\n");

  GNUNET_assert (NULL != h->sock_listen);

  LOG (GNUNET_ERROR_TYPE_INFO, "Accepting incoming connection\n");
  sock = GNUNET_NETWORK_socket_accept (h->sock_listen,
                                       (struct sockaddr *) &addr_other,
                                       &addr_other_len);
  if (NULL == sock)
  {
    //LOG(GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection, %s", strerror(errno));
    LOG (GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection\n");
    return;
  }
  if (GNUNET_OK != GNUNET_NETWORK_socket_set_blocking (sock, GNUNET_NO))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "Failed setting socket of incoming connection to non-blocking\n");
    return;
  }
  connection = GNUNET_new (struct Connection);
  connection->sock = sock;
  connection->peer_addr = GNUNET_strdup (addr_other.sun_path);
  connection->handle = h;
  LOG (GNUNET_ERROR_TYPE_INFO, "Peer connected\n");
  GNUNET_CONTAINER_DLL_insert (h->connections_head,
                               h->connections_tail,
                               connection);
  if (NULL != h->notify_connect)
  {
    // TODO maybe do some of this even if handler doesnt exist
    char **addresses = GNUNET_new_array (1, char *);
    addresses[0] = GNUNET_malloc ((sizeof (char) * strlen (addr_other.sun_path)) + 1);
    addresses[0][0] = '\0';
    // TODO get the socket name of the connecting socket or check if it doesn't
    //      have a proper name
    ////GNUNET_memcpy (addresses[0], addr_other.sun_path, strlen (addr_other.sun_path));
    //addresses[0] = GNUNET_strdup (addr_other.sun_path);
    ////char *address = GNUNET_malloc (sizeof (char) * strlen (addr_other.sun_path));
    //LOG (GNUNET_ERROR_TYPE_INFO, "addr_other_len: %u\n", addr_other_len);
    //LOG (GNUNET_ERROR_TYPE_INFO, "strlen(addr_other.sun_path): %u\n", strlen(addr_other.sun_path));
    //LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check0: %s\n", addr_other.sun_path);
    //LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check1: %s\n", addresses[0]);
    ////addr_other_p = GNUNET_NETWORK_get_addr (sock);
    ////LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check2: %s\n", addr_other_p->sa_data);
    connection->mq =
      GNUNET_MQ_queue_for_callbacks (mq_send_impl,
                                     mq_destroy_impl,
                                     mq_cancel_impl,
                                     connection, // impl_state - gets passed to _impls
                                     h->handlers, // handlers - may be NULL?
                                     mq_error_handler_impl,
                                     connection->cls_mq); // FIXME cls for error_handler
    GNUNET_assert (NULL == connection->notify_connect_task);
    connection->notify_connect_task =
      GNUNET_SCHEDULER_add_now (do_notify_connect, connection);
  }
  connection->recv_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                   connection->sock,
                                   do_read,
                                   connection);
}


/**
 * @brief Connect to another peer
 *
 * This function is scheduled and pays attention that it's not called
 * unnecessarily.
 *
 * @param cls
 */
static void
do_connect_to_peer (void *cls)
{
  struct PeerConnectCls *peer_connect_cls = cls;

  peer_connect_cls->peer_connect_task = NULL;
  GNUNET_CONTAINER_DLL_remove (peer_connect_cls->h->peer_connect_cls_head,
                               peer_connect_cls->h->peer_connect_cls_tail,
                               peer_connect_cls);
  // FIXME do we call our own api? - feels fishy
  GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (peer_connect_cls->h,
                                              peer_connect_cls->sock_name,
                                              GNUNET_MQ_PRIO_BEST_EFFORT,
                                              GNUNET_BANDWIDTH_VALUE_MAX);
  GNUNET_free (peer_connect_cls->sock_name);
  GNUNET_free (peer_connect_cls);
}


/**
 * @brief Notify core about address change.
 *
 * This is in an extra function so the callback gets called after the
 * GNUNET_CORE_UNDERLAY_DUMMY_connect() finishes.
 *
 * @param cls Closure: The handle of the dummy underlay.
 */
static void
do_notify_address_change (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  h->notify_address_change_task = NULL;
  h->notify_address_change (h->cls,
                            h->network_location_hash,
                            h->network_generation_id);
}


/**
 * @brief Handle the discovery of a certain socket.
 *
 * This is called from within the discovery of file names with the correct
 * pattern.
 * It checks whether we are already connected to this socket, are waiting for a
 * reply, it's our own socket.
 * Issue a connection if the conditions are given.
 *
 * @param cls handle to the dummy service
 * @param filename the discovered filename
 *
 * @return #GNUNET_OK indicating that the iteration through filnames is
 * supposed to continue
 */
static enum GNUNET_GenericReturnValue
discovered_socket_cb (void *cls,
                      const char *filename)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  struct PeerConnectCls *peer_connect_cls;

  if (0 == memcmp (filename,
                   h->sock_name,
                   strlen (filename)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Discovered own socket - skip\n");
    return GNUNET_OK;
  }
  LOG (
      GNUNET_ERROR_TYPE_INFO,
      "Discovered another peer with address `%s' trying to connect\n",
      filename);
  for (struct Connection *conn_iter = h->connections_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    if (0 == memcmp (filename,
                     conn_iter->peer_addr,
                     strlen (filename)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Already connected to this peer\n");
      return GNUNET_OK;
    }
  }
  for (struct PeerConnectCls *pcc_iter = h->peer_connect_cls_head;
       NULL != pcc_iter;
       pcc_iter = pcc_iter->next)
  {
    if (0 == memcmp (filename,
                     pcc_iter->sock_name,
                     strlen (filename)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Already know this peer and waiting to connect\n");
      return GNUNET_OK;
    }
  }
  // TODO check if address is already in DLL
  peer_connect_cls = GNUNET_new (struct PeerConnectCls);
  peer_connect_cls->h = h;
  peer_connect_cls->sock_name = GNUNET_strdup (filename);
  // TODO schedule a single task that iterates over DLL
  peer_connect_cls->peer_connect_task =
    GNUNET_SCHEDULER_add_now (do_connect_to_peer,
                              peer_connect_cls);
  GNUNET_CONTAINER_DLL_insert (h->peer_connect_cls_head,
                               h->peer_connect_cls_tail,
                               peer_connect_cls);

  return GNUNET_OK;
}


/**
 * @brief Discover sockets of other peers
 *
 * Sockets with a certain file name pattern are treated as candidates.
 *
 * @param cls
 */
static void
do_discover_peers (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  int ret;

  ret = GNUNET_DISK_glob (SOCK_NAME_BASE "*" SOCK_EXTENSION,
                          discovered_socket_cb,
                          h);

  h->peer_discovery_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100),
      do_discover_peers,
      h);
}


/**
 * Opens UNIX domain socket.
 *
 * It start trying with a default name and successively increases a number
 * within it, when it encounters already used sockets.
 *
 * @param cls Closure: The handle of the dummy underlay.
 */
static void
do_open_socket (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  struct sockaddr_un *addr_un;
  socklen_t addr_un_len;
  uint64_t sock_name_ctr = 0; // Append to the socket name to avoid collisions
  uint8_t ret = GNUNET_NO;
  // TODO check that everything gets freed and closed in error cases

  h->sock_listen = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
  if (NULL == h->sock_listen)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Fd does not open\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Opened socket, going to bind to address\n");

  addr_un = GNUNET_new (struct sockaddr_un);
  addr_un->sun_family = AF_UNIX;
  addr_un_len = sizeof (struct sockaddr_un);
  // TODO we might want to change this loop to schedule a new task
  do {
    GNUNET_snprintf (addr_un->sun_path,
                     addr_un_len - sizeof (sa_family_t),
                     SOCK_NAME_BASE "%u" SOCK_EXTENSION "\0", sock_name_ctr++);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Trying to bind to `%s'\n", addr_un->sun_path);
    ret = GNUNET_NETWORK_socket_bind (h->sock_listen,
                                     (struct sockaddr *) addr_un,
                                     addr_un_len);
    if ((GNUNET_OK != ret) && (98 != errno))
    {
      // Error different from Address already in use - cancel
      LOG (GNUNET_ERROR_TYPE_ERROR,
          "Faild binding to socket: %u %s (closing socket)\n",
          errno, strerror(errno));
      GNUNET_NETWORK_socket_close (h->sock_listen);
      h->sock_listen = NULL;
      GNUNET_free (addr_un);
      // TODO check that everything gets freed and closed in error cases
      return;
    }
  } while (GNUNET_OK != ret);
  LOG (GNUNET_ERROR_TYPE_INFO, "Bound to `%s'\n", addr_un->sun_path);
  h->sock_name = GNUNET_strdup (addr_un->sun_path);
  GNUNET_free (addr_un);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Mark socket as accepting connections\n");
  if (GNUNET_OK != GNUNET_NETWORK_socket_listen (h->sock_listen, BACKLOG))
  {
    //LOG (GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket: %s", strerror(errno));
    LOG (GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket (closing socket)\n");
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (h->sock_listen));
    GNUNET_free (addr_un);
    return;
  }

  if (NULL != h->notify_address_change)
  {
    // FIXME compute the network_location_hash and network_generation_id
    // FIXME _schedule_now()
    // TODO cancel and cleanup task on run and shutdown
    h->notify_address_change_task =
      GNUNET_SCHEDULER_add_now (do_notify_address_change, h);
  }

  do_discover_peers (h);

  LOG (GNUNET_ERROR_TYPE_INFO, "Going to listen for connections\n");
  h->listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  h->sock_listen,
                                                  do_accept,
                                                  h);
}


/**
 * Connect to the core underlay dummy service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param handlers array of message handlers or NULL; note that the closures
 *                 provided will be ignored and replaced with the respective
 *                 return value from @a nc
 * @param cls closure for the @a nc, @a nd and @a na callbacks
 * @param nc function to call on connect events, or NULL
 * @param nd function to call on disconnect events, or NULL
 * @param na function to call on address changes, or NULL
 * @return NULL on error
 */
struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *
GNUNET_CORE_UNDERLAY_DUMMY_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct GNUNET_MQ_MessageHandler *handlers,
                              void *cls,
                              GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect nc, // FIXME returns cls for error_handler
                              GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect nd,
                              GNUNET_CORE_UNDERLAY_DUMMY_NotifyAddressChange na)
{
  // once core connects, we create a socket
  // I guess usually we'd connect to a running transport service that already
  // has or has not its open connections

  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;
  uint32_t i;

  h = GNUNET_malloc (sizeof (struct GNUNET_CORE_UNDERLAY_DUMMY_Handle));
  h->notify_connect = nc;
  h->notify_disconnect = nd;
  h->notify_address_change = na;
  //h->handlers = handlers;
  if (NULL != handlers)
  {
    // FIXME use GNUNET_MQ_copy_handlers()
    for (i = 0; NULL != handlers[i].cb; i++)
      ;
    h->handlers = GNUNET_new_array (i + 1, struct GNUNET_MQ_MessageHandler);
    GNUNET_memcpy (h->handlers,
                   handlers,
                   i * sizeof(struct GNUNET_MQ_MessageHandler));
  }
  h->cls = cls;
  // FIXME treat 0 as special, invalid value?
  memset (&h->network_location_hash, 0, sizeof (struct GNUNET_HashCode));
  // FIXME treat 0 as special, invalid value?
  h->network_generation_id = 0;

  // FIXME this needs to potentially be cancelled in _disconnect
  do_open_socket(h); // TODO we could inline this function

  LOG (GNUNET_ERROR_TYPE_INFO, "Core connected\n");

  return h;
}


/**
 * Disconnect from the core underlay dummy service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_disconnect
(struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *handle)
{
  struct PeerConnectCls *pcc_next;
  struct Connection *conn_next;

  LOG (GNUNET_ERROR_TYPE_INFO, "Core disconnects\n");
  // TODO delete, free and close everything
  if (NULL != handle->notify_address_change_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling notify address change task\n");
    GNUNET_SCHEDULER_cancel (handle->notify_address_change_task);
  }
  if (NULL != handle->peer_discovery_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling peer discovery task\n");
    GNUNET_SCHEDULER_cancel (handle->peer_discovery_task);
  }
  for (struct PeerConnectCls *pcc = handle->peer_connect_cls_head;
       NULL != pcc;
       pcc = pcc_next)
  {
    pcc_next = pcc->next;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling peer connect task\n");
    GNUNET_SCHEDULER_cancel (pcc->peer_connect_task);
    GNUNET_CONTAINER_DLL_remove (handle->peer_connect_cls_head,
                                 handle->peer_connect_cls_tail,
                                 pcc);
    GNUNET_free (pcc->sock_name);
    GNUNET_free (pcc);
  }
  if (NULL != handle->listen_task)
  {
    // FIXME this seems not to be called (according to logs) is the listen task
    // even running?
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling listen task\n");
    GNUNET_SCHEDULER_cancel (handle->listen_task);
  }
  if (NULL != handle->sock_listen)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "closing socket\n");
    GNUNET_NETWORK_socket_close (handle->sock_listen);
  }
  for (struct Connection *conn_iter = handle->connections_head;
       NULL != conn_iter;
       conn_iter = conn_next)
  {
    // TODO consider moving MQ_destroy() into connection_destroy(), but keep in
    // mind that connection_destroy() is also called from within
    // mq_destroy_impl()
    conn_next = conn_iter->next;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Destroying a connection\n");
    GNUNET_MQ_destroy (conn_iter->mq); // This triggers mq_destroy_impl()
  }
  // TODO handlers
  GNUNET_free (handle);
}


/**
 * Notification from the CORE service to the CORE UNDERLAY DUMMY service
 * that the CORE service has finished processing a message from
 * CORE UNDERLAY DUMMY (via the @code{handlers} of
 * #GNUNET_CORE_UNDERLAY_DUMMY_connect()) and that it is thus now OK for CORE
 * UNDERLAY DUMMY to send more messages for the peer with @a mq.
 *
 * Used to provide flow control, this is our equivalent to
 * #GNUNET_SERVICE_client_continue() of an ordinary service.
 *
 * Note that due to the use of a window, CORE UNDERLAY DUMMY may send multiple
 * messages destined for the same peer even without an intermediate
 * call to this function. However, CORE must still call this function
 * once per message received, as otherwise eventually the window will
 * be full and CORE UNDERLAY DUMMY will stop providing messages to CORE on @a
 * mq.
 *
 * @param ch core underlay dummy handle
 * @param mq continue receiving on this message queue
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h,
    struct GNUNET_MQ_Handle *mq)
{
  // TODO we currently have a window size of 1 - expand it!
  /* Find the connection beloning to the mq */
  for (struct Connection *conn_iter = h->connections_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    if (mq == conn_iter->mq)
    {
      GNUNET_assert (NULL == conn_iter->recv_task);
      conn_iter->recv_task =
        GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                       conn_iter->sock,
                                       do_read,
                                       conn_iter);
      return;
    }
  }
  LOG (GNUNET_ERROR_TYPE_ERROR, "No connection with the given mq!\n");
  GNUNET_assert (0);
}


/**
 * Instruct the underlay dummy to try to connect to another peer.
 *
 * Once the connection was successful, the
 * #GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect
 * will be called with a mq towards the peer.
 *
 * @param ch core underlay dummy handle
 * @param peer_address URI of the peer to connect to
 * @param pp what kind of priority will the application require (can be
 *           #GNUNET_MQ_PRIO_BACKGROUND, we will still try to connect)
 * @param bw desired bandwidth, can be zero (we will still try to connect)
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h,
    const char *peer_address,
    enum GNUNET_MQ_PriorityPreferences pp,
    struct GNUNET_BANDWIDTH_Value32NBO bw)
{
  struct Connection *connection;
  struct sockaddr_un addr_other;
  memset (&addr_other, 0, sizeof (addr_other));

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Trying to connect to socket: `%s'\n", peer_address);
  if (0 == strcmp (peer_address, h->sock_name))
  {
    // Don't connect to own socket!
    // FIXME better handling
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not going to connect to own address\n");
    return;
  }
  /**
   * Check whether we are already connected to this peer
   *
   * This is limited as we don't always have the socket name of the other peer
   */
  for (struct Connection *conn_iter = h->connections_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    if (0 == strcmp (peer_address, conn_iter->peer_addr))
    {
      // FIXME better handling
      // FIXME this may trigger 'doubly' on empty string
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Already connected to this peer - don't try to open another connection\n");
      return;
    }
  }
  for (struct PeerConnectCls *pcc_iter = h->peer_connect_cls_head;
       NULL != pcc_iter;
       pcc_iter = pcc_iter->next)
  {
    if (0 == strcmp (peer_address,
                     pcc_iter->sock_name))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Already discovered this peer and waiting to connect\n");
      return;
    }
  }

  connection = GNUNET_new (struct Connection);
  connection->sock = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
  connection->handle = h;
  if (NULL == connection->sock)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Socket does not open\n");
    GNUNET_free (connection);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_set_blocking (connection->sock, GNUNET_NO))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Failed setting socket to non-blocking\n");
    GNUNET_free (connection);
    return;
  }

  addr_other.sun_family = AF_UNIX;
  //strcpy (addr_other.sun_path, peer_address);
  GNUNET_memcpy (addr_other.sun_path, peer_address, strlen (peer_address));
  if (GNUNET_OK != GNUNET_NETWORK_socket_connect (connection->sock,
                                                  (struct sockaddr *) &addr_other,
                                                  sizeof(addr_other)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "failed to connect to the socket: %u %s (closing socket)\n",
        errno, strerror(errno));
    GNUNET_NETWORK_socket_close (connection->sock);
    GNUNET_free (connection);
    //LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check: %s\n", addr_other.sun_path);
    return;
  }
  connection->peer_addr = GNUNET_strdup (peer_address);
  LOG (GNUNET_ERROR_TYPE_INFO, "Successfully connected to socket\n");
  connection->recv_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                   connection->sock,
                                   do_read,
                                   connection);
  connection->mq =
    GNUNET_MQ_queue_for_callbacks (mq_send_impl,
                                   mq_destroy_impl,
                                   mq_cancel_impl,
                                   connection, // impl_state - gets passed to _impls
                                   h->handlers, // handlers - may be NULL?
                                   mq_error_handler_impl,
                                   connection->cls_mq); // FIXME cls for error_handler
  // TODO fill all fields of connection
  GNUNET_CONTAINER_DLL_insert (h->connections_head,
                               h->connections_tail,
                               connection);
  if (NULL != h->notify_connect)
  {
    GNUNET_assert (NULL == connection->notify_connect_task);
    connection->notify_connect_task =
      GNUNET_SCHEDULER_add_now (do_notify_connect, connection);
  }

  //  FIXME: proper array
  //  FIXME: proper address format ("dummy:<sock_name>")
}


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/** @} */ /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_core_underlay_dummy.c */
