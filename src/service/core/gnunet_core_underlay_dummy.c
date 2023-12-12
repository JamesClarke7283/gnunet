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
#define BUFF_SIZE 8192
#define BACKLOG 10

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
   * Array of message handlers given by the client.
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Message queue towards the connected peer.
   * TODO our implementation currently allows for only one connected peer -
   * build more flexible data structures.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Closure for the mq towards the client.
   */
  void *cls_mq;

  /**
   * Closure for handlers TODO which handlers???
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
   * Socket for the connected peer.
   * TODO our implementation currently allows for only one connected peer -
   * build more flexible data structures.
   */
  struct GNUNET_NETWORK_Handle *sock;

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
   * Task waiting for incoming messages.
   */
  struct GNUNET_SCHEDULER_Task *recv_task;

  /**
   * Task to notify core about address changes.
   */
  struct GNUNET_SCHEDULER_Task *notify_address_change_task;

  /**
   * Task waiting until the socket becomes ready to be written to.
   */
  struct GNUNET_SCHEDULER_Task *write_task;

  /**
   * Currently handled message.
   */
  struct GNUNET_MessageHeader *msg_next;
  // TODO create mechanism to manage peers/queues
};


/**
 * @brief Callback scheduled to run when there is something to read from the
 * socket. Reads the data from the socket and passes it to the message queue.
 *
 * @param cls Closure: The hanlde to the underlay dummy
 */
static void
do_read (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  ssize_t ret;
  char buf[65536] GNUNET_ALIGN;
  struct GNUNET_MessageHeader *msg;

  h->recv_task = NULL;
  ret = GNUNET_NETWORK_socket_recv (h->sock,
                                    buf,
                                    sizeof(buf));
  //LOG (GNUNET_ERROR_TYPE_INFO, "Read %d bytes\n", (int) ret);
  msg = GNUNET_malloc (ret);
  GNUNET_memcpy (msg, buf, ret);
  GNUNET_MQ_handle_message (h->handlers, msg);
  h->recv_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                h->sock,
                                                do_read,
                                                h);
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
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  h->write_task = NULL;
  sent = GNUNET_NETWORK_socket_send (h->sock,
                                     h->msg_next,
                                     sizeof(h->msg_next));
  if (GNUNET_SYSERR == sent)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to send message\n");
    return; // TODO proper handling
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "Successfully sent message\n");
  GNUNET_free (h->msg_next);
  h->msg_next = NULL;
  // TODO reschedule for the next round. With the current implementation of the
  // single message buffer, this doesn't make sense
  //h->write_task = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
  //                                             sock_listen,
  //                                             &write_cb,
  //                                             NULL);
  // TODO GNUNET_MQ_impl_send_continue
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
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = impl_state;

  LOG(GNUNET_ERROR_TYPE_INFO, "from mq_send_impl\n");
  if (NULL != h->msg_next) return; // This is a very sloppy implementation - a
                                   // dummy. This might cause problems later
  h->msg_next = GNUNET_new (struct GNUNET_MessageHeader);
  GNUNET_memcpy (h->msg_next, msg, sizeof (msg));
  if (NULL == h->write_task)
  {
    h->write_task =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      h->sock,
                                      &write_cb,
                                      h);
    LOG(GNUNET_ERROR_TYPE_INFO, "Scheduled sending of message\n");
  }
  else
  {
    LOG(GNUNET_ERROR_TYPE_INFO, "Not scheduled sending of message - already scheduled a task for that\n");
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
  // TODO
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
  // TODO
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

  struct GNUNET_NETWORK_Handle *sock;
  struct sockaddr_un addr_other;
  struct sockaddr *addr_other_p;
  socklen_t addr_other_len = sizeof(addr_other);

  GNUNET_assert (NULL != h->sock_listen);
  GNUNET_assert (NULL == h->sock);

  h->listen_task = NULL;

  LOG(GNUNET_ERROR_TYPE_INFO, "Accepting incoming connection\n");
  sock = GNUNET_NETWORK_socket_accept (h->sock_listen,
                                       (struct sockaddr *) &addr_other,
                                       &addr_other_len);
  if (NULL == sock)
  {
    //LOG(GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection, %s", strerror(errno));
    LOG(GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection\n");
    return;
  }
  h->sock = sock;
  LOG(GNUNET_ERROR_TYPE_INFO, "Peer connected\n");
  // TODO create mechanism to manage peers
  if (NULL != h->notify_connect)
  {
    // TODO maybe do some of this even if handler doesnt exist
    char **addresses = GNUNET_new_array (1, char *);
    addresses[0] = GNUNET_malloc (sizeof (char) * strlen (addr_other.sun_path));
    addresses[0][0] = '\0';
    //GNUNET_memcpy (addresses[0], addr_other.sun_path, strlen (addr_other.sun_path));
    addresses[0] = GNUNET_strdup (addr_other.sun_path);
    //char *address = GNUNET_malloc (sizeof (char) * strlen (addr_other.sun_path));
    LOG (GNUNET_ERROR_TYPE_INFO, "addr_other_len: %u\n", addr_other_len);
    LOG (GNUNET_ERROR_TYPE_INFO, "strlen(addr_other.sun_path): %u\n", strlen(addr_other.sun_path));
    LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check0: %s\n", addr_other.sun_path);
    LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check1: %s\n", addresses[0]);
    //addr_other_p = GNUNET_NETWORK_get_addr (sock);
    //LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check2: %s\n", addr_other_p->sa_data);
    h->mq =
      GNUNET_MQ_queue_for_callbacks (mq_send_impl,
                                     mq_destroy_impl,
                                     mq_cancel_impl,
                                     h, // impl_state - gets passed to _impls
                                        // TODO we probably need to replace
                                        // this by Queues per peer (or so)
                                     h->handlers, // handlers - may be NULL?
                                     NULL, // mq_error_handler_impl
                                     NULL);// cls
    h->cls_mq = h->notify_connect (h->cls, 1, (const char **) addresses, h->mq);
  }
  GNUNET_assert (NULL == h->recv_task);
  h->recv_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                h->sock,
                                                do_read,
                                                h);
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

  h->notify_address_change (h->cls,
                            h->network_location_hash,
                            h->network_generation_id);
}


/**
 * Opens UNIX domain socket.
 *
 * @param cls Closure: The handle of the dummy underlay.
 */
static void
do_open_socket (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  struct sockaddr_un *addr_un;
  socklen_t addr_un_len;
  char buff[BUFF_SIZE];
  uint64_t sock_name_ctr; // Append to the socket name to avoid collisions
  uint8_t ret;
  // TODO check that everything gets freed and closed in error cases

  h->sock_listen = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
  if (NULL == h->sock_listen)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Fd does not open\n");
    return;
  }
  LOG(GNUNET_ERROR_TYPE_INFO, "Opened socket, going to bind to address\n");

  addr_un = GNUNET_new (struct sockaddr_un);
  addr_un->sun_family = AF_UNIX;
  addr_un_len = sizeof (struct sockaddr_un);
  // TODO we might want to change this loop to schedule a new task
  do {
    // TODO GNUNET_sprintf()?
    sprintf (addr_un->sun_path, SOCK_NAME_BASE "%u\0", sock_name_ctr++);
    LOG (GNUNET_ERROR_TYPE_INFO, "Trying to bind to `%s'\n", addr_un->sun_path);
    ret = GNUNET_NETWORK_socket_bind (h->sock_listen,
                                     (struct sockaddr *) addr_un,
                                     addr_un_len);
    if ((GNUNET_OK != ret) && (98 != errno))
    {
      // Error different from Address already in use - cancel
      LOG(GNUNET_ERROR_TYPE_ERROR, "Faild binding to socket: %u %s\n", errno, strerror(errno));
      GNUNET_NETWORK_socket_close (h->sock_listen);
      h->sock_listen = NULL;
      GNUNET_free (addr_un);
      // TODO check that everything gets freed and closed in error cases
      return;
    }
  } while (GNUNET_OK != ret);
  LOG(GNUNET_ERROR_TYPE_INFO, "Bound to `%s'\n", addr_un->sun_path);
  h->sock_name = GNUNET_strdup (addr_un->sun_path);
  GNUNET_free (addr_un);

  if (NULL != h->notify_address_change)
  {
    // FIXME compute the network_location_hash and network_generation_id
    // FIXME _schedule_now()
    h->notify_address_change_task =
      GNUNET_SCHEDULER_add_now (do_notify_address_change, h);
  }

  LOG(GNUNET_ERROR_TYPE_INFO, "Mark socket as accepting connections\n");
  if (GNUNET_OK != GNUNET_NETWORK_socket_listen (h->sock_listen, BACKLOG))
  {
    //LOG(GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket: %s", strerror(errno));
    LOG(GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket\n");
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (h->sock_listen));
    GNUNET_free (addr_un);
    return;
  }
  LOG(GNUNET_ERROR_TYPE_INFO, "Going to listen for connections\n");

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
                              GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect nc,
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

  LOG(GNUNET_ERROR_TYPE_INFO, "Core connected\n");

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
  LOG (GNUNET_ERROR_TYPE_INFO, "Core disconnects\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Core disconnects\n");
  // TODO delete, free and close everything
  if (NULL != handle->listen_task)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "Cancelling listen task\n");
    GNUNET_SCHEDULER_cancel (handle->listen_task);
  }
  if (NULL != handle->sock_listen)
  {
    GNUNET_NETWORK_socket_close (handle->sock_listen);
  }
  if (NULL != handle->recv_task)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "Cancelling recv task\n");
    GNUNET_SCHEDULER_cancel (handle->recv_task);
  }
  if (NULL != handle->sock)
  {
    GNUNET_NETWORK_socket_close (handle->sock);
  }
  GNUNET_free (handle->sock_name);
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
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *ch,
    struct GNUNET_MQ_Handle *mq)
{
  // TODO we currently have a window size of 1 - expand it!
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
  struct sockaddr_un addr_other;

  LOG(GNUNET_ERROR_TYPE_INFO, "Trying to connect to socket: `%s'\n", peer_address);
  if (0 == strcmp (peer_address, h->sock_name))
  {
    // Don't connect to own socket!
    // FIXME better handling
    LOG(GNUNET_ERROR_TYPE_INFO, "Not going to connect to own address\n");
    return;
  }
  GNUNET_assert (NULL == h->sock);
  h->sock = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
  if (NULL == h->sock)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Socket does not open\n");
    return;
  }

  addr_other.sun_family = AF_UNIX;
  //strcpy (addr_other.sun_path, peer_address);
  GNUNET_memcpy (addr_other.sun_path, peer_address, strlen (peer_address));
  if (GNUNET_OK != GNUNET_NETWORK_socket_connect (h->sock,
                                                  (struct sockaddr *) &addr_other,
                                                  sizeof(addr_other)))
                                                  //sizeof(struct sockaddr_un)))
                                                  //sizeof(struct sockaddr)))
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "failed to connect to the socket: %u %s\n", errno, strerror(errno));
    //LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check: %s\n", addr_other.sun_path);
    return;
  }
  LOG(GNUNET_ERROR_TYPE_INFO, "Successfully connected to socket\n");
  GNUNET_assert (NULL == h->recv_task);
  h->recv_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                h->sock,
                                                do_read,
                                                h);
  GNUNET_assert (NULL == h->mq);
  h->mq =
    GNUNET_MQ_queue_for_callbacks (mq_send_impl,
                                   mq_destroy_impl,
                                   mq_cancel_impl,
                                   h, // impl_state - gets passed to _impls
                                      // TODO we probably need to replace
                                      // this by Queues per peer (or so)
                                   h->handlers, // handlers - may be NULL?
                                   NULL, // mq_error_handler_impl
                                   NULL);
  if (NULL != h->notify_connect)
  {
    h->notify_connect(h->cls,
                      1,
                      (const char **) &peer_address, // FIXME put on heap -
                                                     // don't pass stack
                                                     // address
                      h->mq);
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
