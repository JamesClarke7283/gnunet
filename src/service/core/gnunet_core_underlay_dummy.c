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


// FIXME use gnunet's own wrappers!
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include "gnunet_core_underlay_dummy.h"
#include "gnunet_util_lib.h"
#include "gnunet_scheduler_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "core-underlay-dummy", __VA_ARGS__)

#define SERVER_ADDR_BASE "/tmp/gnunet-core-underlay-dummy-server-socket"
#define CLIENT_ADDR_BASE "/tmp/gnunet-core-underlay-dummy-client-socket"
#define BUFF_SIZE 8192
#define BACKLOG 10

/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_UNDERLAY_DUMMY_Handle
{
  // TODO document
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect notify_connect;
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect notify_disconnect;
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyAddressChange notify_address_change;
  void *cls;
  char *recv_addr;
  int64_t fd;
  struct GNUNET_HashCode network_location_hash;
  uint64_t network_generation_id;
  struct GNUNET_SCHEDULER_Task *listen_task;
  struct GNUNET_SCHEDULER_Task *open_socket_task;
};


/**
 * Listen for a connection on the dummy's socket
 *
 * @param cls the hanlde to the dummy passed as closure
 */
void do_listen (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  h->listen_task = NULL;
  int64_t fd_client;
  struct sockaddr_un addr_client;
  struct sockaddr_un addr_from;
  socklen_t from_len = sizeof(addr_from);

  LOG(GNUNET_ERROR_TYPE_INFO, "Listening for incoming connections\n");
  fd_client = accept (h->fd, (struct sockaddr *) &addr_client, &from_len);
  if (fd_client < 0)
  {
    //LOG(GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection, %s", strerror(errno));
    LOG(GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection\n");
    close (h->fd);
    close (fd_client);
    return;
  }
  LOG(GNUNET_ERROR_TYPE_INFO, "Peer connected\n");
  // TODO use GNUNET_CORE_UNDERLAY_NotifyConnect to signal that another 'peer'
  // connected
  //
  // TODO pass received messages to mq
  //h->listen_task = GNUNET_SCHEDULER_add_now (do_listen, h);
}


/**
 * Shut the dummy down
 *
 * Release our sockets, free memory and cancel scheduled tasks.
 *
 * @param cls handle to the dummy passed as closure
 */
void do_shutdown (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  if (NULL != h->listen_task) GNUNET_SCHEDULER_cancel (h->listen_task);
  // TODO release all sockets
  close(h->fd);
  // TODO free all memory
}

/**
 * Main running task
 *
 * Sets up socket.
 *
 * @param cls
 */
void do_open_socket (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  struct sockaddr_un addr;
  char buff[BUFF_SIZE];

  if ((h->fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Fd does not open\n");
    return;
  }

  memset(&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  unlink (SERVER_ADDR_BASE);
  if (bind (h->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0)
  {
    // TODO use a counter to just use the 'next' free socket
    LOG(GNUNET_ERROR_TYPE_ERROR, "Faild binding to socket\n");
    close(h->fd);
    return;
  }

  h->recv_addr = GNUNET_malloc (strlen (SERVER_ADDR_BASE) + 1);
  h->recv_addr = GNUNET_strdup (SERVER_ADDR_BASE);
  if (NULL != h->notify_address_change)
  {
    // FIXME compute the network_location_hash and network_generation_id
    // FIXME _schedule_now()
    h->notify_address_change (h->cls,
                              h->network_location_hash,
                              h->network_generation_id);
  }

  LOG(GNUNET_ERROR_TYPE_INFO, "Mark socket as accepting connections\n");
  if (listen (h->fd, BACKLOG) < 0)
  {
    //LOG(GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket: %s", strerror(errno));
    LOG(GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket\n");
    close(h->fd);
    return;
  }
  LOG(GNUNET_ERROR_TYPE_INFO, "Going to listen for connections\n");

  h->listen_task = GNUNET_SCHEDULER_add_now (do_listen, h);
  LOG(GNUNET_ERROR_TYPE_INFO, "Listen task: %p\n", h->listen_task);
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

  h = GNUNET_malloc (sizeof (struct GNUNET_CORE_UNDERLAY_DUMMY_Handle));
  h->notify_connect = nc;
  h->notify_disconnect = nd;
  h->notify_address_change = na;
  h->cls = cls;
  // FIXME treat 0 as special, invalid value?
  memset (&h->network_location_hash, 0, sizeof (struct GNUNET_HashCode));
  // FIXME treat 0 as special, invalid value?
  h->network_generation_id = 0;

  // FIXME this needs to potentially be cancelled in _disconnect
  h->open_socket_task = GNUNET_SCHEDULER_add_now (do_open_socket, h);

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
  LOG (GNUNET_ERROR_TYPE_INFO, "listen task: %p\n", handle->listen_task);
  // TODO delete and close everything
  if (NULL != handle->listen_task)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "Cancelling listen task\n");
    GNUNET_SCHEDULER_cancel (handle->listen_task);
  }
  if (NULL != handle->open_socket_task)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "Cancelling open socket task\n");
    GNUNET_SCHEDULER_cancel (handle->open_socket_task);
  }

  //GNUNET_SCHEDULER_shutdown ();
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
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *ch,
    const char *peer_address,
    enum GNUNET_MQ_PriorityPreferences pp,
    struct GNUNET_BANDWIDTH_Value32NBO bw)
{
  int64_t fd;
  struct sockaddr_un addr;
  struct sockaddr_un addr_receiver;

  if ((fd = socket (AF_UNIX, SOCK_STREAM, 0) ) < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Failure opening socket\n");
    return;
  }

  memset (&addr, 0, sizeof (struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strcpy (addr.sun_path, CLIENT_ADDR_BASE);

  unlink (CLIENT_ADDR_BASE);
  if (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Failed to bind to socket\n");
    return;
  }

  addr_receiver.sun_family = AF_UNIX;
  strcpy (addr_receiver.sun_path, peer_address);
  if (connect (fd, (struct sockaddr *) &addr_receiver, sizeof(addr)) < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "failed to connect to the socket\n");
    return;
  }
  //GNUNET_MQ_queue_for_callbacks ()
  //h.notify_connect(cls, 1, peer_address, mq); // if non NULL!
  //  FIXME: proper array
  //  FIXME: proper address format
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
