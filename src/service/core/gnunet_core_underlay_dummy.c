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


#include <sys/socket.h>
#include <unistd.h>
#include "gnunet_core_underlay_dummy.h"
#include "gnunet_util_lib.h"

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
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect notify_connect;
  char *recv_addr;
};


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
  int64_t fd, fd_client;
  struct sockaddr_un addr;
  struct sockaddr_un addr_client;
  int64_t len;
  char buff[BUFF_SIZE];
  struct sockaddr_un addr_from;
  socklen_t from_len = sizeof(addr_from);

  h = GNUNET_malloc (sizeof (struct GNUNET_CORE_UNDERLAY_DUMMY_Handle));
  h->notify_connect = nc;

  if ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Fd does not open");
    return NULL;
  }

  memset(&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  strcpy (addr.sun_path, SERVER_ADDR_BASE);
  unlink (SERVER_ADDR_BASE);
  if (bind (fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    // TODO use a counter to just use the 'next' free socket
    LOG(GNUNET_ERROR_TYPE_ERROR, "Faild binding to socket");
    close(fd);
    return NULL;
  }
  // TODO we could now use GNUNET_CORE_UNDERLAY_NotifyAddressChange to signal
  // that we actually got the address
  h->recv_addr = GNUNET_malloc (strlen (SERVER_ADDR_BASE));
  h->recv_addr = GNUNET_strdup (SERVER_ADDR_BASE);

  if (listen (fd, BACKLOG) < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket");
    close(fd);
    return NULL;
  }

  fd_client = accept (fd, (struct sockaddr *) &addr_client, &from_len);
  if (fd_client < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection");
    close (fd);
    close (fd_client);
    return NULL;
  }
  // TODO use GNUNET_CORE_UNDERLAY_NotifyConnect to signal that another 'peer'
  // connected
  //
  // TODO pass received messages to mq
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
  // TODO delete and close everything
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
    LOG(GNUNET_ERROR_TYPE_ERROR, "Failure opening socket");
    return;
  }

  memset (&addr, 0, sizeof (struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strcpy (addr.sun_path, CLIENT_ADDR_BASE);

  unlink (CLIENT_ADDR_BASE);
  if (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Failed to bind to socket");
    return;
  }

  addr_receiver.sun_family = AF_UNIX;
  strcpy (addr_receiver.sun_path, peer_address);
  if (connect (fd, (struct sockaddr *) &addr_receiver, sizeof(addr)) < 0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "failed to connect to the socket");
    return;
  }
  //GNUNET_MQ_queue_for_callbacks ()
  //h.notify_connect(cls, 1, peer_address, mq);
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
