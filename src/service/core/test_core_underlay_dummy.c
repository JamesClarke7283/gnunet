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
 * @author ch3
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

#include "gnunet_core_underlay_dummy.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "core", __VA_ARGS__)

#define SOCK_NAME_BASE "/tmp/gnunet-core-underlay-dummy-socket"
#define SOCK_EXTENSION ".sock"

#define MTYPE 12345
#define NUMBER_MESSAGES 10
/* Number of open queues per peer - currently only 1 or 2 make sense */
#define NUMBER_CONNECTIONS 2
#define NUMBER_SENDING_PEERS 2

// TODO we could implement checks for early success and tear everything down

struct DummyContext;

struct Connection
{
  struct Connection *next;
  struct Connection *prev;
  struct GNUNET_MQ_Handle *mq;
  struct DummyContext *dc;
  uint32_t result_replys; /* highest index */
};

struct DummyContext
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;
  struct Connection *conn_head;
  struct Connection *conn_tail;
  // XXX:
  //struct Connection open_connections[]; // duplicate structure just for
  //                                      // convenience
  uint32_t num_open_connections;
} dc0, dc1;


struct GNUNET_UNDERLAY_DUMMY_Message
{
  struct GNUNET_MessageHeader header;
  // The following will be used for debugging
  uint64_t id; // id of the message
  uint64_t batch; // first batch of that peer (for this test 0 or 1)
  uint64_t peer; // number of sending peer (for this test 0 or 1)
};


uint8_t result_address_callback = GNUNET_NO;
uint8_t result_connect_cb_0 = GNUNET_NO;
uint8_t result_connect_cb_1 = GNUNET_NO;
uint32_t result_replys_0 = 0;
uint32_t result_replys_1 = 0;

static struct GNUNET_SCHEDULER_Task *timeout_task;

/**
 * @brief Notify about an established connection.
 *
 * @param cls the closure given to the 'service' on
 * GNUNET_CORE_UNDERLAY_DUMMY_connect
 * @param num_addresses number of addresses connected to the incoming
 *                      connection
 * @param addresses string represenation of the @a num_addresses addresses
 *                  connected to the incoming connection
 * @param mq
 *
 * @return The returned value overwrites the cls set in the handlers for this
 * mq. If NULL, the cls from the original handlers array is used.
 */
void *notify_connect_cb (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq)
{
  struct DummyContext *dc = (struct DummyContext *) cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_UNDERLAY_DUMMY_Message *msg;
  struct Connection *connection;

  if (0 == num_addresses)
  {
  LOG (GNUNET_ERROR_TYPE_INFO,
      "(%u) Got notified about successful connection to peer with %u address\n",
      dc == &dc0 ? 0 : 1,
      num_addresses);
  }
  else
  {
  LOG (GNUNET_ERROR_TYPE_INFO,
      "(%u) Got notified about successful connection to peer with %u address: `%s'\n",
      dc == &dc0 ? 0 : 1,
      num_addresses,
      addresses[num_addresses - 1]);
  }
  /* Note test result */
  if (GNUNET_NO == result_connect_cb_0)
  {
    result_connect_cb_0 = GNUNET_YES;
  }
  else if (GNUNET_YES == result_connect_cb_0 &&
             GNUNET_NO == result_connect_cb_1)
  {
    result_connect_cb_1 = GNUNET_YES;
  }
  if (NUMBER_CONNECTIONS <= dc->num_open_connections)
  {
    /* Don't accept further connections */
    // TODO how to handle an unwanted connection?
    // TODO close mq
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "(%u) Aleready have maximum connections open - not going to open another one.\n",
        dc == &dc0 ? 0 : 1);
    // TODO it might be really bad to call _destroy() during the
    // notify_connect_cb() - schedule?
    GNUNET_MQ_destroy (mq);
    return NULL;
  }
  connection = GNUNET_new (struct Connection);
  connection->mq = mq;
  connection->dc = dc;
  connection->result_replys = 0;
  GNUNET_MQ_set_handlers_closure (mq, connection);
  GNUNET_CONTAINER_DLL_insert (dc->conn_head,
                               dc->conn_tail,
                               connection);
  dc->num_open_connections++;
  // FIXME get it in sync: number of messages sent (per connection) vs. number
  // of messages received (per peer)
  if (NUMBER_SENDING_PEERS == 1 &&
      &dc1 == dc)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "(%u) Not going to send messages - only one peer is supposed to\n",
        dc == &dc0 ? 0 : 1);
    return connection;
  }
  for (uint64_t i = 0; i < NUMBER_MESSAGES; i++)
  {
    env = GNUNET_MQ_msg (msg, MTYPE); // TODO usually we wanted to keep the
                                      // envelopes to potentially cancel the
                                      // message
    // a real implementation would set message fields here
    msg->id = GNUNET_htonll (i);
    msg->batch = GNUNET_htonll (dc->num_open_connections - 1);
    msg->peer = GNUNET_htonll (&dc0 == dc ? 0 : 1);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "(%u) Going to send message %u through message queue %u\n",
        &dc0 == dc ? 0 : 1,
        i,
        dc->num_open_connections - 1);
    GNUNET_MQ_send (mq, env);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "(%u) Sent message %u through message queue %u\n",
        &dc0 == dc ? 0 : 1,
        i,
        dc->num_open_connections - 1);
  }

  return connection;
}


// TODO
//typedef void (*GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect) (
//  void *cls,
//  void *handler_cls);


void address_change_cb (void *cls,
                        struct GNUNET_HashCode network_location_hash,
                        uint64_t network_generation_id)
{
  struct DummyContext *dc = cls;

  result_address_callback = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_INFO,
      "(%u) Got informed of address change\n",
      dc == &dc0 ? 0 : 1);
  if (&dc0 == dc)
  {
    /* We cannot know which peer has which socket - try both */
    GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                                SOCK_NAME_BASE "0" SOCK_EXTENSION,
                                                GNUNET_MQ_PRIO_BEST_EFFORT,
                                                GNUNET_BANDWIDTH_VALUE_MAX);
    GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                                SOCK_NAME_BASE "1" SOCK_EXTENSION,
                                                GNUNET_MQ_PRIO_BEST_EFFORT,
                                                GNUNET_BANDWIDTH_VALUE_MAX);
  }
  else if (NUMBER_SENDING_PEERS == 2 &&
           &dc1 == dc)
  {
    /* We cannot know which peer has which socket - try both */
    GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                                SOCK_NAME_BASE "0" SOCK_EXTENSION,
                                                GNUNET_MQ_PRIO_BEST_EFFORT,
                                                GNUNET_BANDWIDTH_VALUE_MAX);
    GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                                SOCK_NAME_BASE "1" SOCK_EXTENSION,
                                                GNUNET_MQ_PRIO_BEST_EFFORT,
                                                GNUNET_BANDWIDTH_VALUE_MAX);
  }
}

void do_shutdown (void *cls)
{
  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (dc0.h);
  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (dc1.h);
  for (struct Connection *conn_iter = dc0.conn_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    result_replys_0 = result_replys_0 + conn_iter->result_replys;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "added %u replies for this connection\n",
         conn_iter->result_replys);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "counted %u replies for peer 0\n",
       result_replys_0);
  for (struct Connection *conn_iter = dc1.conn_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    result_replys_1 = result_replys_1 + conn_iter->result_replys;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "added %u replies for this connection\n",
         conn_iter->result_replys);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "counted %u replies for peer 1\n",
       result_replys_1);
  LOG(GNUNET_ERROR_TYPE_INFO, "Disconnected from underlay dummy\n");
}


void do_timeout (void *cls)
{
  timeout_task = NULL;

  LOG(GNUNET_ERROR_TYPE_INFO, "Disconnecting from underlay dummy\n");
  GNUNET_SCHEDULER_shutdown ();
}


static void
handle_test (void *cls, const struct GNUNET_UNDERLAY_DUMMY_Message *msg)
{
  struct Connection *connection = cls;

  GNUNET_assert (NULL != cls);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "received test message %u (%u, %u)\n",
       GNUNET_ntohll (msg->id),
       GNUNET_ntohll (msg->batch),
       GNUNET_ntohll (msg->peer));
  if (connection->dc->conn_head == connection)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "on connection 0\n");
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "on connection 1\n");
  }

  // TODO check the content

  connection->result_replys++;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(%u messages on this channel now)\n",
       connection->result_replys);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(peer %u)\n", &dc0 == connection->dc ? 0 : 1);
  GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (connection->dc->h,
                                               connection->mq);
}


static void run_test (void *cls)
{
  GNUNET_log_setup ("test-core-underlay-dummy", "DEBUG", NULL);
  dc0.num_open_connections = 0;
  dc1.num_open_connections = 0;
  struct GNUNET_MQ_MessageHandler handlers[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_UNDERLAY_DUMMY_Message, NULL),
    GNUNET_MQ_handler_end ()
  };
  LOG(GNUNET_ERROR_TYPE_INFO, "Connecting to underlay dummy\n");
  dc0.h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, //cfg
                                              handlers,
                                              &dc0, // cls
                                              notify_connect_cb,
                                              NULL, // nd
                                              address_change_cb);
  LOG(GNUNET_ERROR_TYPE_INFO, "(0) Connected to underlay dummy\n");
  dc1.h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, //cfg
                                              handlers,
                                              &dc1, // cls
                                              notify_connect_cb,
                                              NULL, // nd
                                              address_change_cb);
  LOG(GNUNET_ERROR_TYPE_INFO, "(1) Connected to underlay dummy 2\n");
  GNUNET_SCHEDULER_add_shutdown (do_shutdown, NULL);
  timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                               do_timeout,
                                               NULL);
}

int main (void)
{
  GNUNET_SCHEDULER_run (run_test, NULL);

  if (GNUNET_YES != result_address_callback) return -1;
  if (GNUNET_YES != result_connect_cb_0) return -1;
  if (GNUNET_YES != result_connect_cb_1) return -1;
  if (NUMBER_MESSAGES * NUMBER_SENDING_PEERS != result_replys_0)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Peer 0 received %u of %u messages\n",
        result_replys_0,
        NUMBER_MESSAGES * NUMBER_SENDING_PEERS);
    // XXX:
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Peer 1 received %u of %u messages\n",
        result_replys_1,
        NUMBER_MESSAGES * NUMBER_SENDING_PEERS);
    return -1;
  }
  if (NUMBER_MESSAGES * NUMBER_SENDING_PEERS != result_replys_1)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Peer 1 received %u of %u messages\n",
        result_replys_1,
        NUMBER_MESSAGES * NUMBER_SENDING_PEERS);
    return -1;
  }
  return 0;
}


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/** @} */ /* end of group */

/** @} */ /* end of group addition */

/* end of test_gnunet_core_underlay_dummy.c */
