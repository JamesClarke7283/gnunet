/*
      This file is part of GNUnet
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
 * @file src/service/core/test_core_plugin_underlay_dummy.c
 * @brief a plugin to provide the API for running test cases.
 * @author ch3
 * TODO:
 *  - try to avoid generic pointer and globally known struct UnderlayDummyState
 *  - cleaner separate the waiting for connection to finish out of _cmd_connect()
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

#include "gnunet_core_underlay_dummy.h"


#define NUM_MESSAGES 10
#define NUM_CHANNELS 2

#define MTYPE 12345

/**
 * @brief Generic logging shortcut
 */
#define LOG(kind, ...) \
  GNUNET_log_from_nocheck (kind, "core-plugin-underlay-dummy", __VA_ARGS__)


struct GNUNET_UNDERLAY_DUMMY_Message
{
  struct GNUNET_MessageHeader header;
  // The following will be used for debugging
  uint64_t id; // id of the message
  uint64_t batch; // first batch of that peer (for this test 0 or 1)
  //uint64_t peer; // number of sending peer (for this test 0 or 1)
};


typedef void
(*handle_msg)(
  void *cls,
  const struct GNUNET_UNDERLAY_DUMMY_Message *msg);


struct UnderlayDummyState;


struct Channel
{
  struct UnderlayDummyState *uds;
  struct GNUNET_MQ_Handle *mq;
};


struct UnderlayDummyState
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;
  // The number of channels supposed to reach
  uint32_t num_channels_target;
  struct GNUNET_TESTING_AsyncContext ac;
  const char *node_id;
  // FIXME: set cls per handler
  void *handlers_cls;
  uint32_t handlers_len;
  handle_msg *handlers;
  struct Channel **channels;
  uint32_t channels_len;
};


struct UnderlayDummyRecvState
{
  uint64_t num_messages_target;
  uint64_t num_messages_received;
  struct GNUNET_TESTING_AsyncContext ac;
};


struct UnderlayDummySendState
{
  uint64_t num_messages;
  uint64_t num_channels;
};


/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
connect_traits (void *cls,
                const void **ret,
                const char *trait,
                unsigned int index)
{
  struct UnderlayDummyState *uds = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_CORE_make_trait_connect (uds),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


static void
handle_test (void *cls, const struct GNUNET_UNDERLAY_DUMMY_Message *msg)
{
  struct Channel *channel = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received message (%u, %u) - going to call handlers\n",
      msg->id,
      msg->batch);
  // TODO call registered handlers
  for (uint32_t i = 0; i < channel->uds->handlers_len; i++)
  {
    // FIXME: set cls per handler
    channel->uds->handlers[i] (channel->uds->handlers_cls, msg);
  }

  GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (channel->uds->h,
                                               channel->mq);
}


void *notify_connect_cb (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq)
{
  struct UnderlayDummyState *uds = cls;
  struct Channel *channel;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "A new connection was established\n");

  channel = GNUNET_new (struct Channel);
  channel->uds = uds;
  channel->mq = mq;
  GNUNET_array_append (uds->channels,
                       uds->channels_len,
                       channel);

  if (uds->num_channels_target == uds->channels_len)
  {
    GNUNET_TESTING_async_finish (&uds->ac);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "(post connect_cb _async_finish)\n");
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(post connect_cb - %u of %u)\n",
      uds->channels_len,
      uds->num_channels_target);
  return channel;
}


void address_change_cb (void *cls,
                        struct GNUNET_HashCode network_location_hash,
                        uint64_t network_generation_id)
{
  struct UnderlayDummyState *uds = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Our set of addresses changed\n");
}


static void
exec_connect_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummyState *uds = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(%s) Going to connect to underlay dummy\n",
      uds->node_id);
  struct GNUNET_MQ_MessageHandler handlers[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_UNDERLAY_DUMMY_Message, NULL),
    GNUNET_MQ_handler_end ()
  };

  uds->h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, // cfg
                                               handlers,
                                               uds, // cls
                                               notify_connect_cb,
                                               NULL, // nd
                                               address_change_cb);

}


static void
exec_connect_cleanup (void *cls)
{
  struct UnderlayDummyState *uds = cls;

  GNUNET_assert (NULL != uds->h);
  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (uds->h);
}


const struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_connect (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  const char* node_id,
  uint32_t num_channels)
{
  struct UnderlayDummyState *uds;

  uds = GNUNET_new (struct UnderlayDummyState);
  uds->node_id = GNUNET_strdup (node_id);
  uds->handlers = GNUNET_new_array (0, handle_msg);
  uds->handlers_len = 0;
  uds->num_channels_target = num_channels;
  uds->channels = GNUNET_new_array (0, struct Channel *);
  return GNUNET_TESTING_command_new_ac (
      uds, // state
      label,
      &exec_connect_run,
      &exec_connect_cleanup,
      &connect_traits,
      &uds->ac);
}


void
handle_msg_test (void *cls,
                 const struct GNUNET_UNDERLAY_DUMMY_Message *msg)
{
  struct UnderlayDummyRecvState *udrs = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "received test message %u (%u)\n",
       GNUNET_ntohll (msg->id),
       GNUNET_ntohll (msg->batch));
  udrs->num_messages_received++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received %u messages (of %u)\n",
      udrs->num_messages_received,
      udrs->num_messages_target);
  if (udrs->num_messages_target > udrs->num_messages_received) return;
  if (udrs->num_messages_target == udrs->num_messages_received)
    GNUNET_TESTING_async_finish (&udrs->ac);
  if (udrs->num_messages_target < udrs->num_messages_received)
    GNUNET_assert (0);
}


static void
exec_recv_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummyRecvState *udrs = cls;
  struct UnderlayDummyState *uds;

  if (GNUNET_OK != GNUNET_CORE_get_trait_connect (
        // TODO make the "connect" an input to the command
        GNUNET_TESTING_interpreter_lookup_command (is, "connect"),
        (const void**) &uds)) {
    GNUNET_assert (0);
  };
  // FIXME: set cls per hanlder
  GNUNET_array_append (uds->handlers,
                       uds->handlers_len,
                       &handle_msg_test);
  uds->handlers_cls = udrs;
}


static void
exec_recv_cleanup (void *cls)
{
  struct UnderlayDummyState *uds = cls;

  // TODO
}


const struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_recv (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  uint64_t num_messages)
{
  struct UnderlayDummyRecvState *udrs;

  udrs = GNUNET_new (struct UnderlayDummyRecvState);
  udrs->num_messages_target = num_messages;
  udrs->num_messages_received = 0;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_recv)\n");
  return GNUNET_TESTING_command_new_ac (
      udrs, // state
      label,
      &exec_recv_run,
      &exec_recv_cleanup,
      NULL,
      &udrs->ac);
}


static void
exec_send_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummySendState *udss = cls;
  struct UnderlayDummyState *uds;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_UNDERLAY_DUMMY_Message *msg;

  if (GNUNET_OK != GNUNET_CORE_get_trait_connect (
        GNUNET_TESTING_interpreter_lookup_command (is, "connect"),
        (const void**) &uds)) {
    GNUNET_assert (0);
  };

  GNUNET_assert (NULL != uds->channels);
  GNUNET_assert (udss->num_channels == uds->channels_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Going to send %u messages on %u channels\n",
      udss->num_messages,
      udss->num_channels);
  for (uint32_t i = 0; i < udss->num_channels; i++)
  {
    for (uint64_t ii = 0; ii < udss->num_messages; ii++)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to send message %u (channel %u)\n", ii, i);
      env = GNUNET_MQ_msg (msg, MTYPE); // TODO usually we wanted to keep the
                                        // envelopes to potentially cancel the
                                        // message
      msg->id = GNUNET_htonll (ii);
      msg->batch = GNUNET_htonll (i);
      GNUNET_MQ_send (uds->channels[i]->mq, env);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Sent message %u (channel %u)\n", ii, i);
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sent messages\n");
}


static void
exec_send_cleanup (void *cls)
{
  struct UnderlayDummyState *uds = cls;

}


const struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_send (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  uint64_t num_messages,
  uint32_t num_channels)
{
  struct UnderlayDummySendState *udss;

  udss = GNUNET_new (struct UnderlayDummySendState);
  udss->num_messages = num_messages;
  udss->num_channels = num_channels;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_send)\n");
  return GNUNET_TESTING_command_new (
      udss, // state
      label,
      &exec_send_run,
      &exec_send_cleanup,
      NULL);
}


GNUNET_TESTING_MAKE_PLUGIN (
  libgnunet_test_core,
  underlay_dummy,
    GNUNET_TESTING_cmd_make_unblocking (
      GNUNET_CORE_cmd_connect ("connect",
                               GNUNET_OS_PROCESS_EXITED,
                               0,
                               my_node_id,
                               NUM_CHANNELS)),
    GNUNET_TESTING_cmd_make_unblocking (
      GNUNET_CORE_cmd_recv ("recv",
                            GNUNET_OS_PROCESS_EXITED,
                            0,
                            NUM_MESSAGES)),
    /* Wait until underlay dummy is connected to another peer: */
    GNUNET_TESTING_cmd_finish ("connect-finished",
                               "connect",
                               GNUNET_TIME_relative_multiply (
                                 GNUNET_TIME_UNIT_SECONDS, 2)),
    /* Wait until all 'peers' are connected: */
    GNUNET_TESTING_cmd_barrier_reached ("connected-reached",
                                        "connected"),
    // The following is currently far from 'the testing way'
    // receive and send should be different commands
    GNUNET_CORE_cmd_send ("send",
                          GNUNET_OS_PROCESS_EXITED,
                          0,
                          NUM_MESSAGES,
                          NUM_CHANNELS),
    GNUNET_TESTING_cmd_finish ("recv-finished",
                               "recv",
                               GNUNET_TIME_relative_multiply (
                                 GNUNET_TIME_UNIT_SECONDS, 5)),
    GNUNET_TESTING_cmd_end ()
  )


// testing_core_cmd_connecting_peers.c takes as inspiration
// FIXME: likely not ideally placed here, move to its own file
GNUNET_CORE_SIMPLE_DUMMY_UNDERLAY_TRAITS (
    GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT, GNUNET_CORE)


/* end of src/service/core/test_core_plugin_underlay_dummy.c */

