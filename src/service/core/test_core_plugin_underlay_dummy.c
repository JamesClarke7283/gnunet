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


enum UDS_State_Connected
{
  UDS_State_Connected_TRUE,
  UDS_State_Connected_FALSE,
};


struct UnderlayDummyState
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_TESTING_AsyncContext ac;
  enum UDS_State_Connected connected;
  const char *node_id;
  // FIXME: set cls per handler
  void *handlers_cls;
  uint32_t handlers_len;
  handle_msg *handlers;
};


struct UnderlayDummyRecvState
{
  struct GNUNET_TESTING_AsyncContext ac;
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
  struct UnderlayDummyState *uds = cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received message - going to call handlers\n");
  // TODO call registered handlers
  for (uint32_t i = 0; i < uds->handlers_len; i++)
  {
    // FIXME: set cls per handler
    uds->handlers[i] (uds->handlers_cls, msg);
  }
}


void *notify_connect_cb (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq)
{
  struct UnderlayDummyState *uds = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "A new connection was established\n");

  uds->mq = mq;

  if (UDS_State_Connected_FALSE == uds->connected)
  {
    GNUNET_TESTING_async_finish (&uds->ac);
    uds->connected = UDS_State_Connected_TRUE;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "(post connect_cb _async_finish)\n");
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(post connect_cb)\n");
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
  const char* node_id)
{
  struct UnderlayDummyState *uds;

  uds = GNUNET_new (struct UnderlayDummyState);
  uds->connected = UDS_State_Connected_FALSE;
  uds->node_id = GNUNET_strdup (node_id);
  uds->handlers = GNUNET_new_array (0, handle_msg);
  uds->handlers_len = 0;
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

  GNUNET_TESTING_async_finish (&udrs->ac);
}


static void
exec_recv_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummyRecvState *udrs = cls;
  struct UnderlayDummyState *uds;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_UNDERLAY_DUMMY_Message *msg;

  if (GNUNET_OK != GNUNET_CORE_get_trait_connect (
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
  unsigned long int expected_exit_code)
{
  struct UnderlayDummyRecvState *udrs;

  udrs = GNUNET_new (struct UnderlayDummyRecvState);
  //udrs->received = UDRS_State_Received_FALSE;
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
  (void) cls;
  struct UnderlayDummyState *uds;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_UNDERLAY_DUMMY_Message *msg;

  if (GNUNET_OK != GNUNET_CORE_get_trait_connect (
        GNUNET_TESTING_interpreter_lookup_command (is, "connect"),
        (const void**) &uds)) {
    GNUNET_assert (0);
  };

  GNUNET_assert (NULL != uds->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to send message\n");
  env = GNUNET_MQ_msg (msg, MTYPE); // TODO usually we wanted to keep the
                                    // envelopes to potentially cancel the
                                    // message
  msg->id = GNUNET_htonll (0); // i
  msg->batch = GNUNET_htonll (0); // dc->num_open_connections - 1
  GNUNET_MQ_send (uds->mq, env);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sent message\n");
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
  unsigned long int expected_exit_code)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_send)\n");
  return GNUNET_TESTING_command_new (
      NULL, // state
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
                               my_node_id)),
    GNUNET_TESTING_cmd_make_unblocking (
      GNUNET_CORE_cmd_recv ("recv",
                            GNUNET_OS_PROCESS_EXITED,
                            0)),
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
    GNUNET_CORE_cmd_send ("send", GNUNET_OS_PROCESS_EXITED, 0),
    GNUNET_TESTING_cmd_finish ("recv-finished",
                               "recv",
                               GNUNET_TIME_relative_multiply (
                                 GNUNET_TIME_UNIT_SECONDS, 3)),
    GNUNET_TESTING_cmd_end ()
  )


// testing_core_cmd_connecting_peers.c takes as inspiration
// FIXME: likely not ideally placed here, move to its own file
GNUNET_CORE_SIMPLE_DUMMY_UNDERLAY_TRAITS (
    GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT, GNUNET_CORE)


/* end of src/service/core/test_core_plugin_underlay_dummy.c */

