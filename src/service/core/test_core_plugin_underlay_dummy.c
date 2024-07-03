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
} uds;


struct GNUNET_UNDERLAY_DUMMY_Message
{
  struct GNUNET_MessageHeader header;
  // The following will be used for debugging
  uint64_t id; // id of the message
  uint64_t batch; // first batch of that peer (for this test 0 or 1)
  //uint64_t peer; // number of sending peer (for this test 0 or 1)
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
    GNUNET_CORE_make_trait_connect (uds->h),
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
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(post connect_cb _async_finish)\n");
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to connect to underlay dummy\n");
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
  struct UnderlayDummyState *uds)
{
  uds->connected = UDS_State_Connected_FALSE;
  return GNUNET_TESTING_command_new_ac (
      uds, // state
      label,
      &exec_connect_run,
      &exec_connect_cleanup,
      &connect_traits,
      &uds->ac);
}


static void
exec_send_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummyState *uds = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_UNDERLAY_DUMMY_Message *msg;

  GNUNET_assert (NULL != uds->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to send message\n");
  env = GNUNET_MQ_msg (msg, MTYPE); // TODO usually we wanted to keep the
                                    // envelopes to potentially cancel the
                                    // message
  msg->id = GNUNET_htonll (0); // i
  msg->batch = GNUNET_htonll (0); // dc->num_open_connections - 1
  GNUNET_MQ_send (uds->mq, env);
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
  struct UnderlayDummyState *uds)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_send)\n");
  return GNUNET_TESTING_command_new (
      uds, // state
      label,
      &exec_send_run,
      &exec_send_cleanup,
      &connect_traits);
}


GNUNET_TESTING_MAKE_PLUGIN (
  libgnunet_test_core,
  underlay_dummy,
    //GNUNET_TESTING_cmd_barrier_create ("barrier-connected", 5),
    GNUNET_TESTING_cmd_make_unblocking (
      GNUNET_CORE_cmd_connect ("connect",
                               GNUNET_OS_PROCESS_EXITED,
                               0,
                               &uds)),
    /* Wait until underlay dummy is connected to another peer: */
    GNUNET_TESTING_cmd_finish ("connect-finished",
                               "connect",
                               GNUNET_TIME_UNIT_SECONDS),
    /* Wait until all 'peers' are connected: */
    GNUNET_TESTING_cmd_barrier_reached ("barrier-connected-reached",
                                        "barrier-connected"),
    GNUNET_TESTING_cmd_end ()
  )


// testing_core_cmd_connecting_peers.c takes as inspiration
// FIXME: likely not ideally placed here, move to its own file
GNUNET_CORE_SIMPLE_DUMMY_UNDERLAY_TRAITS (
    GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT, GNUNET_CORE)


/* end of src/service/core/test_core_plugin_underlay_dummy.c */

