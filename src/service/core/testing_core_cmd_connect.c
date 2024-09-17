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
 * @file src/service/core/testing_core_connect.c
 * @brief a function to connect to the core service for testing
 * @author ch3
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_testing_core_lib.h"


//#define NUM_MESSAGES 10
//#define NUM_CHANNELS 2
//
//#define MTYPE 12345

/**
 * @brief Generic logging shortcut
 */
#define LOG(kind, ...) \
  GNUNET_log_from_nocheck (kind, "core-plugin-connect", __VA_ARGS__)


//struct ConnectState
//{
//  struct GNUNET_CORE_Handle *h;
//  //// The number of channels supposed to reach
//  //uint32_t num_channels_target;
//  struct GNUNET_TESTING_AsyncContext ac;
//  enum GNUNET_GenericReturnValue finished;
//  //const char *node_id;
//  //// FIXME: set cls per handler
//  //void *handlers_cls;
//  uint32_t handlers_len;
//  GNUNET_TESTING_CORE_handle_msg *handlers;
//};



static void
handle_test (void *cls, const struct GNUNET_TESTING_CORE_Message *msg)
{
  //struct GNUNET_TESTING_CORE_Channel *channel = cls;

  //LOG (GNUNET_ERROR_TYPE_DEBUG,
  //    "Received message (%" PRIu64 ", %" PRIu64 ") - going to call handlers\n",
  //    GNUNET_ntohll (msg->id),
  //    GNUNET_ntohll (msg->batch));
  //for (uint32_t i = 0; i < channel->connect_state->handlers_len; i++)
  //{
  //  // FIXME: set cls per handler
  //  channel->connect_state->handlers[i] (channel->connect_state->handlers_cls, channel, msg);
  //}

  //GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (channel->connect_state->h,
  //                                             channel->mq);
}


/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
connect_traits (void *cls,
                const void **ret,
                const char *trait,
                unsigned int index)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_CORE_TESTING_make_trait_connect (connect_state),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


static void
init_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *my_identity)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  // TODO we could finish _connect here.
  //LOG (GNUNET_ERROR_TYPE_DEBUG,
  //    "Connected to core, own pid: %s\n",
  //    GNUNET_i2s (my_identity);
  //  GNUNET_TESTING_async_finish (&connect_state->ac);
}


static void *
connect_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *peer_id,
  struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  struct GNUNET_TESTING_CORE_Channel *channel;
  (void) peer_id; /* unused - the underlay dummy doesn't know abot peer ids */

  LOG (GNUNET_ERROR_TYPE_DEBUG, "A new connection was established\n");

  channel = GNUNET_new (struct GNUNET_TESTING_CORE_Channel);
  channel->connect_state = connect_state;
  channel->mq = mq;
  GNUNET_CONTAINER_DLL_insert (connect_state->channels_head,
                               connect_state->channels_tail,
                               channel);

  /* Call connect handlers from test */
  for (uint32_t i = 0; i < connect_state->connect_cbs_len; i++)
  {
    // TODO check if we really want to pass everything as-is
    connect_state->connect_cbs[i] (cls,
                                        peer_id,
                                        mq);
  }

  //if ((connect_state->num_channels_target == connect_state->channels_len) &&
  //    (GNUNET_NO == connect_state->finished))
  //{
  //  LOG (GNUNET_ERROR_TYPE_DEBUG, "(post connect_cb _async_finish)\n");
  //  GNUNET_TESTING_async_finish (&connect_state->ac);
  //  connect_state->finished = GNUNET_YES;
  //}
  //LOG (GNUNET_ERROR_TYPE_DEBUG,
  //    "(post connect_cb - %u of %u)\n",
  //    connect_state->channels_len,
  //    connect_state->num_channels_target);

  return channel;
}


static void
disconnect_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *peer,
  void *peer_cls)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  //struct GNUNET_TESTING_CORE_Channel *channel = handler_cls;
  //uint32_t i_target = 0;

  //LOG (GNUNET_ERROR_TYPE_DEBUG, "from notify_disconnect_cb()\n");
  ///**
  // * Remove the closed channel:
  // *  1. find the (index of the) closed channel
  // *  2. copy all following channel one to the front
  // */
  //for (uint32_t i = 0; i < connect_state->channels_len; i++)
  //{
  //  if (channel == connect_state->channels[i])
  //  {
  //    //connect_state->channels[i] = NULL; // XXX
  //    i_target = i;
  //    break;
  //  }
  //}
  ////for (uint32_t i = i_target; i < (connect_state->channels_len - 1); i++)
  ////{
  ////  GNUNET_memcpy ();
  ////}
  //GNUNET_memcpy (&connect_state->channels[i_target],
  //               &connect_state->channels[i_target+1],
  //               (connect_state->channels_len - i_target - 1) * sizeof (struct GNUNET_TESTING_CORE_Channel *));
  //GNUNET_array_grow (connect_state->channels, connect_state->channels_len, connect_state->channels_len-1);
  //GNUNET_free (channel);
}


static void
exec_connect_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(%s) Going to connect to core\n",
      connect_state->node_id);
  struct GNUNET_MQ_MessageHandler handlers[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_TESTING_CORE_Message, NULL),
    GNUNET_MQ_handler_end ()
  };

  connect_state->h = GNUNET_CORE_connect (NULL, // cfg
                                          connect_state, // cls
                                          init_cb,
                                          connect_cb,
                                          disconnect_cb,
                                          handlers);

}


static void
exec_connect_cleanup (void *cls)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;

  GNUNET_assert (NULL != connect_state->h);
  GNUNET_CORE_disconnect (connect_state->h);
  // TODO cleanup!
}



const struct GNUNET_TESTING_Command
GNUNET_TESTING_CORE_cmd_connect (
  const char *label,
  const char* node_id//,
  //uint32_t num_channels
  )
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state;

  // TODO get handler from caller to call on new connections

  connect_state = GNUNET_new (struct GNUNET_TESTING_CORE_ConnectState);
  connect_state->recv_handlers = GNUNET_new_array (0, GNUNET_TESTING_CORE_handle_msg);
  connect_state->recv_handlers_len = 0;
  connect_state->connect_cbs = GNUNET_new_array (0, GNUNET_TESTING_CORE_connect_cb);
  connect_state->connect_cbs_len = 0; // TODO rename num_ -> _len
  connect_state->finished = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_connect)\n");
  return GNUNET_TESTING_command_new_ac (
      connect_state, // state
      label,
      &exec_connect_run,
      &exec_connect_cleanup,
      &connect_traits,
      &connect_state->ac);
}


/* end of src/service/core/testing_core_connect.c */
