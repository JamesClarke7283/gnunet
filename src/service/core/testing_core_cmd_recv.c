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
 * @file src/service/core/testing_core_recv.c
 * @brief a function to receive messages from another peer
 * @author ch3
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_testing_core_lib.h"


/**
 * @brief Generic logging shortcut
 */
#define LOG(kind, ...) \
  GNUNET_log_from_nocheck (kind, "core-plugin-connect", __VA_ARGS__)


struct RecvState;


struct ChannelCount
{
  struct GNUNET_TESTING_CORE_Channel *channel;
  struct RecvState *rs;
  uint64_t num_messages_received;
};


struct RecvState
{
  struct ChannelCount *channel_count;
  uint32_t num_channels;
  uint64_t num_messages_target;
  struct GNUNET_TESTING_AsyncContext ac;
};


static void
handle_msg_test (void *cls,
                 struct GNUNET_TESTING_CORE_Channel *channel,
                 const struct GNUNET_TESTING_CORE_Message *msg)
{
  //struct ChannelCount *channel_count = cls;
  struct RecvState *rs = cls;
  struct ChannelCount *channel_count;
  uint32_t channel_i;
  uint64_t num_messages_received;
  uint64_t num_messages_target;
  enum GNUNET_GenericReturnValue ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "received test message %" PRIu64 " (%" PRIu64 ")\n",
       GNUNET_ntohll (msg->id),
       GNUNET_ntohll (msg->batch));
  channel_i = rs->num_channels; /* For error checking -
                                     should be overwritten in the following loop. */
  for (uint32_t i = 0; i<rs->num_channels; i++)
  {
    channel_count = &rs->channel_count[i];
    if (NULL == channel_count->channel)
    {
      channel_count->channel = channel;
      channel_count->rs = rs;
      channel_i = i;
      break;
    }
    else if (channel == channel_count->channel)
    {
      channel_i = i;
      break;
    }
    // else: continue until suitable channel count structure is found
  }
  GNUNET_break_op (channel_i != rs->num_channels);
  channel_count->num_messages_received++;

  num_messages_received = channel_count->num_messages_received;
  num_messages_target = channel_count->rs->num_messages_target;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received %" PRIu64 " messages (of %" PRIu64 " on channel %" PRIu32 ")\n",
      num_messages_received,
      num_messages_target,
      channel_i);
  if (num_messages_target > num_messages_received) return;
  if (num_messages_target < num_messages_received)
    GNUNET_assert (0);
  //if (num_messages_target == num_messages_received)
  //  GNUNET_TESTING_async_finish (&rs->ac);
  ret = GNUNET_YES;
  for (uint32_t i = 0; i < rs->num_channels; i++)
  {
    channel_count = &rs->channel_count[i];
    if (channel_count->num_messages_received != rs->num_messages_target)
      ret = GNUNET_NO;
  }
  if (GNUNET_YES == ret) GNUNET_TESTING_async_finish (&rs->ac);
}


static void
exec_recv_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct RecvState *rs = cls;
  const struct GNUNET_TESTING_CORE_ConnectState *connect_state;

  if (GNUNET_OK != GNUNET_CORE_TESTING_get_trait_connect (
        // TODO make the "connect" an input to the command
        GNUNET_TESTING_interpreter_lookup_command (is, "connect"),
        &connect_state)) {
    GNUNET_assert (0);
  };
  // FIXME: set cls per hanlder
  GNUNET_array_append (connect_state->recv_handlers,
                       connect_state->recv_handlers_len,
                       &handle_msg_test);
  // FIXME is the following ok?
  ((struct GNUNET_TESTING_CORE_ConnectState *)connect_state)->recv_handlers_cls = rs;
}


static void
exec_recv_cleanup (void *cls)
{
  //struct RecvState *rs = cls;

  //GNUNET_free (rs->channel_count);
  //GNUNET_free (rs);
}


const struct GNUNET_TESTING_Command
GNUNET_TESTING_CORE_cmd_recv (
  const char *label,
  uint64_t num_messages,
  uint32_t num_channels)
{
  struct RecvState *rs;

  // TODO this could be a static global variable
  rs = GNUNET_new (struct RecvState);
  rs->channel_count = GNUNET_new_array (num_channels, struct ChannelCount);
  rs->num_channels = num_channels;
  rs->num_messages_target = num_messages;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_recv)\n");
  return GNUNET_TESTING_command_new_ac (
      rs, // state
      label,
      &exec_recv_run,
      &exec_recv_cleanup,
      NULL,
      &rs->ac); // FIXME
}


/* end of src/service/core/testing_core_recv.c */
