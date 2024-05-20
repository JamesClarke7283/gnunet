/*
      This file is part of GNUnet
      Copyright (C) 2021 GNUnet e.V.

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
 * @file testing_api_cmd_stop_peer.c
 * @brief cmd to stop a peer.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testbed_lib.h"
#include "gnunet_transport_testing_ng_lib.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)


/**
 * Struct to hold information for callbacks.
 *
 */
struct StopPeerState
{
  // Label of the cmd to start the peer.
  const char *start_label;
};


/**
 * The run method of this cmd will stop all services of a peer which were used to test the transport service.
 *
 */
static void
stop_peer_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct StopPeerState *stop_ps = cls;
  const struct GNUNET_TESTING_StartPeerState *sps;
  const struct GNUNET_TESTING_Command *start_cmd;

  start_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                         stop_ps->start_label);
  GNUNET_TRANSPORT_TESTING_get_trait_state (start_cmd,
                                            &sps);

  if (NULL != sps->peer)
  {
    if (GNUNET_OK !=
        GNUNET_TESTBED_peer_stop (sps->peer))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Testing lib failed to stop peer %u (`%s')\n",
           sps->no,
           GNUNET_i2s (&sps->id));
    }
    GNUNET_TESTBED_peer_destroy (sps->peer);
  }
  if (NULL != sps->rh_task)
    GNUNET_SCHEDULER_cancel (sps->rh_task);
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
stop_peer_cleanup (void *cls)
{
  struct StopPeerState *sps = cls;

  GNUNET_free (sps);
}


/**
 * Trait function of this cmd does nothing.
 *
 */
static int
stop_peer_traits (void *cls,
                  const void **ret,
                  const char *trait,
                  unsigned int index)
{
  return GNUNET_OK;
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param start_label Label of the cmd to start the peer.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_peer (const char *label,
                              const char *start_label)
{
  struct StopPeerState *sps;

  sps = GNUNET_new (struct StopPeerState);
  sps->start_label = start_label;
  return GNUNET_TESTING_command_new (sps,
                                     label,
                                     &stop_peer_run,
                                     &stop_peer_cleanup,
                                     &stop_peer_traits);
}
