/*
     This file is part of GNUnet.
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
 * @file service/pils/test_pils.c
 * @brief testcase for pils.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_pils_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testing_testbed_lib.h"
#include "gnunet_testing_arm_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "test-pils-api", __VA_ARGS__)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_PILS_Handle *h;
struct GNUNET_TESTING_AsyncContext ac;
//const struct GNUNET_CONFIGURATION_Handle *cfg;

static void
pid_change_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *peer_id,
  const struct GNUNET_HashCode *hash)
{
  // TODO
}


static void
exec_connect_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  // TODO
  h = GNUNET_PILS_connect (NULL, //"test_pils_api.conf", // cfg
                           NULL, // cls
                           pid_change_cb);
}


static void
exec_connect_cleanup (void *cls)
{
  // TODO
  GNUNET_PILS_disconnect (h);
}



static const struct GNUNET_TESTING_Command
GNUNET_TESTING_PILS_cmd_connect (
  const char *label)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting command 'connect'\n");
  return GNUNET_TESTING_command_new_ac (
      NULL, //uds, // state
      label,
      &exec_connect_run,
      &exec_connect_cleanup,
      NULL,
      &ac);
}


int
main (int argc, char *argv[])
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting test\n");
  {
    struct GNUNET_TESTING_Command commands[] = {
      GNUNET_TESTBED_cmd_system_create ("system",
                                        "my-node-id"),
      GNUNET_TESTING_ARM_cmd_start_peer ("start",
                                         "system",
                                         "test_pils_api.conf"),
      GNUNET_TESTING_PILS_cmd_connect ("connect"),
      GNUNET_TESTING_cmd_end ()
    };

    return GNUNET_TESTING_main (commands,
                                TIMEOUT);
  }
}


/* end of test_pils_api.c */
