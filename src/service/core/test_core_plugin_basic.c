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
 * @file testing/test_arm_plugin_probnat.c
 * @brief a plugin to test burst nat traversal..
 * @author t3sserakt, ch3
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testing_arm_lib.h"
#include "gnunet_testing_testbed_lib.h"
#include "gnunet_testing_core_lib.h"


GNUNET_TESTING_MAKE_PLUGIN (
  libgnunet_test_core,
  basic,
  GNUNET_TESTBED_cmd_system_create ("system",
                                    my_node_id),
  GNUNET_TESTING_ARM_cmd_start_peer ("start",
                                     "system",
                                     "test_core_basic_peer.conf"),
  GNUNET_TESTING_CORE_cmd_connect ("connect",
                                   my_node_id),
  GNUNET_TESTING_cmd_make_unblocking (
    GNUNET_TESTING_CORE_cmd_recv ("recv",
                                  10, /* num messages */
                                  1)), /* num channels */
  GNUNET_TESTING_cmd_make_unblocking (
    GNUNET_TESTING_CORE_cmd_send ("send",
                                  10, /* num messages */
                                  1)), /* num channels */
  GNUNET_TESTING_cmd_finish ("recv-finished",
                             "recv",
                             GNUNET_TIME_relative_multiply (
                               GNUNET_TIME_UNIT_SECONDS, 5)),
  // recv - set up receiving of messages
  //      - we probably won't need the below: just register a handler. done.
  //      - if it is set up the right way, we won't need to wait for a
  //        connection manually
  //      - let receive wait for a connection itself internally
  // //connect-finished
  // //connect barrier
  // send
  //      - write send in a way that we don't need to tell it manually to wait
  //        for a barrier or such - let it check internally
  //      - doesn't have to be async
  // recv-finish
  GNUNET_TESTING_cmd_stop_peer ("stop",
                                "start"),
  GNUNET_TESTING_cmd_end ()
)


/* end of test_arm_plugin_probnat.c */
