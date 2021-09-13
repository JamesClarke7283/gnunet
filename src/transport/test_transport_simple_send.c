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
 * @file transport/test_transport_api_cmd_simple_send.c
 * @brief Test case executing a script which sends a test message between two peers.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_util_lib.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
  * Return value of the test.
  *
  */
static unsigned int rv = 0;


/**
 * Main function to run the test cases.
 *
 * @param cls not used.
 *
 */
static void
run (void *cls)
{
  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_netjail_start ("netjail-start",
                                      "2",
                                      "1"),
    GNUNET_TESTING_cmd_netjail_start_testing_system ("netjail-start-testbed",
                                                     "2",
                                                     "1",
                                                     "libgnunet_test_transport_plugin_cmd_simple_send",
                                                     &rv),
    GNUNET_TESTING_cmd_stop_testing_system ("stop-testbed",
                                            "netjail-start-testbed",
                                            "2",
                                            "1"),
    GNUNET_TESTING_cmd_netjail_stop ("netjail-stop",
                                     "2",
                                     "1"),
    GNUNET_TESTING_cmd_end ()
  };

  GNUNET_TESTING_run (NULL,
                      commands,
                      TIMEOUT);
}


int
main (int argc,
      char *const *argv)
{
  GNUNET_log_setup ("test-netjail",
                    "DEBUG",
                    NULL);
  GNUNET_SCHEDULER_run (&run,
                        NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test finished!\n");
  return rv;
}
