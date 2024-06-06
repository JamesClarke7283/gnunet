/*
  This file is part of GNUNET
  Copyright (C) 2024 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 3,
  or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public
  License along with GNUnet; see the file COPYING.  If not,
  see <http://www.gnu.org/licenses/>
*/
/**
 * @file core/test_core_underlay_dummy_testing.c
 * @brief testcase to test core's underlay dummy
 * @author ch3
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


int
main (int argc,
      char *const *argv)
{
  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_make_unblocking (
        // TODO evaluate the use of GNUNET_TESTING_cmd_batch()
      GNUNET_TESTING_cmd_exec_va ("dummy_underlay0",
                                  GNUNET_OS_PROCESS_EXITED,
                                  0,
                                  "./test_core_underlay_dummy_single_0.sh",
                                  NULL)),
    GNUNET_TESTING_cmd_make_unblocking (
      GNUNET_TESTING_cmd_exec_va ("dummy_underlay1",
                                  GNUNET_OS_PROCESS_EXITED,
                                  0,
                                  "./test_core_underlay_dummy_single_1.sh",
                                  NULL)),
    GNUNET_TESTING_cmd_finish ("wait-dummy_underlay0",
                               "dummy_underlay0",
                               GNUNET_TIME_relative_multiply (
                                 GNUNET_TIME_UNIT_SECONDS, 5)),
    GNUNET_TESTING_cmd_finish ("wait-dummy_underlay1",
                               "dummy_underlay1",
                               GNUNET_TIME_UNIT_ZERO),
    GNUNET_TESTING_cmd_end ()
  };

  GNUNET_log_setup ("test-underlay_dummy",
                    "DEBUG",
                    NULL);
  return GNUNET_TESTING_main (commands,
                              GNUNET_TIME_UNIT_MINUTES);
}


/* end of test_testing_api.c */

