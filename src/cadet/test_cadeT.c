/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file cadet/test_cadeT.c
 * @brief testcase for cadet.c
 * @author xrs
 *
 * Goal:
 *   - test session resumption after a hard channel breakup
 *
 * ToDos:
 *   x setup peer A
 *   x setup peer B
 *   x setup cadet on peer B listening on port "cadet_port"
 *   x create a channel from peer A to B
 *   - create method to find out KX initiator
 *   - send a message over channel
 *   - check if message was received
 *   - breakup the connection without sending a channel destroy message
 *   - assert tunnel is down
 *   - resume channel (second handshake for tunnel)
 *   - send second message over channel
 *   - check if message was receveived
 *   - end test
 *
 * Questions:
 *   - can we simulate hard breakups with TESTBED?
 *     - yes, with GNUNET_TESTBED_underlay_configure_link 
 *   - how can we test the sublayers of CADET, e.g. connection, tunnel, channel?
 *
 * Development
 *   - red -> green -> refactor (cyclic)
 *   - be aware of Continuation Passing Style (CPS) programming
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "cadet.h"
#include <test_cadeT_util.h>

#define CONFIG            "test_cadet.conf"
#define TESTPROGAM_NAME   "test-cadet-channel-resumption"

/****************************** TEST LOGIC ********************************/

void
run_test ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);

  /**
   * This function is called after all testbed management is done and the 
   * testbed peers are ready for the actual test logic.
   * Use struct test_peers[i] to control the peers.
   */
}


int 
main (int argc, char *argv[])
{
  GNUNET_TESTBED_test_run (TESTPROGAM_NAME,
                           CONFIG,
                           REQUESTED_PEERS, 0LL, NULL, NULL,
                           connect_to_peers, NULL);
  return test_result;
}

/* end of test_template_api.c */
