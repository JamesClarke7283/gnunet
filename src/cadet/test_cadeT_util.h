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
 * @file cadet/test_cadeT_util.h
 * @brief testcase for cadet.c
 * @author xrs
 */

#include "platform.h"
#include "gnunet_testbed_service.h"
#include "cadet.h"

#define REQUESTED_PEERS   2
#define TIMEOUT_IN_SEC    5
#define PORTNAME          "cadet_port"

int test_result;

void 
prepare_test ();

void 
run_test ();

void 
handle_message (void *cls,
                const struct GNUNET_MessageHeader *msg);

int
check_message (void *cls,
               const struct GNUNET_MessageHeader *message);

void handle_message ();

/**
 * Structure for storing information of testbed peers.
 */
struct TEST_PEERS
{
  /**
   * Index of the peer.
   */
  int idx;

  /**
   * Peer Identity.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Handle of TESTBED peer.
   */
  struct GNUNET_TESTBED_Peer *testbed_peer;

  /**
   * Testbed management is finished and test peer is ready for test logic.
   */
  int ready;

  /**
   * Channel of initiating peer.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * CADET handle.
   */
  struct GNUNET_CADET_Handle *cadet;

} test_peers[REQUESTED_PEERS];
