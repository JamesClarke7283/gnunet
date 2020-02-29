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
 *   - setup peer A
 *   - setup peer B
 *   - setup cadet on peer B listening on port 1234
 *   - create a channel from peer A to B
 *   - create method to find out session initiator
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
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "cadet.h"

#define REQUESTED_PEERS   2
#define CONFIG            "test_cadet.conf"
#define TESTPROGAM_NAME   "test-cadet-channel-resumption"
#define PORTNAME          "cadet_port"

struct GNUNET_TESTBED_Operation *testbed_to_svc[2];

/**
 * Port name kown by the two peers.
 */
static struct GNUNET_HashCode hashed_portname;

static int test_result = 0;

// FIXME: temp cnt
static int cnt = 0;

/****************************** TEST LOGIC ********************************/

// TBD

/************************** TESBED MANAGEMENT *****************************/

static void
shutdown_task (void *cls)
{
  for (int i=0; i<REQUESTED_PEERS; i++)
    GNUNET_TESTBED_operation_done (testbed_to_svc[i]);
}

static void
disconnect_from_peer (void *cls,
                      void *op_result)
{
  struct GNUNET_CADET_Handle *cadet = op_result;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "disconnect_from_cadet ()\n");

  GNUNET_CADET_disconnect (cadet);
}

static void *
setup_initiating_peer (void *cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  struct GNUNET_CADET_Handle *cadet;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "setup_initiating_peer()\n");

  cadet = GNUNET_CADET_connect (cfg);

  if (NULL == cadet)
    GNUNET_SCHEDULER_shutdown ();

  return cadet;
}

static void *
handle_port_connects (void *cls,
                      struct GNUNET_CADET_Channel *channel,
                      const struct GNUNET_PeerIdentity *source)
{
  return NULL;
}

static void 
handle_port_disconnects (void *cls, 
                         const struct GNUNET_CADET_Channel *channel)
{
}

static void *
setup_listening_peer (void *cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CADET_Handle *cadet;
  struct GNUNET_CADET_Port *port;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "setup_listening_peer()\n");
  
  cadet = GNUNET_CADET_connect (cfg);

  if (NULL == cadet)
    GNUNET_SCHEDULER_shutdown ();

  GNUNET_CRYPTO_hash (PORTNAME, sizeof(PORTNAME), &hashed_portname);
  port = GNUNET_CADET_open_port (cadet, &hashed_portname,
                                 &handle_port_connects,
                                 NULL,
                                 NULL,
                                 &handle_port_disconnects,
                                 NULL);

  return cadet;
}

static void
check_test_readyness (void *cls,
                      struct GNUNET_TESTBED_Operation *op,
                      void *ca_result,
                      const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "check_test_readyness()\n");

  if (2 == ++cnt)
    GNUNET_SCHEDULER_shutdown ();
}

static void
connect_to_peers (void *cls,
                  struct GNUNET_TESTBED_RunHandle *h,
                  unsigned int num_peers,
                  struct GNUNET_TESTBED_Peer **peers,
                  unsigned int links_succeeded,
                  unsigned int links_failed)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "connect_to_peers()\n");

  GNUNET_assert (0 == links_failed);


  testbed_to_svc[1] = GNUNET_TESTBED_service_connect (NULL, peers[1],
                                                      "cadet", 
                                                      &check_test_readyness, NULL,
                                                      &setup_listening_peer,
                                                      &disconnect_from_peer, NULL);
  testbed_to_svc[0] = GNUNET_TESTBED_service_connect (NULL, peers[0],
                                                      "cadet", 
                                                      &check_test_readyness, NULL,
                                                      &setup_initiating_peer,
                                                      &disconnect_from_peer, NULL);

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
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
