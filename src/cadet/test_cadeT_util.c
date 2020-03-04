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
 * @file cadet/test_cadeT_util.c
 * @brief testcase for cadet.c
 * @author xrs
 */

#include <test_cadeT_util.h>

/**
 * Testbed operation for connecting to the services. 
 */
static struct GNUNET_TESTBED_Operation *testbed_to_svc[REQUESTED_PEERS];

/**
 * Testbed operation for requesting peer information.
 */
static struct GNUNET_TESTBED_Operation *testbed_info_req[REQUESTED_PEERS];

/**
 * Port name kown by the two peers.
 */
static struct GNUNET_HashCode hashed_portname;

/**
 * Result of the test.
 */
int test_result = 0;

/**
 * Counter for gathering peerinformation.
 */
static int peerinfo_cnt = 0;

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

/************************** TESBED MANAGEMENT *****************************/

static void
shutdown_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);

  for (int i=0; i<REQUESTED_PEERS; i++)
    GNUNET_TESTBED_operation_done (testbed_to_svc[i]);
}

static void
timeout ()
{
  GNUNET_SCHEDULER_shutdown ();
}

static void
disconnect_from_peer (void *cls,
                      void *op_result)
{
  struct GNUNET_CADET_Handle *cadet = op_result;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);

  GNUNET_CADET_disconnect (cadet);
}

static void 
disconnect_channel (void *cls,
                    const struct GNUNET_CADET_Channel *channel)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);
}

static void *
setup_initiating_peer (void *cls,
                       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CADET_Handle *cadet;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);

  cadet = GNUNET_CADET_connect (cfg);
  test_peers[0].cadet = cadet;

  if (NULL == cadet)
    GNUNET_SCHEDULER_shutdown ();

  channel = GNUNET_CADET_channel_create (cadet,
                                         NULL,
                                         &test_peers[1].id,
                                         &hashed_portname,
                                         NULL,
                                         &disconnect_channel,
                                         NULL);
  test_peers[0].channel = channel;

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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);
  
  cadet = GNUNET_CADET_connect (cfg);
  test_peers[1].cadet = cadet;

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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);

  // FIXME: check, if all peers are ready, then continue with the
  // test logic.
  if (GNUNET_OK)
    run_test();
}

static int
peerinfo_complete ()
{
  return (REQUESTED_PEERS == ++peerinfo_cnt) ? GNUNET_YES : GNUNET_NO;
}

void
connect_to_service (void *cb_cls,
                    struct GNUNET_TESTBED_Operation *op,
                    const struct GNUNET_TESTBED_PeerInformation *pinfo,
                    const char *emsg)
{
  struct TEST_PEERS *test_peer = cb_cls;

  // Store peer ID.
  test_peer->id = *(pinfo->result.id);

  if (peerinfo_complete())
  {
    testbed_to_svc[1] = 
      GNUNET_TESTBED_service_connect (NULL, test_peers[1].testbed_peer,
                                      "cadet", 
                                      &check_test_readyness, NULL,
                                      &setup_listening_peer,
                                      &disconnect_from_peer, NULL);
    testbed_to_svc[0] = 
      GNUNET_TESTBED_service_connect (NULL, test_peers[0].testbed_peer,
                                      "cadet",
                                      &check_test_readyness, NULL,
                                      &setup_initiating_peer,
                                      &disconnect_from_peer, NULL);
  }
}

void
prepare_test (void *cls,
              struct GNUNET_TESTBED_RunHandle *h,
              unsigned int num_peers,
              struct GNUNET_TESTBED_Peer **peers,
              unsigned int links_succeeded,
              unsigned int links_failed)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);

  GNUNET_assert (GNUNET_NO == links_failed);
  GNUNET_assert (REQUESTED_PEERS == num_peers);

  for (int i=0; i<REQUESTED_PEERS; i++)
  {
    test_peers[i].ready = GNUNET_NO;
    test_peers[i].idx = i;
    test_peers[i].testbed_peer = peers[i];
  }

  testbed_info_req[0] = GNUNET_TESTBED_peer_get_information (peers[0],
                                                             GNUNET_TESTBED_PIT_IDENTITY,
                                                             &connect_to_service,
                                                             &test_peers[0]);
  testbed_info_req[1] = GNUNET_TESTBED_peer_get_information (peers[1],
                                                             GNUNET_TESTBED_PIT_IDENTITY,
                                                             &connect_to_service,
                                                             &test_peers[1]);

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, TIMEOUT_IN_SEC), 
                                &timeout, NULL);
}
