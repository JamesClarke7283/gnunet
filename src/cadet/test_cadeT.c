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
 *   x create method to find out KX initiator
 *   x send a message over channel
 *   x check if message was received
 *   - breakup the connection without the receiver receiving a channel destroy message
 *   - assert tunnel is down
 *   - resume channel (second handshake for tunnel)
 *   - send second message over channel
 *   - check if message was receveived
 *   - end test
 *
 * Questions:
 *   - can we simulate hard breakups with TESTBED?
 *     - GNUNET_TESTBED_underlay_configure_link not implemented
 *     - GNUNET_TESTBED_underlaylinkmodel_set_link not usable
 *     - GNUNET_TESTBED_peer_stop evokes standard service disconnect
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

} test_peers[2];


/****************************** TEST LOGIC ********************************/

static int kx_initiator;
static struct GNUNET_TESTBED_UnderlayLinkModel *model;
static int msg_count;
static struct GNUNET_SCHEDULER_Task *task;

enum RES {
  RECEIVED_MESSAGE = 1
};

enum RES check;

static void
set_data_loss_rate (int rate)
{
  GNUNET_TESTBED_underlaylinkmodel_set_link (model,
                                             test_peers[0].testbed_peer,
                                             0, rate, 100);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s: %i loss.\n", __func__, rate);
}

void 
handle_message (void *cls, 
                const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);
}

static void
send_message ()
{
  struct GNUNET_MQ_Envelope *envelope;
  struct GNUNET_MessageHeader *msg;
  int *data;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);

  envelope = GNUNET_MQ_msg_extra (msg, 1000,
                                  GNUNET_MESSAGE_TYPE_DUMMY);
  data = (int *) &msg[1];
  *data = 1000;

  GNUNET_MQ_send (GNUNET_CADET_get_mq (test_peers[0].channel), 
                  envelope);

  msg_count++;

  switch (msg_count) 
  {
    case 2: set_data_loss_rate (100); break;
    case 4: set_data_loss_rate (0); break;
  }

  if (msg_count < 5)
    task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1),
                                         &send_message,
                                         NULL);
}

int
check_message (void *cls,
               const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK;             /* all is well-formed */
}

void 
handle_message (void *cls, 
                const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);
  GNUNET_CADET_receive_done (test_peers[1].channel);

  check = RECEIVED_MESSAGE;
}

/**
 * This function is called after all testbed management is done and the 
 * testbed peers are ready for the actual test logic.
 * Use struct test_peers[i] to control the peers.
 */
void
run_test ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%s\n", __func__);

  // Init underlay link model to manipulate links
  model = GNUNET_TESTBED_underlaylinkmodel_create (test_peers[1].testbed_peer,
                                                   GNUNET_TESTBED_UNDERLAYLINKMODELTYPE_BLACKLIST);

  kx_initiator = (0 < GNUNET_memcmp (&test_peers[0].id, &test_peers[1].id)) ? 1 : 0;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
              "KX initiator is peer %s (idx:%i)\n", 
              GNUNET_i2s (&test_peers[kx_initiator].id),
              kx_initiator);

  send_message();
}


int 
main (int argc, char *argv[])
{
  GNUNET_TESTBED_test_run (TESTPROGAM_NAME,
                           CONFIG,
                           REQUESTED_PEERS, 0LL, NULL, NULL,
                           prepare_test, NULL);
  return test_result;
}

/* end of test_template_api.c */
