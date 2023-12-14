/*
     This file is part of GNUnet.
     Copyright (C) 2023 GNUnet e.V.

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
 * @addtogroup Core
 * @{
 *
 * @author ch3
 *
 * @file
 * Implementation of the dummy core underlay that uses unix domain sockets
 *
 * @defgroup CORE
 * Secure Communication with other peers
 *
 * @see [Documentation](https://gnunet.org/core-service) TODO
 *
 * @{
 */

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_core_underlay_dummy.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "core", __VA_ARGS__)

#define SOCK_NAME_BASE "/tmp/gnunet-core-underlay-dummy-socket"

#define MTYPE 12345

struct DummyContext
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;
  struct GNUNET_MQ_Handle *mq;
} *dc0, *dc1;

uint8_t result_address_callback = GNUNET_NO;
uint8_t result_connect_cb_0 = GNUNET_NO;
uint8_t result_connect_cb_1 = GNUNET_NO;
uint8_t result_reply_0 = GNUNET_NO;
uint8_t result_reply_1 = GNUNET_NO;

static struct GNUNET_SCHEDULER_Task *timeout_task;

void *notify_connect_cb (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq)
{
  struct DummyContext *dc = (struct DummyContext *) cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  // FIXME consider num_addresses to be 0
  LOG (GNUNET_ERROR_TYPE_INFO,
      "Got notified about successful connection to peer with %u address: `%s'\n",
      num_addresses,
      addresses[num_addresses - 1]);
  dc->mq = mq;
  if (GNUNET_NO == result_connect_cb_0)
  {
    result_connect_cb_0 = GNUNET_YES;
  }
  else if (GNUNET_YES == result_connect_cb_0 &&
             GNUNET_NO == result_connect_cb_1)
  {
    result_connect_cb_1 = GNUNET_YES;
  }
  env = GNUNET_MQ_msg (msg, MTYPE); // TODO
  // a real implementation would set message fields here
  GNUNET_MQ_send (mq, env);
  LOG (GNUNET_ERROR_TYPE_INFO, "Sent message through message queue\n");

  return dc;
}

// TODO
//typedef void (*GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect) (
//  void *cls,
//  void *handler_cls);

void address_change_cb (void *cls,
                        struct GNUNET_HashCode network_location_hash,
                        uint64_t network_generation_id)
{
  struct DummyContext *dc = cls;
  result_address_callback = GNUNET_YES;
  LOG(GNUNET_ERROR_TYPE_INFO, "Got informed of address change\n");
  GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                              SOCK_NAME_BASE "1",
                                              GNUNET_MQ_PRIO_BEST_EFFORT,
                                              GNUNET_BANDWIDTH_VALUE_MAX);
}

void do_shutdown (void *cls)
{
  //struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (dc0->h);
  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (dc1->h);
  GNUNET_free (dc0);
  GNUNET_free (dc1);
  LOG(GNUNET_ERROR_TYPE_INFO, "Disconnected from underlay dummy\n");
}

void do_timeout (void *cls)
{
  timeout_task = NULL;

  LOG(GNUNET_ERROR_TYPE_INFO, "Disconnecting from underlay dummy\n");
  GNUNET_SCHEDULER_shutdown ();
}


static void
handle_test (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct DummyContext *dc = (struct DummyContext *) cls;

  LOG (GNUNET_ERROR_TYPE_INFO, "received test message\n");

  // TODO check the content

  if (GNUNET_NO == result_reply_0)
  {
    result_reply_0 = GNUNET_YES;
  }
  else if (GNUNET_YES == result_reply_0 && GNUNET_NO == result_reply_1)
  {
    result_reply_1 = GNUNET_YES;
  }
  GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (dc->h, dc->mq);
}


static void run_test (void *cls)
{
  GNUNET_log_setup ("test-core-underlay-dummy", "DEBUG", NULL);
  dc0 = GNUNET_new(struct DummyContext);
  dc1 = GNUNET_new(struct DummyContext);
  struct GNUNET_MQ_MessageHandler handlers0[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_MessageHeader, dc0),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_MessageHandler handlers1[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_MessageHeader, dc1),
    GNUNET_MQ_handler_end ()
  };
  LOG(GNUNET_ERROR_TYPE_INFO, "Connecting to underlay dummy\n");
  dc0->h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, //cfg
                                               handlers0,
                                               dc0, // cls
                                               notify_connect_cb, // nc
                                               NULL, // nd
                                               address_change_cb); // na
  LOG(GNUNET_ERROR_TYPE_INFO, "Connected to underlay dummy 1\n");
  dc1->h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, //cfg
                                               handlers1,
                                               dc1, // cls
                                               notify_connect_cb, // nc
                                               NULL, // nd
                                               address_change_cb); // na
  LOG(GNUNET_ERROR_TYPE_INFO, "Connected to underlay dummy 2\n");
  GNUNET_SCHEDULER_add_shutdown (do_shutdown, NULL);
  timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                               do_timeout,
                                               NULL);
}

int main (void)
{
  GNUNET_SCHEDULER_run (run_test, NULL);
  //GNUNET_SCHEDULER_shutdown ();

  if (GNUNET_YES != result_address_callback) return -1;
  if (GNUNET_YES != result_connect_cb_0) return -1;
  if (GNUNET_YES != result_connect_cb_1) return -1;
  if (GNUNET_YES != result_reply_0) return -1;
  if (GNUNET_YES != result_reply_1) return -1;
  return 0;
}


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/** @} */ /* end of group */

/** @} */ /* end of group addition */

/* end of test_gnunet_core_underlay_dummy.c */
