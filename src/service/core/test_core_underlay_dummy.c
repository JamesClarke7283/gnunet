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

uint8_t address_callback = GNUNET_NO;

static struct GNUNET_SCHEDULER_Task *timeout_task;

void *notify_connect_cb (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq)
{
  LOG (GNUNET_ERROR_TYPE_INFO,
      "Got notified about successful connection to peer with %u address: `%s'\n",
      num_addresses,
      addresses[num_addresses - 1]);
}
// TODO
//typedef void (*GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect) (
//  void *cls,
//  void *handler_cls);
void address_change_cb (void *cls,
                        struct GNUNET_HashCode network_location_hash,
                        uint64_t network_generation_id)
{
  address_callback = GNUNET_YES;
  LOG(GNUNET_ERROR_TYPE_INFO, "Got informed of address change\n");
}

void do_shutdown (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (h);
  LOG(GNUNET_ERROR_TYPE_INFO, "Disconnected from underlay dummy\n");
}

void do_timeout (void *cls)
{
  timeout_task = NULL;

  LOG(GNUNET_ERROR_TYPE_INFO, "Disconnecting from underlay dummy\n");
  GNUNET_SCHEDULER_shutdown ();
}


void run_test (void *cls)
{
  GNUNET_log_setup ("test-core-underlay-dummy", "DEBUG", NULL);
  LOG(GNUNET_ERROR_TYPE_INFO, "Connecting to underlay dummy\n");
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h =
    GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, //cfg
                                        NULL, // handlers
                                        NULL, // cls
                                        notify_connect_cb, // nc
                                        NULL, // nd
                                        address_change_cb); // na
  GNUNET_SCHEDULER_add_shutdown (do_shutdown, h);
  LOG(GNUNET_ERROR_TYPE_INFO, "Connected to underlay dummy\n");
  //timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
  //                                             do_timeout,
  //                                             NULL);
}

int main (void)
{
  GNUNET_SCHEDULER_run (run_test, NULL);
  //GNUNET_SCHEDULER_shutdown ();

  if (GNUNET_YES != address_callback) return -1;
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
