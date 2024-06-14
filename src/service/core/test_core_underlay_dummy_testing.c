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

#include "gnunet_core_underlay_dummy.h"


#define MTYPE 12345


struct UnderlayDummyState
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;
} uds0, uds1;


struct GNUNET_UNDERLAY_DUMMY_Message
{
  struct GNUNET_MessageHeader header;
  // The following will be used for debugging
  uint64_t id; // id of the message
  uint64_t batch; // first batch of that peer (for this test 0 or 1)
  //uint64_t peer; // number of sending peer (for this test 0 or 1)
};


/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
connect_traits (void *cls,
                const void **ret,
                const char *trait,
                unsigned int index)
{
  struct UnderlayDummyState *uds = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_CORE_make_trait_connect (uds->h),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


static void
handle_test (void *cls, const struct GNUNET_UNDERLAY_DUMMY_Message *msg)
{
  struct Connection *connection = cls;
}


void *notify_connect_cb (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq)
{
  struct DummyContext *dc = (struct DummyContext *) cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_UNDERLAY_DUMMY_Message *msg;
  struct Connection *connection;
}


void address_change_cb (void *cls,
                        struct GNUNET_HashCode network_location_hash,
                        uint64_t network_generation_id)
{
  struct DummyContext *dc = cls;
}


static void
exec_connect_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummyState *uds = cls;

  struct GNUNET_MQ_MessageHandler handlers[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_UNDERLAY_DUMMY_Message, NULL),
    GNUNET_MQ_handler_end ()
  };

  uds->h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, // cfg
                                               handlers,
                                               uds, // cls
                                               notify_connect_cb,
                                               NULL, // nd
                                               address_change_cb);

}


static void
exec_connect_cleanup (void *cls)
{
  struct UnderlayDummyState *uds = cls;

  if (NULL != uds->h)
  {
    GNUNET_CORE_UNDERLAY_DUMMY_disconnect (uds->h);
  }
}


const struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_connect (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  struct UnderlayDummyState *uds)
{
  return GNUNET_TESTING_command_new (
      uds, // state
      label,
      &exec_connect_run,
      &exec_connect_cleanup,
      &connect_traits);
}


static void
exec_disconnect_run (void *cls,
                     struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummyState *uds = cls;

  GNUNET_assert (NULL != uds->h);
  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (uds->h);
  uds->h = NULL;
}


static void
exec_disconnect_cleanup (void *cls)
{
  struct UnderlayDummyState *uds = cls;
}


const struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_disconnect (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  struct UnderlayDummyState *uds)
{
  return GNUNET_TESTING_command_new (
      uds, // state
      label,
      &exec_disconnect_run,
      &exec_disconnect_cleanup,
      NULL);
}


int
main (int argc,
      char *const *argv)
{
  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_CORE_cmd_connect ("connect0",
                             GNUNET_OS_PROCESS_EXITED,
                             0,
                             &uds0),
    GNUNET_CORE_cmd_connect ("connect1",
                             GNUNET_OS_PROCESS_EXITED,
                             0,
                             &uds1),
    GNUNET_CORE_cmd_disconnect ("disconnect0",
                                GNUNET_OS_PROCESS_EXITED,
                                0,
                                &uds0),
    GNUNET_CORE_cmd_disconnect ("disconnect1",
                                GNUNET_OS_PROCESS_EXITED,
                                0,
                                &uds1),
    GNUNET_TESTING_cmd_end ()
  };

  GNUNET_log_setup ("test-underlay_dummy",
                    "DEBUG",
                    NULL);
  return GNUNET_TESTING_main (commands,
                              GNUNET_TIME_relative_multiply (
                                GNUNET_TIME_UNIT_SECONDS,
                                5));
}

// testing_core_cmd_connecting_peers.c takes as inspiration
// FIXME: likely not ideally placed here, move to its own file
GNUNET_CORE_SIMPLE_DUMMY_UNDERLAY_TRAITS (
    GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT, GNUNET_CORE)

/* end of test_testing_api.c */

