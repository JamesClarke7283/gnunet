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
 * @file testing/testing_api_cmd_netjail_stop.c
 * @brief Command to stop the netjail script.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_barrier.h"
#include "gnunet_testing_netjail_lib.h"


#define NETJAIL_STOP_SCRIPT "netjail_stop.sh"

/**
 * Struct to hold information for callbacks.
 *
 */
struct NetJailState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  // Child Wait handle
  struct GNUNET_ChildWaitHandle *cwh;

  /**
   * Configuration file for the test topology.
   */
  char *topology_config;

  /**
   * The process id of the start script.
   */
  struct GNUNET_OS_Process *stop_proc;

  /**
   * Shall we read the topology from file, or from a string.
   */
  unsigned int *read_file;

};


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
netjail_stop_cleanup (void *cls)
{
  struct NetJailState *ns = cls;

  if (NULL != ns->cwh)
  {
    GNUNET_wait_child_cancel (ns->cwh);
    ns->cwh = NULL;
  }
  if (NULL != ns->stop_proc)
  {
    GNUNET_assert (0 ==
                   GNUNET_OS_process_kill (ns->stop_proc,
                                           SIGKILL));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_OS_process_wait (ns->stop_proc));
    GNUNET_OS_process_destroy (ns->stop_proc);
    ns->stop_proc = NULL;
  }
  GNUNET_free (ns);
}


/**
 * Callback which will be called if the setup script finished.
 *
 */
static void
child_completed_callback (void *cls,
                          enum GNUNET_OS_ProcessStatusType type,
                          long unsigned int exit_code)
{
  struct NetJailState *ns = cls;

  ns->cwh = NULL;
  GNUNET_OS_process_destroy (ns->stop_proc);
  ns->stop_proc = NULL;
  if (0 == exit_code)
  {
    GNUNET_TESTING_async_finish (&ns->ac);
  }
  else
  {
    GNUNET_TESTING_async_fail (&ns->ac);
  }
}


/**
* The run method starts the script which deletes the network namespaces.
*
* @param cls closure.
* @param is interpreter state.
*/
static void
netjail_stop_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct NetJailState *ns = cls;
  char *pid;
  char *data_dir;
  char *script_name;
  char *read_file;


  data_dir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  GNUNET_asprintf (&script_name, "%s%s", data_dir, NETJAIL_STOP_SCRIPT);
  GNUNET_asprintf (&read_file, "%u", *(ns->read_file));
  unsigned int helper_check = GNUNET_OS_check_helper_binary (
    script_name,
    GNUNET_YES,
    NULL);

  if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No SUID for %s!\n",
                script_name);
    GNUNET_TESTING_interpreter_fail (is);
  }
  else if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s not found!\n",
                script_name);
    GNUNET_TESTING_interpreter_fail (is);
  }

  GNUNET_asprintf (&pid,
                   "%u",
                   getpid ());
  {
    char *const script_argv[] = {script_name,
                                 ns->topology_config,
                                 pid,
                                 read_file,
                                 NULL};
    ns->stop_proc = GNUNET_OS_start_process_vap (GNUNET_OS_INHERIT_STD_ERR,
                                                 NULL,
                                                 NULL,
                                                 NULL,
                                                 script_name,
                                                 script_argv);
  }
  ns->cwh = GNUNET_wait_child (ns->stop_proc,
                               &child_completed_callback,
                               ns);
  GNUNET_break (NULL != ns->cwh);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_stop (const char *label,
                                 char *topology_config,
                                 unsigned int *read_file)
{
  struct NetJailState *ns;

  ns = GNUNET_new (struct NetJailState);
  ns->topology_config = topology_config;
  ns->read_file = read_file;
  return GNUNET_TESTING_command_new (ns, label,
                                     &netjail_stop_run,
                                     &netjail_stop_cleanup,
                                     NULL, &ns->ac);
}
