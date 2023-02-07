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
 * @file testing/testing_api_cmd_hello_world.c
 * @brief Command to start the netjail peers.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_barrier.h"
#include "gnunet_testing_netjail_lib.h"
#include "testing.h"
#include "testing_cmds.h"

#define NETJAIL_EXEC_SCRIPT "netjail_exec.sh"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Struct to store messages send/received by the helper into a DLL
 *
 */
struct HelperMessage
{

  /**
   * Kept in a DLL.
   */
  struct HelperMessage *next;

  /**
   * Kept in a DLL.
   */
  struct HelperMessage *prev;

  /**
   * Size of the original message.
   */
  uint16_t bytes_msg;

  /* Followed by @e bytes_msg of msg.*/
};


/**
 * Struct to store information handed over to callbacks.
 *
 */
struct NetJailState
{
  /**
   * Global state of the interpreter, used by a command
   * to access information about other commands.
   */
  struct GNUNET_TESTING_Interpreter *is;

  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The complete topology information.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  /**
   * Array with handles of helper processes.
   */
  const struct GNUNET_HELPER_Handle **helper;

  /**
   * Size of the array NetJailState#helper.
   *
   */
  unsigned int n_helper;

  /**
   * Number of nodes in a natted subnet.
   *
   */
  unsigned int local_m;

  /**
   * Number of natted subnets.
   *
   */
  unsigned int global_n;

  /**
   * Number of global known nodes.
   *
   */
  unsigned int known;


  /**
   * Number of test environments started.
   *
   */
  unsigned int number_of_testsystems_started;

  /**
   * Number of peers started.
   *
   */
  unsigned int number_of_peers_started;

  /**
   * Number of local tests finished.
   *
   */
  unsigned int number_of_local_tests_finished;

  /**
   * Number of local tests prepared to finish.
   *
   */
  unsigned int number_of_local_tests_prepared;

  /**
   * Name of the test case plugin the helper will load.
   *
   */
  char *plugin_name;

  /**
   * Shall we read the topology from file, or from a string.
   */
  unsigned int *read_file;

  /**
   * String with topology data or name of topology file.
   */
  char *topology_data;

  /**
   * Time after this cmd has to finish.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Timeout task.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;
};

/**
 * Struct containing the number of the netjail node and the NetJailState which
 * will be handed to callbacks specific to a test environment.
 */
struct TestingSystemCount
{
  /**
   * The plugin correlated to this netjail node.
   */
  struct TestcasePlugin *plugin;

  /**
   * Kept in a DLL.
   */
  struct TestingSystemCount *next;

  /**
   * Kept in a DLL.
   */
  struct TestingSystemCount *prev;

  /**
   * The send handle for the helper
   */
  struct GNUNET_HELPER_SendHandle *shandle;

  /**
   * Struct to store information handed over to callbacks.
   *
   */
  struct NetJailState *ns;

  /**
   * The messages send to the helper.
   */
  struct GNUNET_MessageHeader *msg;
};


/**
* Code to clean up resource this cmd used.
*
* @param cls closure
*/
static void
netjail_exec_cleanup (void *cls)
{
  struct NetJailState *ns = cls;
  GNUNET_free (ns);
}


/**
 * This function prepares an array with traits.
 *
 */
static enum GNUNET_GenericReturnValue
netjail_exec_traits (void *cls,
                     const void **ret,
                     const char *trait,
                     unsigned int index)
{
  struct NetJailState *ns = cls;
  const struct GNUNET_HELPER_Handle **helper = ns->helper;


  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_helper_handles (helper),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Continuation function from GNUNET_HELPER_send()
 *
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
static void
clear_msg (void *cls, int result)
{
  struct TestingSystemCount *tbc = cls;

  GNUNET_assert (NULL != tbc->shandle);
  // GNUNET_free (tbc->shandle);
  GNUNET_free (tbc->plugin);
  tbc->shandle = NULL;
  GNUNET_free (tbc);
}


static void
send_message_to_locals (
  unsigned int i,
  unsigned int j,
  struct NetJailState *ns,
  struct GNUNET_MessageHeader *header
  )
{
  const struct GNUNET_HELPER_Handle *helper;
  struct TestingSystemCount *tbc;
  unsigned int count;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "send message of type %u to locals\n",
       header->type);
  tbc = GNUNET_new (struct TestingSystemCount);
  tbc->ns = ns;
  if (0 == i)
    count = j;
  else
    count = (i - 1) * ns->local_m + j + ns->known;

  helper = ns->helper[count - 1];



  struct GNUNET_HELPER_SendHandle *sh = GNUNET_HELPER_send (
    (struct GNUNET_HELPER_Handle *) helper,
    header,
    GNUNET_NO,
    &clear_msg,
    tbc);

  tbc->shandle = sh;
}


static void
send_all_local_tests_prepared (unsigned int i, unsigned int j, struct
                               NetJailState *ns)
{
  struct GNUNET_TESTING_CommandAllLocalTestsPrepared *reply;
  size_t msg_length;


  msg_length = sizeof(struct GNUNET_TESTING_CommandAllLocalTestsPrepared);
  reply = GNUNET_new (struct GNUNET_TESTING_CommandAllLocalTestsPrepared);
  reply->header.type = htons (
    GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED);
  reply->header.size = htons ((uint16_t) msg_length);

  send_message_to_locals (i, j, ns, &reply->header);
  GNUNET_free (reply);
}


static void
send_all_peers_started (unsigned int i, unsigned int j, struct NetJailState *ns)
{
  struct GNUNET_TESTING_CommandAllPeersStarted *reply;
  size_t msg_length;

  msg_length = sizeof(struct GNUNET_TESTING_CommandAllPeersStarted);
  reply = GNUNET_new (struct GNUNET_TESTING_CommandAllPeersStarted);
  reply->header.type = htons (
    GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED);
  reply->header.size = htons ((uint16_t) msg_length);

  send_message_to_locals (i, j, ns, &reply->header);
  GNUNET_free (reply);
}


void
barrier_attached (struct NetJailState *ns, const struct
                  GNUNET_MessageHeader *message)
{
  struct CommandBarrierAttached *am;
  struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_TESTING_Barrier *barrier;
  struct GNUNET_ShortHashCode key;
  struct GNUNET_HashCode hc;
  const char *barrier_name;

  am = (struct CommandBarrierAttached *) message;
  barrier_name = (const char *) &am[1];
  barrier = TST_interpreter_get_barrier (ns->is, barrier_name);
  GNUNET_assert (NULL != barrier);
  node = GNUNET_TESTING_barrier_get_node (barrier, am->node_number);
  if (NULL == node)
  {
    node = GNUNET_new (struct GNUNET_TESTING_NetjailNode);
    node->node_number = am->node_number;

    GNUNET_CRYPTO_hash (&(node->node_number), sizeof(node->node_number), &hc);
    memcpy (&key, &hc, sizeof (key));
    GNUNET_CONTAINER_multishortmap_put (barrier->nodes,
                                        &key,
                                        node,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  node->expected_reaches = node->expected_reaches + am->expected_reaches;
  barrier->expected_reaches = barrier->expected_reaches + am->expected_reaches;
}


void
barrier_reached (struct NetJailState *ns, const struct
                 GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTING_Barrier *barrier;
  const char *barrier_name;
  struct GNUNET_TESTING_CommandBarrierReached *rm = (struct
                                                     GNUNET_TESTING_CommandBarrierReached
                                                     *) message;

  barrier_name = (const char *) &rm[1];
  
  barrier = TST_interpreter_get_barrier (ns->is, barrier_name);
  GNUNET_assert (NULL != barrier);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "barrier %s reached %p %u\n",
       barrier_name,
       barrier,
       barrier->reached);
  barrier->reached++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%u %p\n",
           barrier->reached,
           barrier);
  if (GNUNET_TESTING_barrier_crossable (barrier))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s can be crossed\n",
       barrier_name);
    TST_interpreter_finish_attached_cmds (ns->is, barrier->name);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "barrier %s reached finished\n",
       barrier_name);
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
 */
static int
helper_mst (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct NetJailState *ns = cls;
  unsigned int total_number = ns->local_m * ns->global_n + ns->known;
  uint16_t message_type = ntohs (message->type);
  struct GNUNET_TESTING_CommandLocalFinished *lf;

  switch (message_type)
  {
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ATTACHED:
    barrier_attached (ns, message);
    break;
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_REACHED:
    barrier_reached (ns, message);
    break;
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY:
    ns->number_of_testsystems_started++;
    break;
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED:
    ns->number_of_peers_started++;
    if (ns->number_of_peers_started == total_number)
    {
      for (int i = 1; i <= ns->known; i++)
      {
        send_all_peers_started (0,i, ns);
      }
      for (int i = 1; i <= ns->global_n; i++)
      {
        for (int j = 1; j <= ns->local_m; j++)
        {
          send_all_peers_started (i,j, ns);
        }
      }
      ns->number_of_peers_started = 0;
    }
    break;
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TEST_PREPARED:
    ns->number_of_local_tests_prepared++;
    if (ns->number_of_local_tests_prepared == total_number)
    {
      for (int i = 1; i <= ns->known; i++)
      {
        send_all_local_tests_prepared (0,i, ns);
      }

      for (int i = 1; i <= ns->global_n; i++)
      {
        for (int j = 1; j <= ns->local_m; j++)
        {
          send_all_local_tests_prepared (i,j, ns);
        }
      }
    }
    break;
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED:
    lf = (struct GNUNET_TESTING_CommandLocalFinished *) message;

    ns->number_of_local_tests_finished++;
    if (GNUNET_OK != lf->rv)
    {
      GNUNET_TESTING_async_fail (&(ns->ac));
    } else if (ns->number_of_local_tests_finished == total_number)
    {
      GNUNET_SCHEDULER_cancel (ns->timeout_task);
      ns->timeout_task = NULL;
      GNUNET_TESTING_async_finish (&ns->ac);
    }
    break;
  default:
    // We received a message we can not handle.
    GNUNET_assert (0);
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "total %u sysstarted %u peersstarted %u prep %u finished %u %u %u %u\n",
       total_number,
       ns->number_of_testsystems_started,
       ns->number_of_peers_started,
       ns->number_of_local_tests_prepared,
       ns->number_of_local_tests_finished,
       ns->local_m,
       ns->global_n,
       ns->known);




  return GNUNET_OK;
}


/**
 * Callback called if there was an exception during execution of the helper.
 *
 */
static void
exp_cb (void *cls)
{
  struct NetJailState *ns = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called exp_cb.\n");
  if (NULL != ns->timeout_task)
    GNUNET_SCHEDULER_cancel (ns->timeout_task);
  GNUNET_TESTING_async_fail (&(ns->ac));
}


/**
 * Function to initialize a init message for the helper.
 *
 * @param plugin_name Name of the test case plugin the helper will load.
 *
 */
static struct GNUNET_TESTING_CommandHelperInit *
create_helper_init_msg_ (const char *plugin_name)
{
  struct GNUNET_TESTING_CommandHelperInit *msg;
  uint16_t plugin_name_len;
  uint16_t msg_size;

  GNUNET_assert (NULL != plugin_name);
  plugin_name_len = strlen (plugin_name);
  msg_size = sizeof(struct GNUNET_TESTING_CommandHelperInit) + plugin_name_len;
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT);
  msg->plugin_name_size = htons (plugin_name_len);
  GNUNET_memcpy ((char *) &msg[1],
                 plugin_name,
                 plugin_name_len);
  return msg;
}


/**
 * Function which start a single helper process.
 *
 */
static void
start_helper (struct NetJailState *ns,
              unsigned int m,
              unsigned int n)
{
  struct TestcasePlugin *plugin;
  struct GNUNET_HELPER_Handle *helper;
  struct GNUNET_TESTING_CommandHelperInit *msg;
  struct TestingSystemCount *tbc;
  char *m_char;
  char *n_char;
  char *global_n_char;
  char *local_m_char;
  char *known_char;
  char *node_id;
  char *plugin_name;
  char *read_file;
  pid_t pid;
  unsigned int script_num;
  struct GNUNET_ShortHashCode *hkey;
  struct GNUNET_ShortHashCode key;
  struct GNUNET_HashCode hc;
  struct GNUNET_TESTING_NetjailTopology *topology = ns->topology;
  struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_TESTING_NetjailNode *barrier_node;
  struct GNUNET_TESTING_NetjailNamespace *namespace;
  char *data_dir;
  char *script_name;
  struct GNUNET_TESTING_BarrierListEntry *pos;
  struct GNUNET_TESTING_Barrier *barrier;
  struct GNUNET_TESTING_BarrierList *barriers;
  unsigned int node_num;
  char *binary_path;

  if (0 == n)
  {
    node_num = m;
    script_num = m - 1;
  }
  else
  {
    node_num = (n - 1) * ns->local_m + m + ns->known;
    script_num = n - 1 + (n - 1) * ns->local_m + m + ns->known;
  }
  pid = getpid ();

  GNUNET_asprintf (&m_char, "%u", m);
  GNUNET_asprintf (&n_char, "%u", n);
  GNUNET_asprintf (&local_m_char, "%u", ns->local_m);
  GNUNET_asprintf (&global_n_char, "%u",ns->global_n);
  GNUNET_asprintf (&known_char, "%u",ns->known);
  GNUNET_asprintf (&node_id, "%s%06x-%06x\n",
                   "if",
                   pid,
                   script_num);
  // GNUNET_asprintf (&topology_data, "'%s'", ns->topology_data);
  GNUNET_asprintf (&read_file, "%u", *(ns->read_file));

  data_dir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  GNUNET_asprintf (&script_name, "%s%s", data_dir, NETJAIL_EXEC_SCRIPT);
  unsigned int helper_check = GNUNET_OS_check_helper_binary (
    script_name,
    GNUNET_YES,
    NULL);

  tbc = GNUNET_new (struct TestingSystemCount);
  tbc->ns = ns;

  if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No SUID for %s!\n",
                script_name);
    GNUNET_TESTING_interpreter_fail (ns->is);
  }
  else if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s not found!\n",
                script_name);
    GNUNET_TESTING_interpreter_fail (ns->is);
  }

  binary_path = GNUNET_OS_get_libexec_binary_path (HELPER_CMDS_BINARY);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sysstarted %u peersstarted %u prep %u finished %u %u %u %u\n",
       ns->number_of_testsystems_started,
       ns->number_of_peers_started,
       ns->number_of_local_tests_prepared,
       ns->number_of_local_tests_finished,
       ns->local_m,
       ns->global_n,
       ns->known);
  {
    char *const script_argv[] = {script_name,
                                 m_char,
                                 n_char,
                                 binary_path,
                                 global_n_char,
                                 local_m_char,
                                 node_id,
                                 read_file,
                                 ns->topology_data,
                                 NULL};
    helper = GNUNET_HELPER_start (
      GNUNET_YES,
      script_name,
      script_argv,
      &helper_mst,
      &exp_cb,
      ns);
    GNUNET_array_append (ns->helper, ns->n_helper, helper);
  }
  GNUNET_TESTING_add_netjail_helper (ns->is,
                                     helper);
  plugin_name = topology->plugin;

  hkey = GNUNET_new (struct GNUNET_ShortHashCode);
  if (0 == n)
  {
    GNUNET_CRYPTO_hash (&m, sizeof(m), &hc);
    memcpy (hkey,
            &hc,
            sizeof (*hkey));
    if (1 == GNUNET_CONTAINER_multishortmap_contains (topology->map_globals,
                                                      hkey))
    {
      node = GNUNET_CONTAINER_multishortmap_get (topology->map_globals,
                                                 hkey);
      if (NULL != node->plugin)
        plugin_name = node->plugin;
    }
  }
  else
  {
    GNUNET_CRYPTO_hash (&n, sizeof(n), &hc);
    memcpy (hkey,
            &hc,
            sizeof (*hkey));
    if (1 == GNUNET_CONTAINER_multishortmap_contains (topology->map_namespaces,
                                                      hkey))
    {
      namespace = GNUNET_CONTAINER_multishortmap_get (topology->map_namespaces,
                                                      hkey);
      GNUNET_CRYPTO_hash (&m, sizeof(m), &hc);
      memcpy (hkey,
              &hc,
              sizeof (*hkey));
      if (1 == GNUNET_CONTAINER_multishortmap_contains (namespace->nodes,
                                                        hkey))
      {
        node = GNUNET_CONTAINER_multishortmap_get (namespace->nodes,
                                                   hkey);
        if (NULL != node->plugin)
          plugin_name = node->plugin;
      }
    }


  }
  GNUNET_assert (NULL != node);
  node->node_number = node_num;
  plugin = GNUNET_new (struct TestcasePlugin);
  plugin->api = GNUNET_PLUGIN_load (plugin_name,
                                    NULL);
  barriers = plugin->api->get_waiting_for_barriers ();


  for (pos = barriers->head; NULL != pos; pos = pos->next)
  {
    barrier = TST_interpreter_get_barrier (ns->is, pos->barrier_name);
    if (NULL == barrier)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
       "barrier %s added\n",
       pos->barrier_name);
      barrier = GNUNET_new (struct GNUNET_TESTING_Barrier);
      barrier->name = pos->barrier_name;
      barrier->shadow = GNUNET_YES;
      TST_interpreter_add_barrier (ns->is, barrier);

      LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%u %p\n",
           barrier->reached,
           barrier);

      barrier->nodes = GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
       "barrier %p %s node %u added \n",
         barrier,
         pos->barrier_name,
         node->node_number);
    barrier_node = GNUNET_new (struct GNUNET_TESTING_NetjailNode);
    barrier_node->node_number = node->node_number;
    barrier_node->expected_reaches = pos->expected_reaches;
    barrier->expected_reaches = barrier->expected_reaches
                                + pos->expected_reaches;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "number_to_be_reached %u\n",
         barrier->number_to_be_reached);
    if (GNUNET_YES == barrier->shadow)
      barrier->number_to_be_reached++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "number_to_be_reached %u\n",
         barrier->number_to_be_reached);
    GNUNET_CRYPTO_hash (&(node->node_number), sizeof(node->node_number), &hc);
    memcpy (&key, &hc, sizeof (key));
    GNUNET_CONTAINER_multishortmap_put (barrier->nodes,
                                        &key,
                                        barrier_node,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }

  tbc->plugin = plugin;

  msg = create_helper_init_msg_ (plugin_name);

  tbc->shandle = GNUNET_HELPER_send (
    helper,
    &msg->header,
    GNUNET_NO,
    &clear_msg,
    tbc);

  if (NULL == tbc->shandle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Send handle is NULL!\n");
    GNUNET_TESTING_interpreter_fail (ns->is);
  }
  GNUNET_free (pos);
  GNUNET_free (binary_path);
  GNUNET_free (hkey);
  GNUNET_free (msg);
  GNUNET_free (m_char);
  GNUNET_free (n_char);
  GNUNET_free (local_m_char);
  GNUNET_free (global_n_char);
  GNUNET_free (known_char);
  GNUNET_free (node_id);
  GNUNET_free (read_file);
  GNUNET_free (data_dir);
  GNUNET_free (script_name);
  GNUNET_free (barriers);
}


/**
 * Function run when the cmd terminates (good or bad) with timeout.
 *
 * @param cls the interpreter state
 */
static void
do_timeout (void *cls)
{
  struct NetJailState *ns = cls;
  struct GNUNET_TESTING_Command *cmd;

  ns->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Terminating cmd due to global timeout\n");
  cmd = GNUNET_TESTING_interpreter_get_current_command (ns->is);
  GNUNET_TESTING_async_finish (cmd->ac);
}


/**
* This function starts a helper process for each node.
*
* @param cls closure.
* @param cmd CMD being run.
* @param is interpreter state.
*/
static void
netjail_exec_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct NetJailState *ns = cls;

  ns->is = is;
  for (int i = 1; i <= ns->known; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "i %u\n",
                i);
    start_helper (ns,
                  i,
                  0);
  }

  for (int i = 1; i <= ns->global_n; i++)
  {
    for (int j = 1; j <= ns->local_m; j++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "i %u j %u\n",
                  i,
                  j);
      start_helper (ns,
                    j,
                    i);
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding timeout %s\n",
              GNUNET_STRINGS_relative_time_to_string (ns->timeout, GNUNET_NO));
  ns->timeout_task
    = GNUNET_SCHEDULER_add_delayed (ns->timeout,
                                    &do_timeout,
                                    ns);
}


/**
 * Create command.
 *
 * @param label Name for the command.
 * @param topology The complete topology information.
 * @param read_file Flag indicating if the the name of the topology file is send to the helper, or a string with the topology data.
 * @param topology_data If read_file is GNUNET_NO, topology_data holds the string with the topology.
 * @param timeout Before this timeout is reached this cmd MUST finish.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_cmds_helper (
  const char *label,
  struct GNUNET_TESTING_NetjailTopology *topology,
  unsigned int *read_file,
  char *topology_data,
  struct GNUNET_TIME_Relative timeout)
{
  struct NetJailState *ns;

  ns = GNUNET_new (struct NetJailState);
  ns->local_m = topology->nodes_m;
  ns->global_n = topology->namespaces_n;
  ns->known = topology->nodes_x;
  ns->plugin_name = topology->plugin;
  ns->topology = topology;
  ns->read_file = read_file;
  ns->topology_data = topology_data;
  ns->timeout = GNUNET_TIME_relative_subtract (timeout, TIMEOUT);

  return GNUNET_TESTING_command_new (ns, label,
                                     &netjail_exec_run,
                                     &netjail_exec_cleanup,
                                     &netjail_exec_traits,
                                     &ns->ac);
}
