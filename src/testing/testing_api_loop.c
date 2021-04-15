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
 * @file testing/testing_api_loop.c
 * @brief main interpreter loop for testcases
 * @author Christian Grothoff (GNU Taler testing)
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
*/
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "testing.h"

struct GNUNET_TESTING_Interpreter *is;

/**
 * Closure used to sync an asynchronous with an synchronous command.
 */
struct SyncTaskClosure
{

  /**
   * The asynchronous command the synchronous command waits for.
   */
  const struct GNUNET_TESTING_Command *async_cmd;

  /**
   * The synchronous command that waits for the asynchronous command.
   */
  const struct GNUNET_TESTING_Command *sync_cmd;

  /**
   * The interpreter of the test.
   */
  struct GNUNET_TESTING_Interpreter *is;
};

/**
* Closure used to run the finish task.
*/
struct FinishTaskClosure
{

  /**
   * The asynchronous command the synchronous command waits for.
   */
  const struct GNUNET_TESTING_Command *cmd;

  /**
   * The interpreter of the test.
   */
  struct GNUNET_TESTING_Interpreter *is;
};

/**
 * Lookup command by label.
 *
 * @param label label to look for
 * @return NULL if command was not found
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command (const char *label)
{
  if (NULL == label)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Attempt to lookup command for empty label\n");
    return NULL;
  }
  /* Search backwards as we most likely reference recent commands */
  for (int i = is->ip; i >= 0; i--)
  {
    const struct GNUNET_TESTING_Command *cmd = &is->commands[i];

    /* Give precedence to top-level commands.  */
    if ( (NULL != cmd->label) &&
         (0 == strcmp (cmd->label,
                       label)) )
      return cmd;

    if (GNUNET_TESTING_cmd_is_batch (cmd))
    {
#define BATCH_INDEX 1
      struct GNUNET_TESTING_Command *batch;
      struct GNUNET_TESTING_Command *current;
      struct GNUNET_TESTING_Command *icmd;
      const struct GNUNET_TESTING_Command *match;

      current = GNUNET_TESTING_cmd_batch_get_current (cmd);
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_TESTING_get_trait_cmd (cmd,
                                                   BATCH_INDEX,
                                                   &batch));
      /* We must do the loop forward, but we can find the last match */
      match = NULL;
      for (unsigned int j = 0;
           NULL != (icmd = &batch[j])->label;
           j++)
      {
        if (current == icmd)
          break; /* do not go past current command */
        if ( (NULL != icmd->label) &&
             (0 == strcmp (icmd->label,
                           label)) )
          match = icmd;
      }
      if (NULL != match)
        return match;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Command not found: %s\n",
              label);
  return NULL;

}


/**
 * Run the main interpreter loop that performs exchange operations.
 *
 * @param cls contains the `struct InterpreterState`
 */
static void
interpreter_run (void *cls);


/**
 * Current command is done, run the next one.
 */
static void
interpreter_next (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  static unsigned long long ipc;
  static struct GNUNET_TIME_Absolute last_report;
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  if (GNUNET_SYSERR == is->result)
    return; /* ignore, we already failed! */
  if (GNUNET_TESTING_cmd_is_batch (cmd))
  {
    GNUNET_TESTING_cmd_batch_next (is);
  }
  else
  {
    cmd->finish_time = GNUNET_TIME_absolute_get ();
    is->ip++;
  }
  if (0 == (ipc % 1000))
  {
    if (0 != ipc)
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "Interpreter executed 1000 instructions in %s\n",
                  GNUNET_STRINGS_relative_time_to_string (
                    GNUNET_TIME_absolute_get_duration (last_report),
                    GNUNET_YES));
    last_report = GNUNET_TIME_absolute_get ();
  }
  ipc++;
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run,
                                       is);
}


static void
run_finish_task_next (void *cls)
{
  struct FinishTaskClosure *ftc = cls;
  const struct GNUNET_TESTING_Command *cmd = ftc->cmd;
  struct GNUNET_TESTING_Interpreter *is = ftc->is;

  if (cmd->finish (cmd->cls, &interpreter_next, is))
  {
    is->finish_task = GNUNET_SCHEDULER_add_now (&run_finish_task_next, ftc);
  }
  else
  {
    is->finish_task = NULL;
  }

}


static void
run_finish_task_sync (void *cls)
{
  struct SyncTaskClosure *stc = cls;
  const struct GNUNET_TESTING_Command *cmd = stc->async_cmd;
  const struct GNUNET_TESTING_Command *sync_cmd = stc->sync_cmd;
  struct FinishTaskClosure *ftc;
  struct SyncState *sync_state = sync_cmd->cls;
  struct GNUNET_SCHEDULER_Task *finish_task = sync_state->finish_task;

  GNUNET_assert (NULL != finish_task);
  ftc = GNUNET_new (struct FinishTaskClosure);
  ftc->cmd = stc->sync_cmd;
  ftc->is = stc->is;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  if (cmd->default_timeout.rel_value_us < now.abs_value_us
      - sync_state->start_finish_time.abs_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "The command with label %s did not finish its asyncronous task in time.\n",
                cmd->label);
    is->result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
  }

  if (cmd->finish (cmd->cls, run_finish_task_next, ftc))
  {
    finish_task = GNUNET_SCHEDULER_add_now (&run_finish_task_sync, stc);
  }
  else
  {
    finish_task = NULL;
  }
}


static void
start_finish_on_ref (void *cls,
                     const struct GNUNET_TESTING_Command *cmd,
                     struct GNUNET_TESTING_Interpreter *is)
{
  struct SyncState *sync_state = cls;
  struct SyncTaskClosure *stc;
  const struct GNUNET_TESTING_Command *async_cmd;

  async_cmd = sync_state->async_cmd;
  stc = GNUNET_new (struct SyncTaskClosure);
  stc->async_cmd = async_cmd;
  stc->sync_cmd = cmd;
  stc->is = is;
  sync_state->start_finish_time = GNUNET_TIME_absolute_get ();
  sync_state->finish_task = GNUNET_SCHEDULER_add_now (&run_finish_task_sync,
                                                      stc);
}


const struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_finish (const char *finish_label,
                           const char *cmd_ref,
                           struct GNUNET_TIME_Relative timeout)
{
  const struct GNUNET_TESTING_Command *async_cmd;
  struct SyncState *sync_state;

  async_cmd = GNUNET_TESTING_interpreter_lookup_command (cmd_ref);
  sync_state = GNUNET_new (struct SyncState);
  sync_state->async_cmd = async_cmd;

  struct GNUNET_TESTING_Command cmd = {
    .cls = sync_state,
    .label = finish_label,
    .run = &start_finish_on_ref,
    .asynchronous_finish = GNUNET_NO
  };

  return cmd;
}


const struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_make_asynchronous (const struct GNUNET_TESTING_Command cmd)
{

  GNUNET_assert (NULL != cmd.finish);
  const struct GNUNET_TESTING_Command async_cmd = {
    .cls = cmd.cls,
    .label = cmd.label,
    .run = cmd.run,
    .cleanup = cmd.cleanup,
    .traits = cmd.traits,
    .finish = cmd.finish,
    .asynchronous_finish = GNUNET_YES
  };

  return async_cmd;
}


/**
 * Current command failed, clean up and fail the test case.
 *
 * @param is interpreter of the test
 */
void
GNUNET_TESTING_interpreter_fail (struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Failed at command `%s'\n",
              cmd->label);
  while (GNUNET_TESTING_cmd_is_batch (cmd))
  {
    cmd = GNUNET_TESTING_cmd_batch_get_current (cmd);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Batch is at command `%s'\n",
                cmd->label);
  }
  is->result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Create command array terminator.
 *
 * @return a end-command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_end (void)
{
  static struct GNUNET_TESTING_Command cmd;
  cmd.label = NULL;

  return cmd;
}


/**
 * Obtain current label.
 */
const char *
GNUNET_TESTING_interpreter_get_current_label (struct
                                              GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  return cmd->label;
}


/**
 * Run the main interpreter loop.
 *
 * @param cls contains the `struct GNUNET_TESTING_Interpreter`
 */
static void
interpreter_run (void *cls)
{
  struct FinishTaskClosure *ftc;
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  is->task = NULL;

  if (NULL == cmd->label)
  {

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running command END\n");
    is->result = GNUNET_OK;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running command `%s'\n",
              cmd->label);
  cmd->start_time
    = cmd->last_req_time
      = GNUNET_TIME_absolute_get ();
  cmd->num_tries = 1;
  cmd->run (cmd->cls,
            cmd,
            is);
  if ((NULL != cmd->finish) && (GNUNET_NO == cmd->asynchronous_finish))
  {
    ftc = GNUNET_new (struct FinishTaskClosure);
    ftc->cmd = cmd;
    ftc->is = is;
    cmd->finish_task = GNUNET_SCHEDULER_add_now (run_finish_task_next, ftc);
  }
  else
  {
    interpreter_next (is);
  }
}


/**
 * Function run when the test terminates (good or bad).
 * Cleans up our state.
 *
 * @param cls the interpreter state.
 */
static void
do_shutdown (void *cls)
{
  (void) cls;
  struct GNUNET_TESTING_Command *cmd;
  const char *label;

  label = is->commands[is->ip].label;
  if (NULL == label)
    label = "END";

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Executing shutdown at `%s'\n",
              label);

  for (unsigned int j = 0;
       NULL != (cmd = &is->commands[j])->label;
       j++) {
    cmd->cleanup (cmd->cls,
                  cmd);
    if (NULL != cmd->finish_task)
    {
      GNUNET_SCHEDULER_cancel (cmd->finish_task);
      cmd->finish_task = NULL;
    }
  }

  if (NULL != is->task)
  {
    GNUNET_SCHEDULER_cancel (is->task);
    is->task = NULL;
  }
  if (NULL != is->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (is->timeout_task);
    is->timeout_task = NULL;
  }
  GNUNET_free (is->commands);
}


/**
 * Function run when the test terminates (good or bad) with timeout.
 *
 * @param cls NULL
 */
static void
do_timeout (void *cls)
{
  (void) cls;

  is->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Terminating test due to timeout\n");
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Run the testsuite.  Note, CMDs are copied into
 * the interpreter state because they are _usually_
 * defined into the "run" method that returns after
 * having scheduled the test interpreter.
 *
 * @param is the interpreter state
 * @param commands the list of command to execute
 * @param timeout how long to wait
 */
int
GNUNET_TESTING_run (const char *cfg_filename,
                    struct GNUNET_TESTING_Command *commands,
                    struct GNUNET_TIME_Relative timeout)
{
  unsigned int i;

  is = GNUNET_new (struct GNUNET_TESTING_Interpreter);

  if (NULL != is->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (is->timeout_task);
    is->timeout_task = NULL;
  }
  /* get the number of commands */
  for (i = 0; NULL != commands[i].label; i++)
    ;
  is->commands = GNUNET_new_array (i + 1,
                                   struct GNUNET_TESTING_Command);
  memcpy (is->commands,
          commands,
          sizeof (struct GNUNET_TESTING_Command) * i);

  is->timeout_task = GNUNET_SCHEDULER_add_delayed
                       (timeout,
                       &do_timeout,
                       is);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, is);
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run, is);
  return GNUNET_OK;
}


/* end of testing_api_loop.c */
