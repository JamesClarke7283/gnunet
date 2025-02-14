/*
   This file is part of GNUnet
   Copyright (C) 2015, 2016 GNUnet e.V.

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
 * @file curl/curl_reschedule.c
 * @brief API for event loop integration with GNUnet SCHEDULER.
 * @author Christian Grothoff
 */
#include "platform.h"
#include <jansson.h>
#include "gnunet_curl_lib.h"
#include "gnunet_util_lib.h"
#include "curl_internal.h"

/**
 * Closure for #GNUNET_CURL_gnunet_scheduler_reschedule().
 */
struct GNUNET_CURL_RescheduleContext
{
  /**
   * Just the task.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Context we manage.
   */
  struct GNUNET_CURL_Context *ctx;

  /**
   * Parser of the raw response.
   */
  GNUNET_CURL_RawParser parser;

  /**
   * Deallocate the response object.
   */
  GNUNET_CURL_ResponseCleaner cleaner;
};


struct GNUNET_CURL_RescheduleContext *
GNUNET_CURL_gnunet_rc_create_with_parser (struct GNUNET_CURL_Context *ctx,
                                          GNUNET_CURL_RawParser rp,
                                          GNUNET_CURL_ResponseCleaner rc)
{
  struct GNUNET_CURL_RescheduleContext *rctx;

  rctx = GNUNET_new (struct GNUNET_CURL_RescheduleContext);
  rctx->ctx = ctx;
  rctx->parser = rp;
  rctx->cleaner = rc;

  return rctx;
}


/**
 * Just a wrapper to avoid casting of function pointers.
 *
 * @param response the (JSON) response to clean.
 */
static void
clean_result (void *response)
{
  json_decref (response);
}


struct GNUNET_CURL_RescheduleContext *
GNUNET_CURL_gnunet_rc_create (struct GNUNET_CURL_Context *ctx)
{
  struct GNUNET_CURL_RescheduleContext *rc;

  rc = GNUNET_new (struct GNUNET_CURL_RescheduleContext);
  rc->ctx = ctx;
  rc->parser = &GNUNET_CURL_download_get_result_;
  rc->cleaner = &clean_result;
  return rc;
}


void
GNUNET_CURL_gnunet_rc_destroy (struct GNUNET_CURL_RescheduleContext *rc)
{
  if (NULL != rc->task)
    GNUNET_SCHEDULER_cancel (rc->task);
  GNUNET_free (rc);
}


/**
 * Task that runs the context's event loop with the GNUnet scheduler.
 *
 * @param cls a `struct GNUNET_CURL_RescheduleContext *`
 */
static void
context_task (void *cls)
{
  struct GNUNET_CURL_RescheduleContext *rc = cls;
  long timeout;
  int max_fd;
  fd_set read_fd_set;
  fd_set write_fd_set;
  fd_set except_fd_set;
  struct GNUNET_NETWORK_FDSet *rs;
  struct GNUNET_NETWORK_FDSet *ws;
  struct GNUNET_TIME_Relative delay;

  rc->task = NULL;
  GNUNET_CURL_perform2 (rc->ctx, rc->parser, rc->cleaner);
  max_fd = -1;
  timeout = -1;
  FD_ZERO (&read_fd_set);
  FD_ZERO (&write_fd_set);
  FD_ZERO (&except_fd_set);
  GNUNET_CURL_get_select_info (rc->ctx,
                               &read_fd_set,
                               &write_fd_set,
                               &except_fd_set,
                               &max_fd,
                               &timeout);
  if (timeout >= 0)
    delay =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                     timeout);
  else
    delay = GNUNET_TIME_UNIT_FOREVER_REL;
  rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (rs,
                                    &read_fd_set,
                                    max_fd + 1);
  ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (ws,
                                    &write_fd_set,
                                    max_fd + 1);
  if (NULL == rc->task)
    rc->task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                            delay,
                                            rs,
                                            ws,
                                            &context_task,
                                            rc);
  GNUNET_NETWORK_fdset_destroy (rs);
  GNUNET_NETWORK_fdset_destroy (ws);
}


void
GNUNET_CURL_gnunet_scheduler_reschedule (void *cls)
{
  struct GNUNET_CURL_RescheduleContext *rc = *(void **) cls;

  if (NULL != rc->task)
    GNUNET_SCHEDULER_cancel (rc->task);
  rc->task = GNUNET_SCHEDULER_add_now (&context_task,
                                       rc);
}


/* end of curl_reschedule.c */
