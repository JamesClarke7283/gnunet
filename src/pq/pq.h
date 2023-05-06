/*
   This file is part of GNUnet
   Copyright (C) 2017, 2019 GNUnet e.V.

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
 * @file pq/pq.h
 * @brief shared internal data structures of libgnunetpq
 * @author Christian Grothoff
 */
#ifndef PQ_H
#define PQ_H

#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"


/**
 * Handle to Postgres database.
 */
struct GNUNET_PQ_Context
{
  /**
   * Actual connection.
   */
  PGconn *conn;

  /**
   * Statements to execute upon connection.
   */
  struct GNUNET_PQ_ExecuteStatement *es;

  /**
   * Prepared statements.
   */
  struct GNUNET_PQ_PreparedStatement *ps;

  /**
   * Length of the @e ps array.
   */
  unsigned int ps_len;

  /**
   * Last used offset in the @e ps array.
   */
  unsigned int ps_off;

  /**
   * Configuration to use to connect to the DB.
   */
  char *config_str;

  /**
   * Path to load SQL files from.
   */
  char *load_path;

  /**
   * Suffix to append to path to load on startup.
   */
  char *auto_suffix;

  /**
   * Map managing event subscriptions.
   */
  struct GNUNET_CONTAINER_MultiShortmap *channel_map;

  /**
   * Task responsible for processing events.
   */
  struct GNUNET_SCHEDULER_Task *event_task;

  /**
   * File descriptor wrapper for @e event_task.
   */
  struct GNUNET_NETWORK_Handle *rfd;

  /**
   * How fast should we resubscribe again?
   */
  struct GNUNET_TIME_Relative resubscribe_backoff;

  /**
   * Flags controlling the connection.
   */
  enum GNUNET_PQ_Options flags;

  /**
   * Mapping between array types and Oid's, filled at reconnect
   */
  Oid arraytype2oid[GNUNET_PQ_ARRAY_MAX];
};



/**
 * Internal API. Reconnect should re-register notifications
 * after a disconnect.
 *
 * @param db the DB handle
 * @param fd socket to listen on
 */
void
GNUNET_PQ_event_reconnect_ (struct GNUNET_PQ_Context *db,
                            int fd);


#endif
