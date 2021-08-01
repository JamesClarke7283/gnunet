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
 * @file pq/pq_event.c
 * @brief event notifications via Postgres
 * @author Christian Grothoff
 */
#include "platform.h"
#include "pq.h"
#include <pthread.h>


/**
 * Handle for an active LISTENer to the database.
 */
struct GNUNET_DB_EventHandler
{
  /**
   * Channel name.
   */
  struct GNUNET_ShortHashCode sh;

  /**
   * Function to call on events.
   */
  GNUNET_DB_EventCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * Database context this event handler is with.
   */
  struct GNUNET_PQ_Context *db;
};


/**
 * Convert @a es to a short hash.
 *
 * @param es spec to hash to an identifier
 * @param[out] sh short hash to set
 */
static void
es_to_sh (const struct GNUNET_DB_EventHeaderP *es,
          struct GNUNET_ShortHashCode *sh)
{
  struct GNUNET_HashCode h_channel;

  GNUNET_CRYPTO_hash (es,
                      ntohs (es->size),
                      &h_channel);
  GNUNET_static_assert (sizeof (*sh) <= sizeof (h_channel));
  memcpy (sh,
          &h_channel,
          sizeof (*sh));
}


/**
 * Convert @a sh to a Postgres identifier.
 *
 * @param sh short hash to convert to an identifier
 * @param[out] identifier by default, Postgres supports
 *     NAMEDATALEN=64 character identifiers
 * @return end position of the identifier
 */
static char *
sh_to_channel (struct GNUNET_ShortHashCode *sh,
               char identifier[64])
{
  char *end;

  end = GNUNET_STRINGS_data_to_string (sh,
                                       sizeof (*sh),
                                       identifier,
                                       63);
  GNUNET_assert (NULL != end);
  *end = '\0';
  return end;
}


/**
 * Convert @a es to a Postgres identifier.
 *
 * @param es spec to hash to an identifier
 * @param[out] identifier by default, Postgres supports
 *     NAMEDATALEN=64 character identifiers
 * @return end position of the identifier
 */
static char *
es_to_channel (const struct GNUNET_DB_EventHeaderP *es,
               char identifier[64])
{
  struct GNUNET_ShortHashCode sh;

  es_to_sh (es,
            &sh);
  return sh_to_channel (&sh,
                        identifier);
}


/**
 * Closure for #do_notify().
 */
struct NotifyContext
{
  /**
   * Extra argument of the notification, or NULL.
   */
  void *extra;

  /**
   * Number of bytes in @e extra.
   */
  size_t extra_size;
};


/**
 * Function called on every event handler that
 * needs to be triggered.
 *
 * @param cls a `struct NotifyContext`
 * @param sh channel name
 * @param value a `struct GNUNET_DB_EventHandler`
 * @return #GNUNET_OK continue to iterate
 */
static int
do_notify (void *cls,
           const struct GNUNET_ShortHashCode *sh,
           void *value)
{
  struct NotifyContext *ctx = cls;
  struct GNUNET_DB_EventHandler *eh = value;

  eh->cb (eh->cb_cls,
          ctx->extra,
          ctx->extra_size);
  return GNUNET_OK;
}


void
GNUNET_PQ_event_set_socket_callback (struct GNUNET_PQ_Context *db,
                                     GNUNET_PQ_SocketCallback sc,
                                     void *sc_cls)
{
  int fd;

  db->sc = sc;
  db->sc_cls = sc_cls;
  if (NULL == sc)
    return;
  GNUNET_assert (0 ==
                 pthread_mutex_lock (&db->notify_lock));
  fd = PQsocket (db->conn);
  if ( (-1 != fd) &&
       (0 != GNUNET_CONTAINER_multishortmap_size (db->channel_map)) )
    sc (sc_cls,
        fd);
  GNUNET_assert (0 ==
                 pthread_mutex_unlock (&db->notify_lock));
}


void
GNUNET_PQ_event_do_poll (struct GNUNET_PQ_Context *db)
{
  PGnotify *n;

  GNUNET_assert (0 ==
                 pthread_mutex_lock (&db->notify_lock));
  if (1 !=
      PQconsumeInput (db->conn))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read from Postgres: %s\n",
                PQerrorMessage (db->conn));
  while (NULL != (n = PQnotifies (db->conn)))
  {
    struct GNUNET_ShortHashCode sh;
    struct NotifyContext ctx = {
      .extra = NULL
    };

    if (GNUNET_OK !=
        GNUNET_STRINGS_string_to_data (n->relname,
                                       strlen (n->relname),
                                       &sh,
                                       sizeof (sh)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Ignoring notification for unsupported channel identifier `%s'\n",
                  n->relname);
      PQfreemem (n);
      continue;
    }
    if ( (NULL != n->extra) &&
         (GNUNET_OK !=
          GNUNET_STRINGS_string_to_data_alloc (n->extra,
                                               strlen (n->extra),
                                               &ctx.extra,
                                               &ctx.extra_size)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Ignoring notification for unsupported extra data `%s' on channel `%s'\n",
                  n->extra,
                  n->relname);
      PQfreemem (n);
      continue;
    }
    GNUNET_CONTAINER_multishortmap_iterate (db->channel_map,
                                            &do_notify,
                                            &ctx);
    GNUNET_free (ctx.extra);
    PQfreemem (n);
  }
  GNUNET_assert (0 ==
                 pthread_mutex_unlock (&db->notify_lock));
}


/**
 * Function called when the Postgres FD changes and we need
 * to update the scheduler event loop task.
 *
 * @param cls a `struct GNUNET_PQ_Context *`
 * @param fd the file descriptor, possibly -1
 */
static void
scheduler_fd_cb (void *cls,
                 int fd);


/**
 * The GNUnet scheduler notifies us that we need to
 * trigger the DB event poller.
 *
 * @param cls a `struct GNUNET_PQ_Context *`
 */
static void
do_scheduler_notify (void *cls)
{
  struct GNUNET_PQ_Context *db = cls;

  GNUNET_assert (db->scheduler_on);
  GNUNET_assert (NULL != db->rfd);
  GNUNET_PQ_event_do_poll (db);
  db->event_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     db->rfd,
                                     &do_scheduler_notify,
                                     db);
}


/**
 * Function called when the Postgres FD changes and we need
 * to update the scheduler event loop task.
 *
 * @param cls a `struct GNUNET_PQ_Context *`
 * @param fd the file descriptor, possibly -1
 */
static void
scheduler_fd_cb (void *cls,
                 int fd)
{
  struct GNUNET_PQ_Context *db = cls;

  if (NULL != db->event_task)
  {
    GNUNET_SCHEDULER_cancel (db->event_task);
    db->event_task = NULL;
  }
  GNUNET_free (db->rfd);
  if (-1 == fd)
    return;
  if (0 == GNUNET_CONTAINER_multishortmap_size (db->channel_map))
    return;
  db->rfd = GNUNET_NETWORK_socket_box_native (fd);
  db->event_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_ZERO,
                                     db->rfd,
                                     &do_scheduler_notify,
                                     db);
}


void
GNUNET_PQ_event_scheduler_start (struct GNUNET_PQ_Context *db)
{
  int fd;

  GNUNET_assert (! db->scheduler_on);
  GNUNET_assert (NULL == db->sc);
  db->scheduler_on = true;
  db->sc = &scheduler_fd_cb;
  db->sc_cls = db;
  fd = PQsocket (db->conn);
  scheduler_fd_cb (db,
                   fd);
}


void
GNUNET_PQ_event_scheduler_stop (struct GNUNET_PQ_Context *db)
{
  GNUNET_assert (db->scheduler_on);
  GNUNET_free (db->rfd);
  db->sc = NULL;
  db->scheduler_on = false;
  if (NULL != db->event_task)
  {
    GNUNET_SCHEDULER_cancel (db->event_task);
    db->event_task = NULL;
  }
}


static void
manage_subscribe (struct GNUNET_PQ_Context *db,
                  const char *cmd,
                  struct GNUNET_DB_EventHandler *eh)
{
  char sql[16 + 64];
  char *end;
  PGresult *result;

  end = stpcpy (sql,
                cmd);
  end = sh_to_channel (&eh->sh,
                       end);
  result = PQexec (db->conn,
                   sql);
  if (PGRES_COMMAND_OK != PQresultStatus (result))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                     "pq",
                     "Failed to execute `%s': %s/%s/%s/%s/%s",
                     sql,
                     PQresultErrorField (result,
                                         PG_DIAG_MESSAGE_PRIMARY),
                     PQresultErrorField (result,
                                         PG_DIAG_MESSAGE_DETAIL),
                     PQresultErrorMessage (result),
                     PQresStatus (PQresultStatus (result)),
                     PQerrorMessage (db->conn));
  }
  PQclear (result);
}


/**
 * Re-subscribe to notifications after disconnect.
 *
 * @param cls the DB context
 * @param sh the short hash of the channel
 * @param eh the event handler
 * @return #GNUNET_OK to continue to iterate
 */
static int
register_notify (void *cls,
                 const struct GNUNET_ShortHashCode *sh,
                 void *value)
{
  struct GNUNET_PQ_Context *db = cls;
  struct GNUNET_DB_EventHandler *eh = value;

  manage_subscribe (db,
                    "LISTEN ",
                    eh);
  return GNUNET_OK;
}


void
GNUNET_PQ_event_reconnect_ (struct GNUNET_PQ_Context *db)
{
  GNUNET_assert (0 ==
                 pthread_mutex_lock (&db->notify_lock));
  GNUNET_CONTAINER_multishortmap_iterate (db->channel_map,
                                          &register_notify,
                                          db);
  GNUNET_assert (0 ==
                 pthread_mutex_unlock (&db->notify_lock));
}


struct GNUNET_DB_EventHandler *
GNUNET_PQ_event_listen (struct GNUNET_PQ_Context *db,
                        const struct GNUNET_DB_EventHeaderP *es,
                        GNUNET_DB_EventCallback cb,
                        void *cb_cls)
{
  struct GNUNET_DB_EventHandler *eh;
  bool was_zero;

  eh = GNUNET_new (struct GNUNET_DB_EventHandler);
  eh->db = db;
  es_to_sh (es,
            &eh->sh);
  eh->cb = cb;
  eh->cb_cls = cb_cls;
  GNUNET_assert (0 ==
                 pthread_mutex_lock (&db->notify_lock));
  was_zero = (0 == GNUNET_CONTAINER_multishortmap_size (db->channel_map));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multishortmap_put (db->channel_map,
                                                     &eh->sh,
                                                     eh,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  if ( (NULL != db->sc) &&
       was_zero)
  {
    int fd = PQsocket (db->conn);

    if (-1 != fd)
      db->sc (db->sc_cls,
              fd);
  }
  manage_subscribe (db,
                    "LISTEN ",
                    eh);
  GNUNET_assert (0 ==
                 pthread_mutex_unlock (&db->notify_lock));
  return eh;
}


void
GNUNET_PQ_event_listen_cancel (struct GNUNET_DB_EventHandler *eh)
{
  struct GNUNET_PQ_Context *db = eh->db;

  GNUNET_assert (0 ==
                 pthread_mutex_lock (&db->notify_lock));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multishortmap_remove (db->channel_map,
                                                        &eh->sh,
                                                        eh));

  manage_subscribe (db,
                    "UNLISTEN ",
                    eh);
  if ( (NULL != db->sc) &&
       (0 == GNUNET_CONTAINER_multishortmap_size (db->channel_map)) )
  {
    db->sc (db->sc_cls,
            -1);
  }
  GNUNET_assert (0 ==
                 pthread_mutex_unlock (&db->notify_lock));
  GNUNET_free (eh);
}


void
GNUNET_PQ_event_notify (struct GNUNET_PQ_Context *db,
                        const struct GNUNET_DB_EventHeaderP *es,
                        const void *extra,
                        size_t extra_size)
{
  char sql[16 + 64 + extra_size * 8 / 5 + 8];
  char *end;
  PGresult *result;

  end = stpcpy (sql,
                "NOTIFY ");
  end = es_to_channel (es,
                       end);
  end = stpcpy (end,
                ", '");
  end = GNUNET_STRINGS_data_to_string (extra,
                                       extra_size,
                                       end,
                                       sizeof (sql) - (end - sql) - 1);
  GNUNET_assert (NULL != end);
  *end = '\0';
  end = stpcpy (end,
                "'");
  result = PQexec (db->conn,
                   sql);
  if (PGRES_COMMAND_OK != PQresultStatus (result))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                     "pq",
                     "Failed to execute `%s': %s/%s/%s/%s/%s",
                     sql,
                     PQresultErrorField (result,
                                         PG_DIAG_MESSAGE_PRIMARY),
                     PQresultErrorField (result,
                                         PG_DIAG_MESSAGE_DETAIL),
                     PQresultErrorMessage (result),
                     PQresStatus (PQresultStatus (result)),
                     PQerrorMessage (db->conn));
  }
  PQclear (result);
}


/* end of pq_event.c */
