/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2014, 2017, 2018 GNUnet e.V.

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
 * @file zonemaster/gnunet-service-zonemaster-monitor.c
 * @brief monitor namestore changes and publish them immediately to GNUnet name system
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_statistics_service.h"


#define LOG_STRERROR_FILE(kind, syscall, \
                          filename) GNUNET_log_from_strerror_file (kind, "util", \
                                                                   syscall, \
                                                                   filename)


/**
 * How often should we (re)publish each record before
 * it expires?
 */
#define PUBLISH_OPS_PER_EXPIRATION 4

/**
 * How many pending DHT operations do we allow at most?
 */
#define DHT_QUEUE_LIMIT 2000

/**
 * How many events may the namestore give us before it has to wait
 * for us to keep up?
 */
#define NAMESTORE_QUEUE_LIMIT 5

/**
 * What replication level do we use for DHT PUT operations?
 */
#define DHT_GNS_REPLICATION_LEVEL 5

/**
 * Handle for tombston updates which are executed for each published
 * record set.
 */
struct TombstoneActivity
{
  /**
   * Kept in a DLL.
   */
  struct TombstoneActivity *next;

  /**
   * Kept in a DLL.
   */
  struct TombstoneActivity *prev;

  /**
   * Handle for the store operation.
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

};


/**
 * Handle for DHT PUT activity triggered from the namestore monitor.
 */
struct DhtPutActivity
{
  /**
   * Kept in a DLL.
   */
  struct DhtPutActivity *next;

  /**
   * Kept in a DLL.
   */
  struct DhtPutActivity *prev;

  /**
   * Handle for the DHT PUT operation.
   */
  struct GNUNET_DHT_PutHandle *ph;

  /**
   * When was this PUT initiated?
   */
  struct GNUNET_TIME_Absolute start_date;
};


/**
 * Handle to the statistics service
 */
static struct GNUNET_STATISTICS_Handle *statistics;

/**
 * Our handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Our handle to the namestore service
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Handle to monitor namestore changes to instant propagation.
 */
static struct GNUNET_NAMESTORE_ZoneMonitor *zmon;

/**
 * Head of the tombstone operations
 */
static struct TombstoneActivity *ta_head;

/**
 * Tail of the tombstone operations
 */
static struct TombstoneActivity *ta_tail;


/**
 * Head of monitor activities; kept in a DLL.
 */
static struct DhtPutActivity *ma_head;

/**
 * Tail of monitor activities; kept in a DLL.
 */
static struct DhtPutActivity *ma_tail;

/**
 * Number of entries in the DHT queue #ma_head.
 */
static unsigned int ma_queue_length;

/**
 * Optimize block insertion by caching map of private keys to
 * public keys in memory?
 */
static int cache_keys;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls)
{
  struct DhtPutActivity *ma;
  struct TombstoneActivity *ta;

  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down!\n");
  while (NULL != (ma = ma_head))
  {
    GNUNET_DHT_put_cancel (ma->ph);
    ma_queue_length--;
    GNUNET_CONTAINER_DLL_remove (ma_head,
                                 ma_tail,
                                 ma);
    GNUNET_free (ma);
  }
  while (NULL != (ta = ta_head))
  {
    GNUNET_NAMESTORE_cancel (ta->ns_qe);
    GNUNET_CONTAINER_DLL_remove (ta_head,
                                 ta_tail,
                                 ta);
    GNUNET_free (ta);
  }
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics,
                               GNUNET_NO);
    statistics = NULL;
  }
  if (NULL != zmon)
  {
    GNUNET_NAMESTORE_zone_monitor_stop (zmon);
    zmon = NULL;
  }
  if (NULL != namestore_handle)
  {
    GNUNET_NAMESTORE_disconnect (namestore_handle);
    namestore_handle = NULL;
  }
  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
}


/**
 * Continuation called from DHT once the PUT operation triggered
 * by a monitor is done.
 *
 * @param cls a `struct DhtPutActivity`
 */
static void
dht_put_monitor_continuation (void *cls)
{
  struct DhtPutActivity *ma = cls;

  GNUNET_NAMESTORE_zone_monitor_next (zmon,
                                      1);
  ma_queue_length--;
  GNUNET_CONTAINER_DLL_remove (ma_head,
                               ma_tail,
                               ma);
  GNUNET_free (ma);
}


/**
 * Convert namestore records from the internal format to that
 * suitable for publication (removes private records, converts
 * to absolute expiration time).
 *
 * @param rd input records
 * @param rd_count size of the @a rd and @a rd_public arrays
 * @param rd_public where to write the converted records
 * @return number of records written to @a rd_public
 */
static unsigned int
convert_records_for_export (const struct GNUNET_GNSRECORD_Data *rd,
                            unsigned int rd_count,
                            struct GNUNET_GNSRECORD_Data *rd_public,
                            struct GNUNET_TIME_Absolute *expiry)
{
  const struct GNUNET_GNSRECORD_TombstoneRecord *tombstone;
  struct GNUNET_TIME_Absolute expiry_tombstone;
  struct GNUNET_TIME_Absolute now;
  unsigned int rd_public_count;

  rd_public_count = 0;
  tombstone = NULL;
  now = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < rd_count; i++)
  {
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE))
      continue;
    if (GNUNET_GNSRECORD_TYPE_TOMBSTONE == rd[i].record_type)
    {
      tombstone = rd[i].data;
      continue;
    }
    if ((0 == (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION)) &&
        (rd[i].expiration_time < now.abs_value_us))
      continue;   /* record already expired, skip it */
    rd_public[rd_public_count] = rd[i];
    /* Make sure critical record types are published as such */
    if (GNUNET_YES == GNUNET_GNSRECORD_is_critical (rd[i].record_type))
      rd_public[rd_public_count].flags |= GNUNET_GNSRECORD_RF_CRITICAL;
    rd_public_count++;
  }

  *expiry = GNUNET_GNSRECORD_record_get_expiration_time (rd_public_count,
                                                         rd_public);

  /* We need to check if the tombstone has an expiration in the fututre
   * which would mean there was a block published under this label
   * previously that is still valid. In this case we MUST NOT publish this
   * block
   */
  if (NULL != tombstone)
  {
    expiry_tombstone = GNUNET_TIME_absolute_ntoh (tombstone->time_of_death);
    if (GNUNET_TIME_absolute_cmp (*expiry,<=,expiry_tombstone))
      return 0;
  }

  return rd_public_count;
}


/**
 * Store GNS records in the DHT.
 *
 * @param key key of the zone
 * @param label label to store under
 * @param rd_public public record data
 * @param rd_public_count number of records in @a rd_public
 * @param ma handle for the PUT operation
 * @return DHT PUT handle, NULL on error
 */
static struct GNUNET_DHT_PutHandle *
perform_dht_put (const struct GNUNET_IDENTITY_PrivateKey *key,
                 const char *label,
                 const struct GNUNET_GNSRECORD_Data *rd_public,
                 unsigned int rd_public_count,
                 struct GNUNET_TIME_Absolute expire,
                 struct DhtPutActivity *ma)
{
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_HashCode query;
  size_t block_size;
  struct GNUNET_DHT_PutHandle *ret;

  if (cache_keys)
    GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_create2 (key,
                                                                expire,
                                                                label,
                                                                rd_public,
                                                                rd_public_count,
                                                                &block));
  else
    GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_create (key,
                                                               expire,
                                                               label,
                                                               rd_public,
                                                               rd_public_count,
                                                               &block));
  if (NULL == block)
  {
    GNUNET_break (0);
    return NULL;   /* whoops */
  }
  block_size = GNUNET_GNSRECORD_block_get_size (block);
  GNUNET_GNSRECORD_query_from_private_key (key,
                                           label,
                                           &query);
  GNUNET_STATISTICS_update (statistics,
                            "DHT put operations initiated",
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Storing %u record(s) for label `%s' in DHT with expiration `%s' under key %s\n",
              rd_public_count,
              label,
              GNUNET_STRINGS_absolute_time_to_string (expire),
              GNUNET_h2s (&query));
  ret = GNUNET_DHT_put (dht_handle,
                        &query,
                        DHT_GNS_REPLICATION_LEVEL,
                        GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                        GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                        block_size,
                        block,
                        expire,
                        &dht_put_monitor_continuation,
                        ma);
  GNUNET_free (block);
  return ret;
}

static void
ts_store_cont (void *cls, int32_t success, const char *emsg)
{
  struct TombstoneActivity *ta = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tombstone update complete\n");
  GNUNET_CONTAINER_DLL_remove (ta_head,
                               ta_tail,
                               ta);
  GNUNET_free (ta);

}


/**
 * Update tombstone records.
 *
 * @param key key of the zone
 * @param label label to store under
 * @param rd_public public record data
 * @param rd_public_count number of records in @a rd_public
 * @param expire the expiration time for the tombstone
 * @param ta handle for the put operation
 * @return Namestore queue entry, NULL on error
 */
static struct GNUNET_NAMESTORE_QueueEntry *
touch_tombstone (const struct GNUNET_IDENTITY_PrivateKey *key,
                 const char *label,
                 const struct GNUNET_GNSRECORD_Data *rd_original,
                 unsigned int rd_count_original,
                 const struct GNUNET_TIME_Absolute expire,
                 struct TombstoneActivity *ta)
{
  struct GNUNET_TIME_AbsoluteNBO exp_nbo;
  struct GNUNET_GNSRECORD_Data rd[rd_count_original + 1];
  int tombstone_exists = GNUNET_NO;
  unsigned int rd_count;

  exp_nbo = GNUNET_TIME_absolute_hton (expire);
  for (rd_count = 0; rd_count < rd_count_original; rd_count++)
  {
    memcpy (&rd[rd_count], &rd_original[rd_count],
            sizeof (struct GNUNET_GNSRECORD_Data));
    if (GNUNET_GNSRECORD_TYPE_TOMBSTONE == rd[rd_count].record_type)
    {
      rd[rd_count].data = &exp_nbo;
      tombstone_exists = GNUNET_YES;
    }
  }
  if (GNUNET_NO == tombstone_exists)
  {
    rd[rd_count].data = &exp_nbo;
    rd[rd_count].data_size = sizeof (exp_nbo);
    rd[rd_count].record_type = GNUNET_GNSRECORD_TYPE_TOMBSTONE;
    rd[rd_count].flags = GNUNET_GNSRECORD_RF_PRIVATE;
    rd[rd_count].expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
    rd_count++;
  }
  return GNUNET_NAMESTORE_records_store_ (namestore_handle,
                                                key,
                                                label,
                                                rd_count,
                                                rd,
                                                GNUNET_YES,
                                                &ts_store_cont,
                                                ta);
}



/**
 * Process a record that was stored in the namestore
 * (invoked by the monitor).
 *
 * @param cls closure, NULL
 * @param zone private key of the zone; NULL on disconnect
 * @param label label of the records; NULL on disconnect
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
static void
handle_monitor_event (void *cls,
                      const struct GNUNET_IDENTITY_PrivateKey *zone,
                      const char *label,
                      unsigned int rd_count,
                      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rd_public[rd_count];
  unsigned int rd_public_count;
  struct DhtPutActivity *ma;
  struct TombstoneActivity *ta;
  struct GNUNET_TIME_Absolute expire;

  (void) cls;
  GNUNET_STATISTICS_update (statistics,
                            "Namestore monitor events received",
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u records for label `%s' via namestore monitor\n",
              rd_count,
              label);
  /* filter out records that are not public, and convert to
     absolute expiration time. */
  rd_public_count = convert_records_for_export (rd,
                                                rd_count,
                                                rd_public,
                                                &expire);
  if (0 == rd_public_count)
  {
    GNUNET_NAMESTORE_zone_monitor_next (zmon,
                                        1);
    return;   /* nothing to do */
  }
  ma = GNUNET_new (struct DhtPutActivity);
  ma->start_date = GNUNET_TIME_absolute_get ();
  ma->ph = perform_dht_put (zone,
                            label,
                            rd,
                            rd_count,
                            expire,
                            ma);
  ta = GNUNET_new (struct TombstoneActivity);
  ta->ns_qe = touch_tombstone (zone,
                               label,
                               rd,
                               rd_count,
                               expire,
                               ta);
  GNUNET_CONTAINER_DLL_insert_tail (ta_head,
                                    ta_tail,
                                    ta);
  if (NULL == ma->ph)
  {
    /* PUT failed, do not remember operation */
    GNUNET_free (ma);
    GNUNET_NAMESTORE_zone_monitor_next (zmon,
                                        1);
    return;
  }
  GNUNET_CONTAINER_DLL_insert_tail (ma_head,
                                    ma_tail,
                                    ma);
  ma_queue_length++;
  if (ma_queue_length > DHT_QUEUE_LIMIT)
  {
    ma = ma_head;
    GNUNET_CONTAINER_DLL_remove (ma_head,
                                 ma_tail,
                                 ma);
    GNUNET_DHT_put_cancel (ma->ph);
    ma_queue_length--;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "DHT PUT unconfirmed after %s, aborting PUT\n",
                GNUNET_STRINGS_relative_time_to_string (
                  GNUNET_TIME_absolute_get_duration (ma->start_date),
                  GNUNET_YES));
    GNUNET_free (ma);
  }
}


/**
 * The zone monitor encountered an IPC error trying to to get in
 * sync. Restart from the beginning.
 *
 * @param cls NULL
 */
static void
handle_monitor_error (void *cls)
{
  (void) cls;
  GNUNET_STATISTICS_update (statistics,
                            "Namestore monitor errors encountered",
                            1,
                            GNUNET_NO);
}


/**
 * Perform zonemaster duties: watch namestore, publish records.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  unsigned long long max_parallel_bg_queries = 128;

  (void) cls;
  (void) service;
  namestore_handle = GNUNET_NAMESTORE_connect (c);
  if (NULL == namestore_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to the namestore!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  cache_keys = GNUNET_CONFIGURATION_get_value_yesno (c,
                                                     "namestore",
                                                     "CACHE_KEYS");
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (c,
                                             "zonemaster",
                                             "MAX_PARALLEL_BACKGROUND_QUERIES",
                                             &max_parallel_bg_queries))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Number of allowed parallel background queries: %llu\n",
                max_parallel_bg_queries);
  }
  if (0 == max_parallel_bg_queries)
    max_parallel_bg_queries = 1;
  dht_handle = GNUNET_DHT_connect (c,
                                   (unsigned int) max_parallel_bg_queries);
  if (NULL == dht_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not connect to DHT!\n"));
    GNUNET_SCHEDULER_add_now (&shutdown_task,
                              NULL);
    return;
  }

  /* Schedule periodic put for our records. */
  statistics = GNUNET_STATISTICS_create ("zonemaster-mon",
                                         c);
  zmon = GNUNET_NAMESTORE_zone_monitor_start (c,
                                              NULL,
                                              GNUNET_NO,
                                              &handle_monitor_error,
                                              NULL,
                                              &handle_monitor_event,
                                              NULL,
                                              NULL /* sync_cb */,
                                              NULL);
  GNUNET_NAMESTORE_zone_monitor_next (zmon,
                                      NAMESTORE_QUEUE_LIMIT - 1);
  GNUNET_break (NULL != zmon);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
  ("zonemaster-monitor",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  NULL,
  NULL,
  NULL,
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-zonemaster-monitor.c */
