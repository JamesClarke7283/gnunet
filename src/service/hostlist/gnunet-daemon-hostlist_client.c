/*
     This file is part of GNUnet.
     Copyright (C) 2001-2010, 2014, 2016 GNUnet e.V.

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
 * @file hostlist/gnunet-daemon-hostlist_client.c
 * @brief hostlist support.  Downloads HELLOs via HTTP.
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet-daemon-hostlist_client.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_peerstore_service.h"
#include "gnunet-daemon-hostlist.h"
/* Just included for the right curl.h */
#include "gnunet_curl_lib.h"


/**
 * Number of connections that we must have to NOT download
 * hostlists anymore.
 */
#define MIN_CONNECTIONS 4

/**
 * Maximum number of hostlist that are saved
 */
#define MAX_NUMBER_HOSTLISTS 30

/**
 * Time interval hostlists are saved to disk
 */
#define SAVING_INTERVAL \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

/**
 * Time interval between two hostlist tests
 */
#define TESTING_INTERVAL \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)

/**
 * Time interval for download dispatcher before a download is re-scheduled
 */
#define WAITING_INTERVAL \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Defines concerning the hostlist quality metric
 */

/**
 * Initial quality of a new created hostlist
 */
#define HOSTLIST_INITIAL 10000

/**
 * Value subtracted each time a hostlist download fails
 */
#define HOSTLIST_FAILED_DOWNLOAD 100

/**
 * Value added each time a hostlist download is successful
 */
#define HOSTLIST_SUCCESSFUL_DOWNLOAD 100

/**
 * Value added for each valid HELLO received during a hostlist download
 */
#define HOSTLIST_SUCCESSFUL_HELLO 1


/**
 * A single hostlist obtained by hostlist advertisements
 */
struct Hostlist
{
  /**
   * previous entry, used to manage entries in a double linked list
   */
  struct Hostlist *prev;

  /**
   * next entry, used to manage entries in a double linked list
   */
  struct Hostlist *next;

  /**
   * URI where hostlist can be obtained
   */
  const char *hostlist_uri;

  /**
   * Value describing the quality of the hostlist, the bigger the better but (should) never < 0
   * used for deciding which hostlist is replaced if MAX_NUMBER_HOSTLISTS in data structure is reached
   * initial value = HOSTLIST_INITIAL
   * increased every successful download by HOSTLIST_SUCCESSFULL_DOWNLOAD
   * increased every successful download by number of obtained HELLO messages
   * decreased every failed download by HOSTLIST_SUCCESSFULL_DOWNLOAD
   */
  uint64_t quality;

  /**
   * Time the hostlist advertisement was received and the entry was created
   */
  struct GNUNET_TIME_Absolute time_creation;

  /**
   * Last time the hostlist was obtained
   */
  struct GNUNET_TIME_Absolute time_last_usage;

  /**
   * Number of HELLO messages obtained during last download
   */
  uint32_t hello_count;

  /**
   * Number of times the hostlist was successfully obtained
   */
  uint32_t times_used;
};

/**
* Context for a add hello uri request.
*/
struct StoreHelloEntry
{
  /**
   * Kept (also) in a DLL.
   */
  struct StoreHelloEntry *prev;

  /**
   * Kept (also) in a DLL.
   */
  struct StoreHelloEntry *next;

  /**
   * Store hello ctx
   */
  struct GNUNET_PEERSTORE_StoreHelloContext *sc;
};

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Statistics handle.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Proxy hostname or ip we are using (can be NULL).
 */
static char *proxy;

/**
 * Proxy username we are using (can be NULL).
 */
static char *proxy_username;

/**
 * Proxy password we are using (can be NULL).
 */
static char *proxy_password;

/**
 * Proxy type we are using (can be NULL).
 */
static curl_proxytype proxy_type;

/**
 * Number of bytes valid in 'download_buffer'.
 */
static size_t download_pos;

/**
 * Current URL that we are using.
 */
static char *current_url;

/**
 * Current CURL handle.
 */
static CURL *curl;

/**
 * Current multi-CURL handle.
 */
static CURLM *multi;

/**
 * How many bytes did we download from the current hostlist URL?
 */
static uint32_t stat_bytes_downloaded;

/**
 * Amount of time we wait between hostlist downloads.
 */
static struct GNUNET_TIME_Relative hostlist_delay;

/**
 * ID of the task, checking if hostlist download should take plate
 */
static struct GNUNET_SCHEDULER_Task *ti_check_download;

/**
 * ID of the task downloading the hostlist
 */
static struct GNUNET_SCHEDULER_Task *ti_download;

/**
 * ID of the task saving the hostlsit in a regular interval
 */
static struct GNUNET_SCHEDULER_Task *ti_saving_task;

/**
 * ID of the task called to initiate a download
 */
static struct GNUNET_SCHEDULER_Task *ti_download_dispatcher_task;

/**
 * ID of the task controlling the locking between two hostlist tests
 */
static struct GNUNET_SCHEDULER_Task *ti_testing_intervall_task;

/**
 * At what time MUST the current hostlist request be done?
 */
static struct GNUNET_TIME_Absolute end_time;

/**
 * Head of the linkd list to store the store context for hellos.
 */
static struct StoreHelloEntry *she_head;

/**
 * Tail of the linkd list to store the store context for hellos.
 */
static struct StoreHelloEntry *she_tail;

/**
 * Head of the linked list used to store hostlists
 */
static struct Hostlist *linked_list_head;

/**
 *  Tail of the linked list used to store hostlists
 */
static struct Hostlist *linked_list_tail;

/**
 *  Current hostlist used for downloading
 */
static struct Hostlist *current_hostlist;

/**
 *  Size of the linked list  used to store hostlists
 */
static unsigned int linked_list_size;

/**
 * Head of the linked list used to store hostlists
 */
static struct Hostlist *hostlist_to_test;

/**
 * Handle for our statistics GET operation.
 */
static struct GNUNET_STATISTICS_GetHandle *sget;

/**
 * Set to GNUNET_YES if the current URL had some problems.
 */
static int stat_bogus_url;

/**
 * Value controlling if a hostlist is tested at the moment
 */
static int stat_testing_hostlist;

/**
 * Value controlling if a hostlist testing is allowed at the moment
 */
static int stat_testing_allowed;

/**
 * Value controlling if a hostlist download is running at the moment
 */
static int stat_download_in_progress;

/**
 * Value saying if a preconfigured bootstrap server is used
 */
static unsigned int stat_use_bootstrap;

/**
 * Set if we are allowed to learn new hostlists and use them
 */
static int stat_learning;

/**
 * Value saying if hostlist download was successful
 */
static unsigned int stat_download_successful;

/**
 * Value saying how many valid HELLO messages were obtained during download
 */
static unsigned int stat_hellos_obtained;

/**
 * Number of active connections (according to core service).
 */
static unsigned int stat_connection_count;

/**
 * Handle to the PEERSTORE service.
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;


static void
shc_cont (void *cls, int success)
{
  struct StoreHelloEntry *she =  cls;

  she->sc = NULL;
  if (GNUNET_YES == success)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Hostlist entry stored successfully!\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Error storing hostlist entry!\n");
  GNUNET_CONTAINER_DLL_remove (she_head, she_tail, she);
  GNUNET_free (she);
}


/**
 * Process downloaded bits by calling callback on each HELLO.
 *
 * @param ptr buffer with downloaded data
 * @param size size of a record
 * @param nmemb number of records downloaded
 * @param ctx unused
 * @return number of bytes that were processed (always size*nmemb)
 */
static size_t
callback_download (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  static char download_buffer[GNUNET_MAX_MESSAGE_SIZE - 1];
  struct StoreHelloEntry *she;
  const char *cbuf = ptr;
  const struct GNUNET_MessageHeader *msg;
  size_t total;
  size_t cpy;
  size_t left;
  uint16_t msize;

  total = size * nmemb;
  stat_bytes_downloaded += total;
  if ((total == 0) || (stat_bogus_url))
  {
    return total;   /* ok, no data or bogus data */
  }

  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# bytes downloaded from hostlist servers"),
                            (int64_t) total,
                            GNUNET_NO);
  left = total;
  while ((left > 0) || (download_pos > 0))
  {
    cpy = GNUNET_MIN (left, GNUNET_MAX_MESSAGE_SIZE - 1 - download_pos);
    GNUNET_memcpy (&download_buffer[download_pos], cbuf, cpy);
    cbuf += cpy;
    download_pos += cpy;
    left -= cpy;
    if (download_pos < sizeof(struct GNUNET_MessageHeader))
    {
      GNUNET_assert (0 == left);
      break;
    }
    msg = (const struct GNUNET_MessageHeader *) download_buffer;
    msize = ntohs (msg->size);
    if (msize < sizeof(struct GNUNET_MessageHeader))
    {
      GNUNET_STATISTICS_update (
        stats,
        gettext_noop ("# invalid HELLOs downloaded from hostlist servers"),
        1,
        GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _ ("Invalid `%s' message received from hostlist at `%s'\n"),
                  "HELLO",
                  current_url);
      stat_hellos_obtained++;
      stat_bogus_url = 1;
      return total;
    }
    if (download_pos < msize)
    {
      GNUNET_assert (left == 0);
      break;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received valid `%s' message from hostlist server.\n",
                "HELLO");
    GNUNET_STATISTICS_update (
      stats,
      gettext_noop ("# valid HELLOs downloaded from hostlist servers"),
      1,
      GNUNET_NO);
    stat_hellos_obtained++;
    she = GNUNET_new (struct StoreHelloEntry);
    she->sc = GNUNET_PEERSTORE_hello_add (peerstore,
                                          msg,
                                          shc_cont,
                                          she);
    if (NULL != she->sc)
    {
      GNUNET_CONTAINER_DLL_insert (she_head, she_tail, she);
    }
    else
      GNUNET_free (she);
    memmove (download_buffer, &download_buffer[msize], download_pos - msize);
    download_pos -= msize;
  }
  return total;
}


/**
 * Obtain a hostlist URL that we should use.
 *
 * @return NULL if there is no URL available
 */
static char *
get_bootstrap_server ()
{
  char *servers;
  char *ret;
  size_t urls;
  size_t pos;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "HOSTLIST",
                                                          "SERVERS",
                                                          &servers))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_WARNING,
                               "hostlist",
                               "SERVERS");
    return NULL;
  }

  urls = 0;
  if (strlen (servers) > 0)
  {
    urls++;
    pos = strlen (servers) - 1;
    while (pos > 0)
    {
      if (servers[pos] == ' ')
        urls++;
      pos--;
    }
  }
  if (urls == 0)
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_WARNING,
                               "hostlist",
                               "SERVERS");
    GNUNET_free (servers);
    return NULL;
  }

  urls = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, urls) + 1;
  pos = strlen (servers) - 1;
  while (pos > 0)
  {
    if (servers[pos] == ' ')
    {
      urls--;
      servers[pos] = '\0';
    }
    if (urls == 0)
    {
      pos++;
      break;
    }
    pos--;
  }
  ret = GNUNET_strdup (&servers[pos]);
  GNUNET_free (servers);
  return ret;
}


/**
 * Method deciding if a preconfigured or advertisied hostlist is used on a 50:50 ratio
 * @return uri to use, NULL if there is no URL available
 */
static char *
download_get_url ()
{
  uint32_t index;
  unsigned int counter;
  struct Hostlist *pos;

  if (GNUNET_NO == stat_learning)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Using preconfigured bootstrap server\n");
    current_hostlist = NULL;
    return get_bootstrap_server ();
  }

  if ((GNUNET_YES == stat_testing_hostlist) && (NULL != hostlist_to_test))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Testing new advertised hostlist if it is obtainable\n");
    current_hostlist = hostlist_to_test;
    return GNUNET_strdup (hostlist_to_test->hostlist_uri);
  }

  if ((GNUNET_YES == stat_use_bootstrap) || (linked_list_size == 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Using preconfigured bootstrap server\n");
    current_hostlist = NULL;
    return get_bootstrap_server ();
  }
  index =
    GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, linked_list_size);
  counter = 0;
  pos = linked_list_head;
  while (counter < index)
  {
    pos = pos->next;
    counter++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Using learned hostlist `%s'\n",
              pos->hostlist_uri);
  current_hostlist = pos;
  return GNUNET_strdup (pos->hostlist_uri);
}


#define CURL_EASY_SETOPT(c, a, b)                   \
        do                                                \
        {                                                 \
          ret = curl_easy_setopt (c, a, b);               \
          if (CURLE_OK != ret)                            \
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,        \
                      _ ("%s failed at %s:%d: `%s'\n"), \
                      "curl_easy_setopt",               \
                      __FILE__,                         \
                      __LINE__,                         \
                      curl_easy_strerror (ret));        \
        } while (0)


/**
 * Method to save hostlist to a file during hostlist client shutdown
 *
 * @param shutdown set if called because of shutdown, entries in linked list will be destroyed
 */
static void
save_hostlist_file (int shutdown);


/**
 * Add val2 to val1 with overflow check
 *
 * @param val1 value 1
 * @param val2 value 2
 * @return result
 */
static uint64_t
checked_add (uint64_t val1, uint64_t val2)
{
  static uint64_t temp;
  static uint64_t maxv;

  maxv = 0;
  maxv--;

  temp = val1 + val2;
  if (temp < val1)
    return maxv;
  return temp;
}


/**
 * Subtract val2 from val1 with underflow check
 *
 * @param val1 value 1
 * @param val2 value 2
 * @return result
 */
static uint64_t
checked_sub (uint64_t val1, uint64_t val2)
{
  if (val1 <= val2)
    return 0;
  return(val1 - val2);
}


/**
 * Method to check if  a URI is in hostlist linked list
 *
 * @param uri uri to check
 * @return #GNUNET_YES if existing in linked list, #GNUNET_NO if not
 */
static int
linked_list_contains (const char *uri)
{
  struct Hostlist *pos;

  pos = linked_list_head;
  while (pos != NULL)
  {
    if (0 == strcmp (pos->hostlist_uri, uri))
      return GNUNET_YES;
    pos = pos->next;
  }
  return GNUNET_NO;
}


/**
 * Method returning the hostlist element with the lowest quality in the datastore
 * @return hostlist with lowest quality
 */
static struct Hostlist *
linked_list_get_lowest_quality ()
{
  struct Hostlist *pos;
  struct Hostlist *lowest;

  if (linked_list_size == 0)
    return NULL;
  lowest = linked_list_head;
  pos = linked_list_head->next;
  while (pos != NULL)
  {
    if (pos->quality < lowest->quality)
      lowest = pos;
    pos = pos->next;
  }
  return lowest;
}


/**
 * Method to insert a hostlist into the datastore. If datastore
 * contains maximum number of elements, the elements with lowest
 * quality is dismissed
 */
static void
insert_hostlist ()
{
  struct Hostlist *lowest_quality;

  if (MAX_NUMBER_HOSTLISTS <= linked_list_size)
  {
    /* No free entries available, replace existing entry  */
    lowest_quality = linked_list_get_lowest_quality ();
    GNUNET_assert (lowest_quality != NULL);
    GNUNET_log (
      GNUNET_ERROR_TYPE_DEBUG,
      "Removing hostlist with URI `%s' which has the worst quality of all (%llu)\n",
      lowest_quality->hostlist_uri,
      (unsigned long long) lowest_quality->quality);
    GNUNET_CONTAINER_DLL_remove (linked_list_head,
                                 linked_list_tail,
                                 lowest_quality);
    linked_list_size--;
    GNUNET_free (lowest_quality);
  }
  GNUNET_CONTAINER_DLL_insert (linked_list_head,
                               linked_list_tail,
                               hostlist_to_test);
  linked_list_size++;
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# advertised hostlist URIs"),
                         linked_list_size,
                         GNUNET_NO);
  stat_testing_hostlist = GNUNET_NO;
}


/**
 * Method updating hostlist statistics
 */
static void
update_hostlist ()
{
  char *stat;

  if (((stat_use_bootstrap == GNUNET_NO) && (NULL != current_hostlist)) ||
      ((stat_testing_hostlist == GNUNET_YES) && (NULL != current_hostlist)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Updating hostlist statistics for URI `%s'\n",
                current_hostlist->hostlist_uri);
    current_hostlist->hello_count = stat_hellos_obtained;
    current_hostlist->time_last_usage = GNUNET_TIME_absolute_get ();
    current_hostlist->quality =
      checked_add (current_hostlist->quality,
                   (stat_hellos_obtained * HOSTLIST_SUCCESSFUL_HELLO));
    if (GNUNET_YES == stat_download_successful)
    {
      current_hostlist->times_used++;
      current_hostlist->quality =
        checked_add (current_hostlist->quality, HOSTLIST_SUCCESSFUL_DOWNLOAD);
      GNUNET_asprintf (&stat,
                       gettext_noop ("# advertised URI `%s' downloaded"),
                       current_hostlist->hostlist_uri);

      GNUNET_STATISTICS_update (stats, stat, 1, GNUNET_YES);
      GNUNET_free (stat);
    }
    else
      current_hostlist->quality =
        checked_sub (current_hostlist->quality, HOSTLIST_FAILED_DOWNLOAD);
  }
  current_hostlist = NULL;
  /* Alternating the usage of preconfigured and learned hostlists */

  if (stat_testing_hostlist == GNUNET_YES)
    return;

  if (GNUNET_YES == stat_learning)
  {
    if (stat_use_bootstrap == GNUNET_YES)
      stat_use_bootstrap = GNUNET_NO;
    else
      stat_use_bootstrap = GNUNET_YES;
  }
  else
    stat_use_bootstrap = GNUNET_YES;
}


/**
 * Clean up the state from the task that downloaded the
 * hostlist and schedule the next task.
 */
static void
clean_up ()
{
  CURLMcode mret;

  if ((stat_testing_hostlist == GNUNET_YES) &&
      (GNUNET_NO == stat_download_successful) && (NULL != hostlist_to_test))
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_INFO,
      _ (
        "Advertised hostlist with URI `%s' could not be downloaded. Advertised URI gets dismissed.\n"),
      hostlist_to_test->hostlist_uri);
  }

  if (stat_testing_hostlist == GNUNET_YES)
  {
    stat_testing_hostlist = GNUNET_NO;
  }
  if (NULL != hostlist_to_test)
  {
    GNUNET_free (hostlist_to_test);
    hostlist_to_test = NULL;
  }

  if (NULL != multi)
  {
    mret = curl_multi_remove_handle (multi, curl);
    if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_remove_handle",
                  __FILE__,
                  __LINE__,
                  curl_multi_strerror (mret));
    }
    mret = curl_multi_cleanup (multi);
    if (mret != CURLM_OK)
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_cleanup",
                  __FILE__,
                  __LINE__,
                  curl_multi_strerror (mret));
    multi = NULL;
  }
  if (NULL != curl)
  {
    curl_easy_cleanup (curl);
    curl = NULL;
  }
  GNUNET_free (current_url);
  current_url = NULL;
  stat_bytes_downloaded = 0;
  stat_download_in_progress = GNUNET_NO;
}


/**
 * Task that is run when we are ready to receive more data from the hostlist
 * server.
 *
 * @param cls closure, unused
 */
static void
task_download (void *cls);


/**
 * Ask CURL for the select set and then schedule the
 * receiving task with the scheduler.
 */
static void
download_prepare ()
{
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  long timeout;
  struct GNUNET_TIME_Relative rtime;

  max = -1;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  mret = curl_multi_fdset (multi, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("%s failed at %s:%d: `%s'\n"),
                "curl_multi_fdset",
                __FILE__,
                __LINE__,
                curl_multi_strerror (mret));
    clean_up ();
    return;
  }
  mret = curl_multi_timeout (multi, &timeout);
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("%s failed at %s:%d: `%s'\n"),
                "curl_multi_timeout",
                __FILE__,
                __LINE__,
                curl_multi_strerror (mret));
    clean_up ();
    return;
  }
  rtime = GNUNET_TIME_relative_min (
    GNUNET_TIME_absolute_get_remaining (end_time),
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, timeout));
  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling task for hostlist download using cURL\n");
  ti_download = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                             rtime,
                                             grs,
                                             gws,
                                             &task_download,
                                             multi);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
}


static void
task_download (void *cls)
{
  int running;
  struct CURLMsg *msg;
  CURLMcode mret;

  ti_download = NULL;
  if (0 == GNUNET_TIME_absolute_get_remaining (end_time).rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Timeout trying to download hostlist from `%s'\n"),
                current_url);
    update_hostlist ();
    clean_up ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ready for processing hostlist client request\n");
  do
  {
    running = 0;
    if (stat_bytes_downloaded > MAX_BYTES_PER_HOSTLISTS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _ (
                    "Download limit of %u bytes exceeded, stopping download\n"),
                  MAX_BYTES_PER_HOSTLISTS);
      clean_up ();
      return;
    }
    mret = curl_multi_perform (multi, &running);
    if (running == 0)
    {
      do
      {
        msg = curl_multi_info_read (multi, &running);
        GNUNET_break (msg != NULL);
        if (msg == NULL)
          break;
        switch (msg->msg)
        {
        case CURLMSG_DONE:
          if ((msg->data.result != CURLE_OK) &&
              (msg->data.result != CURLE_GOT_NOTHING))
            GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                        _ ("Download of hostlist from `%s' failed: `%s'\n"),
                        current_url,
                        curl_easy_strerror (msg->data.result));
          else
          {
            GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                        _ ("Download of hostlist `%s' completed.\n"),
                        current_url);
            stat_download_successful = GNUNET_YES;
            update_hostlist ();
            if (GNUNET_YES == stat_testing_hostlist)
            {
              GNUNET_log (
                GNUNET_ERROR_TYPE_INFO,
                _ ("Adding successfully tested hostlist `%s' datastore.\n"),
                current_url);
              insert_hostlist ();
              hostlist_to_test = NULL;
              stat_testing_hostlist = GNUNET_NO;
            }
          }
          clean_up ();
          return;

        default:
          break;
        }
      }
      while ((running > 0));
    }
  }
  while (mret == CURLM_CALL_MULTI_PERFORM);

  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("%s failed at %s:%d: `%s'\n"),
                "curl_multi_perform",
                __FILE__,
                __LINE__,
                curl_multi_strerror (mret));
    clean_up ();
  }
  download_prepare ();
}


/**
 * Main function that will download a hostlist and process its
 * data.
 */
static void
download_hostlist ()
{
  CURLcode ret;
  CURLMcode mret;


  current_url = download_get_url ();
  if (current_url == NULL)
    return;
  curl = curl_easy_init ();
  multi = NULL;
  if (curl == NULL)
  {
    GNUNET_break (0);
    clean_up ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
              _ ("Bootstrapping using hostlist at `%s'.\n"),
              current_url);

  stat_download_in_progress = GNUNET_YES;
  stat_download_successful = GNUNET_NO;
  stat_hellos_obtained = 0;
  stat_bytes_downloaded = 0;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# hostlist downloads initiated"),
                            1,
                            GNUNET_NO);
  if (NULL != proxy)
  {
    CURL_EASY_SETOPT (curl, CURLOPT_PROXY, proxy);
    CURL_EASY_SETOPT (curl, CURLOPT_PROXYTYPE, proxy_type);
    if (NULL != proxy_username)
      CURL_EASY_SETOPT (curl, CURLOPT_PROXYUSERNAME, proxy_username);
    if (NULL != proxy_password)
      CURL_EASY_SETOPT (curl, CURLOPT_PROXYPASSWORD, proxy_password);
  }
  download_pos = 0;
  stat_bogus_url = 0;
  CURL_EASY_SETOPT (curl, CURLOPT_WRITEFUNCTION, &callback_download);
  if (ret != CURLE_OK)
  {
    clean_up ();
    return;
  }
  CURL_EASY_SETOPT (curl, CURLOPT_WRITEDATA, NULL);
  if (ret != CURLE_OK)
  {
    clean_up ();
    return;
  }
  CURL_EASY_SETOPT (curl, CURLOPT_FOLLOWLOCATION, 1);
#ifdef CURLOPT_REDIR_PROTOCOLS_STR
  if (0 == strncasecmp (current_url, "https://", strlen ("https://")))
    GNUNET_assert (CURLE_OK == curl_easy_setopt (curl,
                                                 CURLOPT_REDIR_PROTOCOLS_STR,
                                                 "https"));
  else
    GNUNET_assert (CURLE_OK == curl_easy_setopt (curl,
                                                 CURLOPT_REDIR_PROTOCOLS_STR,
                                                 "http,https"));
#else
#ifdef CURLOPT_REDIR_PROTOCOLS
  if (0 == strncasecmp (current_url, "https://", strlen ("https://")))
    GNUNET_assert (CURLE_OK == curl_easy_setopt (curl, CURLOPT_REDIR_PROTOCOLS,
                                                 CURLPROTO_HTTPS));
  else
    GNUNET_assert (CURLE_OK == curl_easy_setopt (curl, CURLOPT_REDIR_PROTOCOLS,
                                                 CURLPROTO_HTTP
                                                 | CURLPROTO_HTTPS));
#endif
#endif
#ifdef CURLOPT_PROTOCOLS_STR
  if (0 == strncasecmp (current_url, "https://", strlen ("https://")))
    GNUNET_assert (CURLE_OK == curl_easy_setopt (curl, CURLOPT_PROTOCOLS_STR,
                                                 "https"));
  else
    GNUNET_assert (CURLE_OK == curl_easy_setopt (curl, CURLOPT_PROTOCOLS_STR,
                                                 "http,https"));
#else
#ifdef CURLOPT_PROTOCOLS
  if (0 == strncasecmp (current_url, "https://", strlen ("https://")))
    GNUNET_assert (CURLE_OK == curl_easy_setopt (curl, CURLOPT_PROTOCOLS,
                                                 CURLPROTO_HTTPS));
  else
    GNUNET_assert (CURLE_OK == curl_easy_setopt (curl, CURLOPT_PROTOCOLS,
                                                 CURLPROTO_HTTP
                                                 | CURLPROTO_HTTPS));
#endif
#endif
  CURL_EASY_SETOPT (curl, CURLOPT_MAXREDIRS, 4);
  /* no need to abort if the above failed */
  CURL_EASY_SETOPT (curl, CURLOPT_URL, current_url);
  if (ret != CURLE_OK)
  {
    clean_up ();
    return;
  }
  CURL_EASY_SETOPT (curl, CURLOPT_FAILONERROR, 1);
#if 0
  CURL_EASY_SETOPT (curl, CURLOPT_VERBOSE, 1);
#endif
  CURL_EASY_SETOPT (curl, CURLOPT_BUFFERSIZE, GNUNET_MAX_MESSAGE_SIZE);
  if (0 == strncmp (current_url, "http", 4))
    CURL_EASY_SETOPT (curl, CURLOPT_USERAGENT, "GNUnet");
  CURL_EASY_SETOPT (curl, CURLOPT_CONNECTTIMEOUT, 60L);
  CURL_EASY_SETOPT (curl, CURLOPT_TIMEOUT, 60L);
  multi = curl_multi_init ();
  if (multi == NULL)
  {
    GNUNET_break (0);
    /* clean_up (); */
    return;
  }
  mret = curl_multi_add_handle (multi, curl);
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("%s failed at %s:%d: `%s'\n"),
                "curl_multi_add_handle",
                __FILE__,
                __LINE__,
                curl_multi_strerror (mret));
    mret = curl_multi_cleanup (multi);
    if (mret != CURLM_OK)
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_cleanup",
                  __FILE__,
                  __LINE__,
                  curl_multi_strerror (mret));
    multi = NULL;
    clean_up ();
    return;
  }
  end_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES);
  download_prepare ();
}


static void
task_download_dispatcher (void *cls)
{
  ti_download_dispatcher_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download is initiated...\n");
  if (GNUNET_NO == stat_download_in_progress)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Download can start immediately...\n");
    download_hostlist ();
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Download in progress, have to wait...\n");
    ti_download_dispatcher_task =
      GNUNET_SCHEDULER_add_delayed (WAITING_INTERVAL,
                                    &task_download_dispatcher,
                                    NULL);
  }
}


/**
 * Task that checks if we should try to download a hostlist.
 * If so, we initiate the download, otherwise we schedule
 * this task again for a later time.
 */
static void
task_check (void *cls)
{
  static int once;
  struct GNUNET_TIME_Relative delay;

  ti_check_download = NULL;
  if (stats == NULL)
  {
    curl_global_cleanup ();
    return;   /* in shutdown */
  }
  if ((stat_connection_count < MIN_CONNECTIONS) &&
      (NULL == ti_download_dispatcher_task))
    ti_download_dispatcher_task =
      GNUNET_SCHEDULER_add_now (&task_download_dispatcher, NULL);

  delay = hostlist_delay;
  if (0 == hostlist_delay.rel_value_us)
    hostlist_delay = GNUNET_TIME_UNIT_SECONDS;
  else
    hostlist_delay = GNUNET_TIME_relative_multiply (hostlist_delay, 2);
  if (hostlist_delay.rel_value_us >
      GNUNET_TIME_UNIT_HOURS.rel_value_us * (1 + stat_connection_count))
    hostlist_delay =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS,
                                     (1 + stat_connection_count));
  GNUNET_STATISTICS_set (stats,
                         gettext_noop (
                           "# milliseconds between hostlist downloads"),
                         hostlist_delay.rel_value_us / 1000LL,
                         GNUNET_YES);
  if (0 == once)
  {
    delay = GNUNET_TIME_UNIT_ZERO;
    once = 1;
  }
  GNUNET_log (
    GNUNET_ERROR_TYPE_INFO,
    _ ("Have %u/%u connections.  Will consider downloading hostlist in %s\n"),
    stat_connection_count,
    MIN_CONNECTIONS,
    GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
  ti_check_download = GNUNET_SCHEDULER_add_delayed (delay, &task_check, NULL);
}


/**
 * This tasks sets hostlist testing to allowed after interval between to testings is reached
 *
 * @param cls closure
 */
static void
task_testing_intervall_reset (void *cls)
{
  ti_testing_intervall_task = NULL;
  stat_testing_allowed = GNUNET_OK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing new hostlist advertisements is allowed again\n");
}


/**
 * Task that writes hostlist entries to a file on a regular base
 *
 * @param cls closure
 */
static void
task_hostlist_saving (void *cls)
{
  ti_saving_task = NULL;
  save_hostlist_file (GNUNET_NO);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostlists will be saved to file again in %s\n",
              GNUNET_STRINGS_relative_time_to_string (SAVING_INTERVAL,
                                                      GNUNET_YES));
  ti_saving_task =
    GNUNET_SCHEDULER_add_delayed (SAVING_INTERVAL, &task_hostlist_saving, NULL);
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param mq message queue for transmissions to @a peer
 */
static void *
handler_connect (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 struct GNUNET_MQ_Handle *mq)
{
  GNUNET_assert (stat_connection_count < UINT_MAX);
  stat_connection_count++;
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# active connections"),
                            1,
                            GNUNET_NO);
  return NULL;
}


/**
 * Method called whenever a given peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handler_disconnect (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *internal_cls)
{
  GNUNET_assert (stat_connection_count > 0);
  stat_connection_count--;
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# active connections"),
                            -1,
                            GNUNET_NO);
}


/**
 * Method called whenever an advertisement message arrives.
 *
 * @param uri the advertised URI
 */
static void
handler_advertisement (const char *uri)
{
  size_t uri_size;
  struct Hostlist *hostlist;

  uri_size = strlen (uri) + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostlist client received advertisement containing URI `%s'\n",
              uri);
  if (GNUNET_NO != linked_list_contains (uri))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "URI `%s' is already known\n", uri);
    return;
  }

  if (GNUNET_NO == stat_testing_allowed)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_DEBUG,
      "Currently not accepting new advertisements: interval between to advertisements is not reached\n");
    return;
  }
  if (GNUNET_YES == stat_testing_hostlist)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_DEBUG,
      "Currently not accepting new advertisements: we are already testing a hostlist\n");
    return;
  }

  hostlist = GNUNET_malloc (sizeof(struct Hostlist) + uri_size);
  hostlist->hostlist_uri = (const char *) &hostlist[1];
  GNUNET_memcpy (&hostlist[1], uri, uri_size);
  hostlist->time_creation = GNUNET_TIME_absolute_get ();
  hostlist->quality = HOSTLIST_INITIAL;
  hostlist_to_test = hostlist;

  stat_testing_hostlist = GNUNET_YES;
  stat_testing_allowed = GNUNET_NO;
  ti_testing_intervall_task =
    GNUNET_SCHEDULER_add_delayed (TESTING_INTERVAL,
                                  &task_testing_intervall_reset,
                                  NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing new hostlist advertisements is locked for the next %s\n",
              GNUNET_STRINGS_relative_time_to_string (TESTING_INTERVAL,
                                                      GNUNET_YES));

  ti_download_dispatcher_task =
    GNUNET_SCHEDULER_add_now (&task_download_dispatcher, NULL);
}


/**
 * Continuation called by the statistics code once
 * we go the stat.  Initiates hostlist download scheduling.
 *
 * @param cls closure
 * @param success #GNUNET_OK if statistics were
 *        successfully obtained, #GNUNET_SYSERR if not.
 */
static void
primary_task (void *cls, int success)
{
  if (NULL != ti_check_download)
  {
    GNUNET_SCHEDULER_cancel (ti_check_download);
    ti_check_download = NULL;
  }
  sget = NULL;
  GNUNET_assert (NULL != stats);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Statistics request done, scheduling hostlist download\n");
  ti_check_download = GNUNET_SCHEDULER_add_now (&task_check, NULL);
}


/**
 * Continuation called by the statistics code once
 * we go the stat.  Initiates hostlist download scheduling.
 *
 * @param cls closure
 */
static void
stat_timeout_task (void *cls)
{
  GNUNET_STATISTICS_get_cancel (sget);
  sget = NULL;
  ti_check_download = GNUNET_SCHEDULER_add_now (&task_check, NULL);
}


/**
 * We've received the previous delay value from statistics.  Remember it.
 *
 * @param cls NULL, unused
 * @param subsystem should be "hostlist", unused
 * @param name will be "milliseconds between hostlist downloads", unused
 * @param value previous delay value, in milliseconds (!)
 * @param is_persistent unused, will be #GNUNET_YES
 */
static int
process_stat (void *cls,
              const char *subsystem,
              const char *name,
              uint64_t value,
              int is_persistent)
{
  hostlist_delay.rel_value_us = value * 1000LL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initial time between hostlist downloads is %s\n",
              GNUNET_STRINGS_relative_time_to_string (hostlist_delay,
                                                      GNUNET_YES));
  return GNUNET_OK;
}


/**
 * Method to load persistent hostlist file during hostlist client startup
 */
static void
load_hostlist_file ()
{
  char *filename;
  char *uri;
  char *emsg;
  struct Hostlist *hostlist;
  uint32_t times_used;
  uint32_t hellos_returned;
  uint64_t quality;
  uint64_t last_used;
  uint64_t created;
  uint32_t counter;
  struct GNUNET_BIO_ReadHandle *rh;

  uri = NULL;
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                            "HOSTLIST",
                                                            "HOSTLISTFILE",
                                                            &filename))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_WARNING,
                               "hostlist",
                               "HOSTLISTFILE");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _ ("Loading saved hostlist entries from file `%s' \n"),
              filename);
  if (GNUNET_NO == GNUNET_DISK_file_test (filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Hostlist file `%s' does not exist\n"),
                filename);
    GNUNET_free (filename);
    return;
  }

  rh = GNUNET_BIO_read_open_file (filename);
  if (NULL == rh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ (
                  "Could not open file `%s' for reading to load hostlists: %s\n"),
                filename,
                strerror (errno));
    GNUNET_free (filename);
    return;
  }

  counter = 0;
  {
    struct GNUNET_BIO_ReadSpec rs[] = {
      GNUNET_BIO_read_spec_int32 ("times used", (int32_t *) &times_used),
      GNUNET_BIO_read_spec_int64 ("quality", (int64_t *) &quality),
      GNUNET_BIO_read_spec_int64 ("last used", (int64_t *) &last_used),
      GNUNET_BIO_read_spec_int64 ("created", (int64_t *) &created),
      GNUNET_BIO_read_spec_int32 ("hellos returned",
                                  (int32_t *) &hellos_returned),
      GNUNET_BIO_read_spec_end (),
    };
    while ((GNUNET_OK == GNUNET_BIO_read_string (rh, "url", &uri, MAX_URL_LEN))
           &&
           (NULL != uri) &&
           (GNUNET_OK == GNUNET_BIO_read_spec_commit (rh, rs)))
    {
      hostlist = GNUNET_malloc (sizeof(struct Hostlist) + strlen (uri) + 1);
      hostlist->hello_count = hellos_returned;
      hostlist->hostlist_uri = (const char *) &hostlist[1];
      GNUNET_memcpy (&hostlist[1], uri, strlen (uri) + 1);
      hostlist->quality = quality;
      hostlist->time_creation.abs_value_us = created;
      hostlist->time_last_usage.abs_value_us = last_used;
      GNUNET_CONTAINER_DLL_insert (linked_list_head, linked_list_tail, hostlist)
      ;
      linked_list_size++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Added hostlist entry with URI `%s' \n",
                  hostlist->hostlist_uri);
      GNUNET_free (uri);
      uri = NULL;
      counter++;
      if (counter >= MAX_NUMBER_HOSTLISTS)
        break;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _ ("%u hostlist URIs loaded from file\n"),
              counter);
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# hostlist URIs read from file"),
                         counter,
                         GNUNET_YES);
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# advertised hostlist URIs"),
                         linked_list_size,
                         GNUNET_NO);

  GNUNET_free (uri);
  emsg = NULL;
  (void) GNUNET_BIO_read_close (rh, &emsg);
  if (emsg != NULL)
    GNUNET_free (emsg);
  GNUNET_free (filename);
}


/**
 * Method to save persistent hostlist file during hostlist client shutdown
 *
 * @param shutdown set if called because of shutdown, entries in linked list will be destroyed
 */
static void
save_hostlist_file (int shutdown)
{
  char *filename;
  struct Hostlist *pos;
  struct GNUNET_BIO_WriteHandle *wh;
  int ok;
  uint32_t counter;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                            "HOSTLIST",
                                                            "HOSTLISTFILE",
                                                            &filename))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_WARNING,
                               "hostlist",
                               "HOSTLISTFILE");
    return;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_directory_create_for_file (filename))
  {
    GNUNET_free (filename);
    return;
  }
  wh = GNUNET_BIO_write_open_file (filename);
  if (NULL == wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ (
                  "Could not open file `%s' for writing to save hostlists: %s\n"),
                filename,
                strerror (errno));
    GNUNET_free (filename);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _ ("Writing %u hostlist URIs to `%s'\n"),
              linked_list_size,
              filename);
  /* add code to write hostlists to file using bio */
  ok = GNUNET_YES;
  counter = 0;
  while (NULL != (pos = linked_list_head))
  {
    if (GNUNET_YES == shutdown)
    {
      GNUNET_CONTAINER_DLL_remove (linked_list_head, linked_list_tail, pos);
      linked_list_size--;
    }
    if (GNUNET_YES == ok)
    {
      struct GNUNET_BIO_WriteSpec ws[] = {
        GNUNET_BIO_write_spec_string ("hostlist uri", pos->hostlist_uri),
        GNUNET_BIO_write_spec_int32 ("times used",
                                     (int32_t *) &pos->times_used),
        GNUNET_BIO_write_spec_int64 ("quality", (int64_t *) &pos->quality),
        GNUNET_BIO_write_spec_int64 (
          "last usage",
          (int64_t *) &pos->time_last_usage.abs_value_us),
        GNUNET_BIO_write_spec_int64 (
          "creation time",
          (int64_t *) &pos->time_creation.abs_value_us),
        GNUNET_BIO_write_spec_int32 ("hellos count",
                                     (int32_t *) &pos->hello_count),
        GNUNET_BIO_write_spec_end (),
      };
      if ((GNUNET_OK != GNUNET_BIO_write_spec_commit (wh, ws)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ ("Error writing hostlist URIs to file `%s'\n"),
                    filename);
        ok = GNUNET_NO;
      }
    }

    if (GNUNET_YES == shutdown)
      GNUNET_free (pos);
    counter++;
    if (counter >= MAX_NUMBER_HOSTLISTS)
      break;
  }
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# hostlist URIs written to file"),
                         counter,
                         GNUNET_YES);

  if (GNUNET_OK != GNUNET_BIO_write_close (wh, NULL))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Error writing hostlist URIs to file `%s'\n"),
                filename);
  GNUNET_free (filename);
}


/**
 * Start downloading hostlists from hostlist servers as necessary.
 *
 * @param c configuration to use
 * @param st statistics handle to use
 * @param[out] ch set to handler for CORE connect events
 * @param[out] dh set to handler for CORE disconnect events
 * @param[out] msgh set to handler for CORE advertisement messages
 * @param learn should we learn hostlist URLs from CORE
 * @return #GNUNET_OK on success
 */
int
GNUNET_HOSTLIST_client_start (const struct GNUNET_CONFIGURATION_Handle *c,
                              struct GNUNET_STATISTICS_Handle *st,
                              GNUNET_CORE_ConnectEventHandler *ch,
                              GNUNET_CORE_DisconnectEventHandler *dh,
                              GNUNET_HOSTLIST_UriHandler *msgh,
                              int learn)
{
  char *filename;
  char *proxytype_str;
  int result;

  GNUNET_assert (NULL != st);
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  cfg = c;
  stats = st;

  /* Read proxy configuration */
  peerstore = GNUNET_PEERSTORE_connect (c);
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "HOSTLIST", "PROXY", &proxy))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found proxy host: `%s'\n", proxy);
    /* proxy username */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                            "HOSTLIST",
                                                            "PROXY_USERNAME",
                                                            &proxy_username))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found proxy username name: `%s'\n",
                  proxy_username);
    }

    /* proxy password */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                            "HOSTLIST",
                                                            "PROXY_PASSWORD",
                                                            &proxy_password))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found proxy password name: `%s'\n",
                  proxy_password);
    }

    /* proxy type */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                            "HOSTLIST",
                                                            "PROXY_TYPE",
                                                            &proxytype_str))
    {
      if (GNUNET_OK != GNUNET_STRINGS_utf8_toupper (proxytype_str,
                                                    proxytype_str))
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Unable to convert `%s' to UTF-8 uppercase\n",
                    proxytype_str);
      proxy_type = CURLPROXY_HTTP;
      if (0 == strcmp (proxytype_str, "HTTP"))
        proxy_type = CURLPROXY_HTTP;
      else if (0 == strcmp (proxytype_str, "HTTP_1_0"))
        proxy_type = CURLPROXY_HTTP_1_0;
      else if (0 == strcmp (proxytype_str, "SOCKS4"))
        proxy_type = CURLPROXY_SOCKS4;
      else if (0 == strcmp (proxytype_str, "SOCKS5"))
        proxy_type = CURLPROXY_SOCKS5;
      else if (0 == strcmp (proxytype_str, "SOCKS4A"))
        proxy_type = CURLPROXY_SOCKS4A;
      else if (0 == strcmp (proxytype_str, "SOCKS5_HOSTNAME"))
        proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
      else
      {
        GNUNET_log (
          GNUNET_ERROR_TYPE_ERROR,
          _ (
            "Invalid proxy type: `%s', disabling proxy! Check configuration!\n")
          ,
          proxytype_str);
        GNUNET_free (proxytype_str);
        GNUNET_free (proxy);
        proxy = NULL;
        GNUNET_free (proxy_username);
        proxy_username = NULL;
        GNUNET_free (proxy_password);
        proxy_password = NULL;

        return GNUNET_SYSERR;
      }
    }
    GNUNET_free (proxytype_str);
  }

  stat_learning = learn;
  *ch = &handler_connect;
  *dh = &handler_disconnect;
  linked_list_head = NULL;
  linked_list_tail = NULL;
  stat_use_bootstrap = GNUNET_YES;
  stat_testing_hostlist = GNUNET_NO;
  stat_testing_allowed = GNUNET_YES;

  if (GNUNET_YES == stat_learning)
  {
    *msgh = &handler_advertisement;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Learning is enabled on this peer\n"));
    load_hostlist_file ();
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Hostlists will be saved to file again in %s\n",
                GNUNET_STRINGS_relative_time_to_string (SAVING_INTERVAL,
                                                        GNUNET_YES));
    ti_saving_task = GNUNET_SCHEDULER_add_delayed (SAVING_INTERVAL,
                                                   &task_hostlist_saving,
                                                   NULL);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Learning is not enabled on this peer\n"));
    *msgh = NULL;
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                              "HOSTLIST",
                                                              "HOSTLISTFILE",
                                                              &filename))
    {
      if (GNUNET_YES == GNUNET_DISK_file_test (filename))
      {
        result = remove (filename);
        if (0 == result)
          GNUNET_log (
            GNUNET_ERROR_TYPE_INFO,
            _ (
              "Since learning is not enabled on this peer, hostlist file `%s' was removed\n"),
            filename);
        else
          GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                    "remove",
                                    filename);
      }
    }
    GNUNET_free (filename);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading stats value on hostlist download frequency\n");
  sget = GNUNET_STATISTICS_get (stats,
                                "hostlist",
                                gettext_noop (
                                  "# milliseconds between hostlist downloads"),
                                &primary_task,
                                &process_stat,
                                NULL);
  if (NULL == sget)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Statistics request failed, scheduling hostlist download\n");
    ti_check_download = GNUNET_SCHEDULER_add_now (&task_check, NULL);
  }
  else
  {
    ti_check_download = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                                      &stat_timeout_task,
                                                      NULL);
  }
  return GNUNET_OK;
}


/**
 * Stop downloading hostlists from hostlist servers as necessary.
 */
void
GNUNET_HOSTLIST_client_stop ()
{
  struct StoreHelloEntry *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hostlist client shutdown\n");
  while (NULL != (pos = she_head))
  {
    GNUNET_CONTAINER_DLL_remove (she_head, she_tail, pos);
    GNUNET_PEERSTORE_hello_add_cancel (pos->sc);
    GNUNET_free (pos);
  }
  if (NULL != sget)
  {
    GNUNET_STATISTICS_get_cancel (sget);
    sget = NULL;
  }
  stats = NULL;
  if (GNUNET_YES == stat_learning)
    save_hostlist_file (GNUNET_YES);
  if (NULL != ti_saving_task)
  {
    GNUNET_SCHEDULER_cancel (ti_saving_task);
    ti_saving_task = NULL;
  }
  if (NULL != ti_download_dispatcher_task)
  {
    GNUNET_SCHEDULER_cancel (ti_download_dispatcher_task);
    ti_download_dispatcher_task = NULL;
  }
  if (NULL != ti_testing_intervall_task)
  {
    GNUNET_SCHEDULER_cancel (ti_testing_intervall_task);
    ti_testing_intervall_task = NULL;
  }
  if (NULL != ti_download)
  {
    GNUNET_SCHEDULER_cancel (ti_download);
    ti_download = NULL;
    update_hostlist ();
    clean_up ();
  }
  if (NULL != ti_check_download)
  {
    GNUNET_SCHEDULER_cancel (ti_check_download);
    ti_check_download = NULL;
    curl_global_cleanup ();
  }
  GNUNET_free (proxy);
  proxy = NULL;
  GNUNET_free (proxy_username);
  proxy_username = NULL;
  GNUNET_free (proxy_password);
  proxy_password = NULL;
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore);
    peerstore = NULL;
  }
  cfg = NULL;
}


/* end of gnunet-daemon-hostlist_client.c */
