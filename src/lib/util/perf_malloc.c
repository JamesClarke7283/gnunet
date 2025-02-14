/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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
 * @author Christian Grothoff
 * @file util/perf_malloc.c
 * @brief measure performance of allocation functions
 */

#include "platform.h"
#include "gnunet_util_lib.h"

static uint64_t
perf_malloc ()
{
  uint64_t ret;

  ret = 0;
  for (size_t i = 1; i < 1024 * 1024; i += 1024)
  {
    ret += i;
    GNUNET_free_nz (GNUNET_malloc (i));
  }
  return ret;
}


static uint64_t
perf_realloc ()
{
  uint64_t ret;

  ret = 0;
  for (size_t i = 10; i < 1024 * 1024 / 5; i += 1024)
  {
    char *ptr;

    ret += i;
    ptr = GNUNET_malloc (i);
    memset (ptr, 1, i);
    ptr = GNUNET_realloc (ptr, i + 5);
    for (size_t j = 0; j<i; j++)
      GNUNET_assert (1 == ptr[j]);
    memset (ptr, 6, i + 5);
    ptr = GNUNET_realloc (ptr, i - 5);
    for (size_t j = 0; j<i - 5; j++)
      GNUNET_assert (6 == ptr[j]);
    GNUNET_free (ptr);
  }
  return ret;
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;
  uint64_t kb;

  start = GNUNET_TIME_absolute_get ();
  kb = perf_malloc ();
  printf ("Malloc perf took %s (%"PRIu64"kb)\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES), kb);
  start = GNUNET_TIME_absolute_get ();
  kb = perf_realloc ();
  printf ("Realloc perf took %s (%"PRIu64"kb)\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES), kb);
  return 0;
}


/* end of perf_malloc.c */
