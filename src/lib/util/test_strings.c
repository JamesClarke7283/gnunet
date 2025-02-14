/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file util/test_strings.c
 * @brief testcase for strings.c
 */

#include "platform.h"
#include "gnunet_util_lib.h"


#define WANT(a, b) if (0 != strcmp (a, b)) { fprintf (stderr, \
                                                      "Got `%s', wanted `%s'\n", \
                                                      b, a); GNUNET_free (b); \
                                             GNUNET_break (0); \
                                             return 1; } else { GNUNET_free (b); \
}
#define WANTNF(a, b) do { if (0 != strcmp (a, b)) { fprintf (stderr, \
                                                             "Got `%s', wanted `%s'\n", \
                                                             b, a); \
                                                    GNUNET_break (0); return 1; \
                          } } while (0)
#define WANTB(a, b, l) if (0 != memcmp (a, b, l)) { GNUNET_break (0); return 1; \
} else { }

#define URLENCODE_TEST_VECTOR_PLAIN "Asbjlaw=ljsdlasjd?人aslkdsa"

#define URLENCODE_TEST_VECTOR_ENCODED \
  "Asbjlaw\%3Dljsdlasjd\%3F\%E4\%BA\%BAaslkdsa"

int
main (int argc, char *argv[])
{
  char buf[128];
  char *r;
  char *b;
  const char *bc;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Absolute atx;
  struct GNUNET_TIME_Relative rt;
  struct GNUNET_TIME_Relative rtx;
  const char *hdir;
  struct GNUNET_STRINGS_IPv6NetworkPolicy *pol;

  pol = GNUNET_STRINGS_parse_ipv6_policy ("::1;");
  GNUNET_assert (NULL != pol);
  GNUNET_free (pol);

  GNUNET_log_setup ("test_strings", "ERROR", NULL);
  sprintf (buf, "4 %s", _ (/* size unit */ "b"));
  b = GNUNET_STRINGS_byte_size_fancy (4);
  WANT (buf, b);
  sprintf (buf, "10 %s", _ (/* size unit */ "KiB"));
  b = GNUNET_STRINGS_byte_size_fancy (10240);
  WANT (buf, b);
  sprintf (buf, "10 %s", _ (/* size unit */ "TiB"));
  b = GNUNET_STRINGS_byte_size_fancy (10240LL * 1024LL * 1024LL * 1024LL);
  WANT (buf, b);
  sprintf (buf, "4 %s", _ (/* time unit */ "ms"));
  bc = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
                                                 (GNUNET_TIME_UNIT_MILLISECONDS,
                                                 4), GNUNET_YES);
  WANTNF (buf, bc);
  sprintf (buf, "7 %s", _ (/* time unit */ "s"));
  bc = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
                                                 (GNUNET_TIME_UNIT_MILLISECONDS,
                                                 7 * 1000), GNUNET_YES);
  WANTNF (buf, bc);
  sprintf (buf, "7 %s", _ (/* time unit */ "h"));
  bc = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_relative_multiply
                                                 (GNUNET_TIME_UNIT_MILLISECONDS,
                                                 7 * 60 * 60 * 1000),
                                               GNUNET_YES);
  WANTNF (buf, bc);

  hdir = getenv ("HOME");

  GNUNET_snprintf (buf, sizeof(buf), "%s%s", hdir, DIR_SEPARATOR_STR);
  b = GNUNET_STRINGS_filename_expand ("~");
  GNUNET_assert (b != NULL);
  WANT (buf, b);
  GNUNET_STRINGS_buffer_fill (buf, sizeof(buf), 3, "a", "btx", "c");
  WANTB ("a\0btx\0c", buf, 8);
  if (6 != GNUNET_STRINGS_buffer_tokenize (buf, sizeof(buf), 2, &r, &b))
    return 1;
  r = GNUNET_strdup (r);
  WANT ("a", r);
  b = GNUNET_strdup (b);
  WANT ("btx", b);
  if (0 != GNUNET_STRINGS_buffer_tokenize (buf, 2, 2, &r, &b))
    return 1;
  at.abs_value_us = 5000000;
  bc = GNUNET_STRINGS_absolute_time_to_string (at);
  /* bc should be something like "Wed Dec 31 17:00:05 1969"
   * where the details of the day and hour depend on the timezone;
   * however, the "0:05 19" should always be there; hence: */
  if (NULL == strstr (bc, "0:05 19"))
  {
    fprintf (stderr, "Got %s\n", bc);
    GNUNET_break (0);
    return 1;
  }
  /* Normalization */
  r = (char*) "q\u0307\u0323"; /* Non-canonical order */

  b = GNUNET_STRINGS_utf8_normalize (r);
  GNUNET_assert (0 == strcmp ("q\u0323\u0307", b));
  GNUNET_free (b);
  b = GNUNET_STRINGS_to_utf8 ("TEST", 4, "ASCII");
  WANT ("TEST", b);

  at = GNUNET_TIME_UNIT_FOREVER_ABS;
  bc = GNUNET_STRINGS_absolute_time_to_string (at);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_STRINGS_fancy_time_to_absolute (bc, &atx));
  GNUNET_assert (atx.abs_value_us == at.abs_value_us);

  at.abs_value_us = 50000000000;
  bc = GNUNET_STRINGS_absolute_time_to_string (at);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_STRINGS_fancy_time_to_absolute (bc, &atx));

  if (atx.abs_value_us != at.abs_value_us)
  {
    GNUNET_assert (0);
  }

  GNUNET_log_skip (2, GNUNET_NO);
  b = GNUNET_STRINGS_to_utf8 ("TEST", 4, "unknown");
  GNUNET_log_skip (0, GNUNET_YES);
  WANT ("TEST", b);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_STRINGS_fancy_time_to_relative ("15m", &rt));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_STRINGS_fancy_time_to_relative ("15 m", &rtx));
  GNUNET_assert (rt.rel_value_us == rtx.rel_value_us);

  GNUNET_assert (0 != GNUNET_STRINGS_urlencode (strlen (
                                                  URLENCODE_TEST_VECTOR_PLAIN),
                                                URLENCODE_TEST_VECTOR_PLAIN,
                                                &b));
  WANT (URLENCODE_TEST_VECTOR_ENCODED, b);
  GNUNET_free (b);
  GNUNET_assert (0 !=
                 GNUNET_STRINGS_urldecode (
                   URLENCODE_TEST_VECTOR_ENCODED,
                   strlen (URLENCODE_TEST_VECTOR_ENCODED),
                   &b));
  WANT (URLENCODE_TEST_VECTOR_PLAIN, b);
  GNUNET_free (b);
  return 0;
}


/* end of test_strings.c */
