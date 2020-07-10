/*
   This file is part of GNUnet.
   Copyright (C) 2020 GNUnet e.V.

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
 * @author Johannes Späth
 * @file src/escrow/gnunet-escrow.c
 * @brief Identity Escrow utility
 *
 */

#include "platform.h"

#include "gnunet_util_lib.h"

/**
 * return value
 */
static int ret;

/**
 * Ego name
 */
static char *ego_name;

/**
 * Plugin name
 */
static char *plugin_name;

static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  ret = 0;
  if (NULL == ego_name)
  {
    ret = 1;
    fprintf (stderr, _ ("Ego is required\n"));
    return;
  }

  if (NULL == plugin_name)
  {
    ret = 1;
    fprintf (stderr, _ ("Escrow plugin name is missing\n"));
    return;
  }

// TODO: where to decide what to call from api?

}


int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('e',
                                 "ego",
                                 "EGO",
                                 gettext_noop ("The EGO to escrow"),
                                 &ego_name),
    GNUNET_GETOPT_option_string ('p',
                                 "plugin",
                                 "PLUGIN",
                                 gettext_noop ("The escrow plugin to use"),
                                 &plugin_name),
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc,
                                       argv,
                                       "gnunet-escrow",
                                       _ ("escrow command line tool"),
                                       options,
                                       &run,
                                       NULL))
    return 1;
  else
    return ret;
}

