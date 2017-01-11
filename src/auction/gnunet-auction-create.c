/*
   This file is part of GNUnet.
   Copyright (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 GNUnet e.V.

   GNUnet is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3, or (at your
   option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNUnet; see the file COPYING.  If not, write to the
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
   */

/**
 * @file auction/gnunet-auction-create.c
 * @brief tool to create a new auction
 * @author Markus Teich
 */
#include "platform.h"
#include "gnunet_util_lib.h"
/* #include "gnunet_auction_service.h" */

static int ret; /** Final status code. */
static char *fndesc; /** filename of the item description */
static char *fnprices; /** filename of the price map */
static struct GNUNET_TIME_Relative dround; /** max round duration */
static struct GNUNET_TIME_Relative dstart; /** time until auction starts */
static unsigned int m = 0; /** auction parameter m */
static int public = 0; /** public outcome */


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
	 char *const *args,
	 const char *cfgfile,
	 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	/* main code here */
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
	static const struct GNUNET_GETOPT_CommandLineOption options[] = {
		{'d', "description", "FILE",
			gettext_noop ("description of the item to be sold"),
			1, &GNUNET_GETOPT_set_filename, &fndesc},
		{'c', "costmap", "FILE",
			gettext_noop ("mapping of possible prices"),
			1, &GNUNET_GETOPT_set_filename, &fnprices},
		{'r', "roundtime", "DURATION",
			gettext_noop ("max duration per round"),
			1, &GNUNET_GETOPT_set_relative_time, &dround},
		{'s', "starttime", "DURATION",
			gettext_noop ("duration until auction starts"),
			1, &GNUNET_GETOPT_set_relative_time, &dstart},
		{'m', "m", "NUMBER",
			gettext_noop ("number of items to sell, 0 for first price auction"),
			0, &GNUNET_GETOPT_set_uint, &m},
		{'p', "public", NULL,
			gettext_noop ("public auction outcome"),
			0, &GNUNET_GETOPT_set_one, &public},
		GNUNET_GETOPT_OPTION_END
	};
	if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
		return 2;

	ret = (GNUNET_OK ==
		   GNUNET_PROGRAM_run (argc, argv,
							   "gnunet-auction-create",
							   gettext_noop ("help text"),
							   options,
							   &run,
							   NULL)) ? ret : 1;
	GNUNET_free ((void*) argv);
	return ret;
}
