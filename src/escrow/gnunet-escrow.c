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
#include "gnunet_escrow_lib.h"

/**
 * return value
 */
static int ret;

/**
 * Plaintext method string
 */
static const char *plaintext_string = "plaintext";

/**
 * GNS method string
 */
static const char *gns_string = "gns";

/**
 * Anastasis method string
 */
static const char *anastasis_string = "anastasis";

/**
 * -P option
 */
static char *put_ego;

/**
 * -V option
 */
static char *verify_ego;

/**
 * -G option
 */
static char *get_ego;

/**
 * The ego
 */
struct GNUNET_IDENTITY_Ego *ego;

/**
 * Anchor string
 */
static char *anchor_string;

/**
 * The escrow anchor
 */
struct GNUNET_ESCROW_Anchor *anchor;

/**
 * Plugin name
 */
static char *method_name;

/**
 * Escrow method
 */
enum GNUNET_ESCROW_Key_Escrow_Method method;

/**
 * Handle to the escrow component
 */
static struct GNUNET_ESCROW_Handle *escrow_handle;

/**
 * Escrow operation
 */
static struct GNUNET_ESCROW_Operation *escrow_op;

/**
 * Handle to the identity service
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Cleanup task
 */
static struct GNUNET_SCHEDULER_Task *cleanup_task;


/**
 * Called to clean up the escrow component
 */
static void
do_cleanup (void *cls)
{
  GNUNET_ESCROW_fini (escrow_handle);
  if (NULL != put_ego)
  {
    GNUNET_free (put_ego);
    put_ego = NULL;
  }
  if (NULL != verify_ego)
  {
    GNUNET_free (verify_ego);
    verify_ego = NULL;
  }
  if (NULL != get_ego)
  {
    GNUNET_free (get_ego);
    get_ego = NULL;
  }
  if (NULL != ego)
  {
    GNUNET_free (ego);
    ego = NULL;
  }
  method = 0;
}


static void
put_cb (void *cls,
        struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  struct GNUNET_ESCROW_Operation *op = cls;

  // TODO: implement
  return;
}


static void
verify_cb (void *cls,
           int verificationResult)
{
  struct GNUNET_ESCROW_Operation *op = cls;

  // TODO: implement
  return;
}


static void
get_cb (void *cls,
        const struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_ESCROW_Operation *op = cls;

  // TODO: implement
  return;
}


static void
start_process ()
{
  /* put */
  if (NULL != put_ego)
  {
    if (NULL == ego)
    {
      fprintf (stderr, "Ego %s not found\n", put_ego);
      cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
      return;
    }
    escrow_op = GNUNET_ESCROW_put (escrow_handle,
                                   ego,
                                   method,
                                   &put_cb,
                                   escrow_op);
    return;
  }
  /* verify */
  if (NULL != verify_ego)
  {
    if (NULL == ego)
    {
      fprintf (stderr, "Ego %s not found\n", verify_ego);
      cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
      return;
    }
    escrow_op = GNUNET_ESCROW_verify (escrow_handle,
                                      ego,
                                      anchor,
                                      method,
                                      &verify_cb,
                                      escrow_op);
    return;
  }
  /* get */
  if (NULL != get_ego)
  {
    if (NULL != ego)
    {
      fprintf (stderr, "The name %s is already in use for an ego\n", get_ego);
      cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
      return;
    }
    escrow_op = GNUNET_ESCROW_get (escrow_handle,
                                   anchor,
                                   get_ego,
                                   method,
                                   &get_cb,
                                   escrow_op);
    return;
  }
}


static int init = GNUNET_YES;

static void
ego_cb (void *cls,
        struct GNUNET_IDENTITY_Ego *e,
        void **ctx,
        const char *name)
{
  char *ego_name = cls;

  if (NULL == name)
  {
    if (GNUNET_YES == init)
    {
      init = GNUNET_NO;
      start_process ();
    }
    return;
  }
  if (0 != strcmp (name, ego_name))
    return;
  ego = e;
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *ego_name;

  ret = 0;

  /* check if method is set */
  if (NULL == method_name)
  {
    ret = 1;
    fprintf (stderr, _ ("Escrow method (-m option) is missing\n"));
    return;
  }

  if (NULL != put_ego)
  {
    if (NULL != verify_ego || NULL != get_ego)
    {
      ret = 1;
      fprintf (stderr, _ ("-P may only be used without -V or -G!\n"));
      return;
    }
    /* put */
    ego_name = put_ego;
  }
  else if (NULL != verify_ego)
  {
    if (NULL != get_ego)
    {
      ret = 1;
      fprintf (stderr, _ ("-V may only be used without -P or -G!\n"));
      return;
    }
    /* verify */
    ego_name = verify_ego;
  }
  else if (NULL != get_ego)
  {
    /* get */
    ego_name = get_ego;
  }
  else
  {
    /* nothing */
    ret = 1;
    fprintf (stderr, _ ("-P, -V or -G option must be specified!\n"));
    return;
  }

  /* determine method */
  if (strncmp (plaintext_string, method_name, strlen (plaintext_string)))
    method = GNUNET_ESCROW_KEY_PLAINTEXT;
  else if (strncmp (gns_string, method_name, strlen (gns_string)))
    method = GNUNET_ESCROW_KEY_GNS;
  else if (strncmp (anastasis_string, method_name, strlen (anastasis_string)))
    method = GNUNET_ESCROW_KEY_ANASTASIS;
  else
  {
    ret = 1;
    fprintf (stderr, _ ("unknown method name!"));
    return;
  }

  escrow_handle = GNUNET_ESCROW_init (c);
  
  /* parse anchor_string according to method */
  anchor = GNUNET_ESCROW_anchor_string_to_data (escrow_handle,
                                                anchor_string,
                                                method);

  /* connect to identity service in order to get the egos */
  identity_handle = GNUNET_IDENTITY_connect (c, &ego_cb, ego_name);
}


int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('P',
                                 "put",
                                 "NAME",
                                 gettext_noop ("Put the ego NAME into escrow"),
                                 &put_ego),
    GNUNET_GETOPT_option_string ('V',
                                 "verify",
                                 "NAME",
                                 gettext_noop ("Verify the escrow of the ego NAME"),
                                 &verify_ego),
    GNUNET_GETOPT_option_string ('G',
                                 "get",
                                 "NAME",
                                 gettext_noop ("Get the ego NAME back from escrow"),
                                 &get_ego),
    GNUNET_GETOPT_option_string ('a',
                                 "anchor",
                                 "ANCHOR",
                                 gettext_noop ("The the escrow anchor"),
                                 &anchor_string),
    GNUNET_GETOPT_option_string ('m',
                                 "method",
                                 "METHOD",
                                 gettext_noop ("The escrow method (and plugin) to use"),
                                 &method_name),
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
