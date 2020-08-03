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
#include "../identity/identity.h"

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
const struct GNUNET_IDENTITY_Ego *ego;

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
  cleanup_task = NULL;
  if (NULL != escrow_handle)
    GNUNET_ESCROW_fini (escrow_handle);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
  if (NULL != escrow_op)
  {
    GNUNET_ESCROW_cancel (escrow_op);
    GNUNET_free (escrow_op);
    escrow_op = NULL;
  }
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
    /* does not have to be freed, as this is done when
       cleaning up the ego list in the plugin */
    ego = NULL;
  }
  method = -1;
}


static void
put_cb (struct GNUNET_ESCROW_Anchor *escrowAnchor)
{
  char *anchorString;

  escrow_op = NULL;

  anchorString = GNUNET_ESCROW_anchor_data_to_string (escrow_handle,
                                                      escrowAnchor,
                                                      method);

  fprintf (stdout, "Escrow finished! Please keep the following anchor \
in order to restore the key later!\n%s\n", anchorString);
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
verify_cb (int verificationResult)
{
  escrow_op = NULL;

  switch (verificationResult)
  {
    case GNUNET_ESCROW_VALID:
      fprintf (stdout, "Escrow is valid!\n");
      break;
    case GNUNET_ESCROW_INVALID:
      fprintf (stdout, "Escrow is INvalid! Please perform a new escrow.\n");
      break;
    default:
      fprintf (stderr, "invalid verificationResult!\n");
  }
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
get_cb (const struct GNUNET_IDENTITY_Ego *ego)
{
  escrow_op = NULL;

  if (NULL == ego)
  {
    ret = 1;
    fprintf (stderr, _ ("escrow failed!\n"));
  }
  else
    fprintf (stdout, "Ego %s could successfully be restored!\n", ego->name);
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
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
                                   &put_cb);
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
                                      &verify_cb);
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
                                   &get_cb);
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
    if (NULL == anchor_string)
    {
      ret = 1;
      fprintf (stderr, _ ("-a is needed for -V!\n"));
      return;
    }
    ego_name = verify_ego;
  }
  else if (NULL != get_ego)
  {
    /* get */
    if (NULL == anchor_string)
    {
      ret = 1;
      fprintf (stderr, _ ("-a is needed for -G!\n"));
      return;
    }
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
  if (!strncmp (plaintext_string, method_name, strlen (plaintext_string)))
    method = GNUNET_ESCROW_KEY_PLAINTEXT;
  else if (!strncmp (gns_string, method_name, strlen (gns_string)))
    method = GNUNET_ESCROW_KEY_GNS;
  else if (!strncmp (anastasis_string, method_name, strlen (anastasis_string)))
    method = GNUNET_ESCROW_KEY_ANASTASIS;
  else
  {
    ret = 1;
    fprintf (stderr, _ ("unknown method name!"));
    return;
  }

  escrow_handle = GNUNET_ESCROW_init (c);
  
  if (NULL != anchor_string)
  {
    /* parse anchor_string according to method */
    anchor = GNUNET_ESCROW_anchor_string_to_data (escrow_handle,
                                                  anchor_string,
                                                  method);
  }

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
