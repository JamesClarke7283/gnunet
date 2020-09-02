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
 * @file escrow/escrow_api.c
 * 
 * @brief api to interact with the escrow component
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_escrow_lib.h"
#include "gnunet_escrow_plugin.h"
#include "escrow.h"


/**
 * Init canary for the plaintext plugin
 */
static int plaintext_initialized;


/**
 * Init canary for the GNS plugin
 */
static int gns_initialized;


/**
 * Init canary for the Anastasis plugin
 */
static int anastasis_initialized;


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
 * None method string
 */
static const char *none_string = "INVALID-METHOD";


/**
 * Pointer to the plaintext plugin API
 */
static struct GNUNET_ESCROW_KeyPluginFunctions *plaintext_api;


/**
 * Pointer to the GNS plugin API
 */
static struct GNUNET_ESCROW_KeyPluginFunctions *gns_api;


/**
 * Pointer to the Anastasis plugin API
 */
static struct GNUNET_ESCROW_KeyPluginFunctions *anastasis_api;


/**
 * Initialize an escrow plugin
 * 
 * @param method the escrow method determining the plugin
 * 
 * @return pointer to the escrow plugin API
 */
static const struct GNUNET_ESCROW_KeyPluginFunctions *
init_plugin (const struct GNUNET_ESCROW_Handle *h,
             enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  switch (method)
  {
    case GNUNET_ESCROW_KEY_PLAINTEXT:
      if (GNUNET_YES == plaintext_initialized)
        return plaintext_api;
      plaintext_initialized = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Loading PLAINTEXT escrow plugin\n");
      plaintext_api = GNUNET_PLUGIN_load ("libgnunet_plugin_escrow_plaintext",
                                          (void *)h->cfg);
      return plaintext_api;
    case GNUNET_ESCROW_KEY_GNS:
      if (GNUNET_YES == gns_initialized)
        return gns_api;
      gns_initialized = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Loading GNS escrow plugin\n");
      gns_api = GNUNET_PLUGIN_load ("libgnunet_plugin_escrow_gns",
                                    (void *)h->cfg);
      return gns_api;
    case GNUNET_ESCROW_KEY_ANASTASIS:
      if (GNUNET_YES == anastasis_initialized)
        return anastasis_api;
      anastasis_initialized = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Loading ANASTASIS escrow plugin\n");
      anastasis_api = GNUNET_PLUGIN_load ("libgnunet_plugin_escrow_anastasis",
                                          (void *)h->cfg);
      return anastasis_api;
    case GNUNET_ESCROW_KEY_NONE: // error case
      fprintf (stderr, "incorrect escrow method!");
      return NULL;
  }
  // should never be reached
  return NULL;
}


/**
 * Get a fresh operation id to distinguish between escrow operations
 *
 * @param h the escrow handle
 * 
 * @return next operation id to use
 */
static uint32_t
get_op_id (struct GNUNET_ESCROW_Handle *h)
{
  return h->last_op_id_used++;
}


/**
 * Initialize the escrow component.
 * 
 * @param cfg the configuration to use
 * 
 * @return handle to use
 */
struct GNUNET_ESCROW_Handle *
GNUNET_ESCROW_init (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_ESCROW_Handle *h;

  h = GNUNET_new (struct GNUNET_ESCROW_Handle);
  h->cfg = GNUNET_CONFIGURATION_dup (cfg);
  h->op_head = NULL;
  h->op_tail = NULL;
  return h;
}


/**
 * Unload all loaded plugins on destruction.
 * 
 * @param h the escrow handle
 */
void
GNUNET_ESCROW_fini (struct GNUNET_ESCROW_Handle *h)
{
  struct GNUNET_ESCROW_Operation *op;

  /* unload all loaded plugins */
  if (GNUNET_YES == plaintext_initialized)
  {
    plaintext_initialized = GNUNET_NO;
    GNUNET_break (NULL == 
                  GNUNET_PLUGIN_unload ("libgnunet_plugin_escrow_plaintext",
                                        plaintext_api));
    plaintext_api = NULL;
  }

  if (GNUNET_YES == gns_initialized)
  {
    gns_initialized = GNUNET_NO;
    GNUNET_break (NULL == 
                  GNUNET_PLUGIN_unload ("libgnunet_plugin_escrow_gns",
                                        gns_api));
    gns_api = NULL;
  }

  if (GNUNET_YES == anastasis_initialized)
  {
    anastasis_initialized = GNUNET_NO;
    GNUNET_break (NULL == 
                  GNUNET_PLUGIN_unload ("libgnunet_plugin_escrow_anastasis",
                                        anastasis_api));
    anastasis_api = NULL;
  }

  /* clean up the operation DLL */
  while (NULL != (op = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
    GNUNET_ESCROW_cancel (op);
  }

  /* free the configuration */
  GNUNET_free (h->cfg);

  /* free the escrow handle */
  GNUNET_free (h);
}


static void
handle_start_escrow_result (void *cls)
{
  struct ESCROW_Plugin_AnchorContinuationWrapper *w = cls;
  struct GNUNET_ESCROW_Operation *op;

  for (op = w->h->op_head; NULL != op; op = op->next)
    if (op->id == w->op_id)
      break;

  if (NULL == op)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (w->h->op_head, w->h->op_tail, op);
  if (NULL != op->cb_put)
    op->cb_put (op->cb_cls, w->anchor, w->emsg);
  GNUNET_free (op);
}


/**
 * Put some data in escrow using the specified escrow method
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego to put in escrow
 * @param userSecret the user secret (e.g. for derivation of escrow identities)
 *                   for GNS escrow, this has to be UNIQUE in the whole network!
 * @param method the escrow method to use
 * @param cb function to call with the escrow anchor on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_put (struct GNUNET_ESCROW_Handle *h,
                   struct GNUNET_IDENTITY_Ego *ego,
                   const char *userSecret,
                   enum GNUNET_ESCROW_Key_Escrow_Method method,
                   GNUNET_ESCROW_AnchorContinuation cb,
                   void *cb_cls)
{
  struct GNUNET_ESCROW_Operation *op;
  const struct GNUNET_ESCROW_KeyPluginFunctions *api;

  op = GNUNET_new (struct GNUNET_ESCROW_Operation);
  op->h = h;
  op->id = get_op_id (h);
  op->method = method;
  op->cb_put = cb;
  op->cb_cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);

  api = init_plugin (h, method);
  op->plugin_op_wrap = api->start_key_escrow (h,
                                              ego,
                                              userSecret,
                                              &handle_start_escrow_result,
                                              op->id);

  return op;
}


static void
handle_restore_key_result (void *cls)
{
  struct ESCROW_Plugin_EgoContinuationWrapper *w = cls;
  struct GNUNET_ESCROW_Operation *op;

  for (op = w->h->op_head; NULL != op; op = op->next)
    if (op->id == w->op_id)
      break;

  if (NULL == op)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (w->h->op_head, w->h->op_tail, op);
  if (NULL != op->cb_get)
    op->cb_get (op->cb_cls, w->ego, w->emsg);
  GNUNET_free (op);
}


/**
 * Get the escrowed data back
 * 
 * @param h the handle for the escrow component
 * @param anchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * @param cb function to call with the restored ego on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_get (struct GNUNET_ESCROW_Handle *h,
                   const struct GNUNET_ESCROW_Anchor *anchor,
                   enum GNUNET_ESCROW_Key_Escrow_Method method,
                   GNUNET_ESCROW_EgoContinuation cb,
                   void *cb_cls)
{
  struct GNUNET_ESCROW_Operation *op;
  const struct GNUNET_ESCROW_KeyPluginFunctions *api;

  op = GNUNET_new (struct GNUNET_ESCROW_Operation);
  op->h = h;
  op->id = get_op_id (h);
  op->method = method;
  op->cb_get = cb;
  op->cb_cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);

  api = init_plugin (h, method);
  op->plugin_op_wrap = api->restore_key (h, anchor, &handle_restore_key_result, op->id);

  return op;
}


static void
handle_verify_escrow_result (void *cls)
{
  struct ESCROW_Plugin_VerifyContinuationWrapper *w = cls;
  struct GNUNET_ESCROW_Operation *op;

  for (op = w->h->op_head; NULL != op; op = op->next)
    if (op->id == w->op_id)
      break;

  if (NULL == op)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (w->h->op_head, w->h->op_tail, op);
  if (NULL != op->cb_verify)
    op->cb_verify (op->cb_cls, w->verificationResult, w->emsg);
  GNUNET_free (op);
}


/**
 * Verify the escrowed data
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego that was put into escrow
 * @param anchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * @param cb function to call with the verification result on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_verify (struct GNUNET_ESCROW_Handle *h,
                      struct GNUNET_IDENTITY_Ego *ego,
                      const struct GNUNET_ESCROW_Anchor *anchor,
                      enum GNUNET_ESCROW_Key_Escrow_Method method,
                      GNUNET_ESCROW_VerifyContinuation cb,
                      void *cb_cls)
{
  struct GNUNET_ESCROW_Operation *op;
  const struct GNUNET_ESCROW_KeyPluginFunctions *api;

  op = GNUNET_new (struct GNUNET_ESCROW_Operation);
  op->h = h;
  op->id = get_op_id (h);
  op->method = method;
  op->cb_verify = cb;
  op->cb_cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);

  api = init_plugin (h, method);
  op->plugin_op_wrap = api->verify_key_escrow (h, ego, anchor, &handle_verify_escrow_result, op->id);

  return op;
}


/**
 * Get the status of an escrow, i.e.
 *   -> when the last escrow was
 *   -> when the next escrow is recommended
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego of which the escrow status has to be determined
 * @param method the escrow method to use
 * 
 * @return the status of the escrow packed into a GNUNET_ESCROW_Status struct
 */
struct GNUNET_ESCROW_Status *
GNUNET_ESCROW_get_status (struct GNUNET_ESCROW_Handle *h,
                          struct GNUNET_IDENTITY_Ego *ego,
                          enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  const struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = init_plugin (h, method);
  return api->get_status (h, ego);
}


/**
 * Deserialize an escrow anchor string (e.g. from command line) into a
 * GNUNET_ESCROW_Anchor struct
 * The anchor string is expected to have the following form:
 *    <method>:<egoName>:<anchorData>
 * with <method>, <egoName> and <anchorData> being URL-encoded
 * 
 * 
 * @param anchorString the encoded escrow anchor string
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct,
 *         NULL if we failed to parse the string
 */
struct GNUNET_ESCROW_Anchor *
GNUNET_ESCROW_anchor_string_to_data (const char *anchorString)
{
  struct GNUNET_ESCROW_Anchor *anchor;
  uint32_t data_size;
  char *anchorStringCopy, *ptr;
  char *methodString, *egoNameString, *anchorDataString;
  char delimiter[] = ":";
  
  anchorStringCopy = GNUNET_strdup (anchorString);
  anchor = NULL;

  /* parse and decode method */
  ptr = strtok (anchorStringCopy, delimiter);
  if (NULL == ptr)
    goto END;
  GNUNET_STRINGS_urldecode (ptr, strlen (ptr), &methodString);
  /* parse and decode ego name */
  ptr = strtok (NULL, delimiter);
  if (NULL == ptr)
    goto END;
  GNUNET_STRINGS_urldecode (ptr, strlen (ptr), &egoNameString);
  /* parse and decode anchor data */
  ptr = strtok (NULL, delimiter);
  if (NULL == ptr)
    goto END;
  GNUNET_STRINGS_urldecode (ptr, strlen (ptr), &anchorDataString);
  /* check if string is over */
  ptr = strtok (NULL, delimiter);
  if (NULL != ptr)
    goto END;

  data_size = strlen (anchorDataString); // data is NOT null-terminated
  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor)
                          + data_size
                          + strlen (egoNameString) + 1);
  anchor->size = data_size;
  anchor->method = GNUNET_ESCROW_method_string_to_number (methodString);
  
  // ptr is now used to fill the anchor
  ptr = (char *)&anchor[1];
  strcpy (ptr, anchorDataString);
  ptr += data_size;
  anchor->egoName = ptr;
  strcpy (ptr, egoNameString);

  END:
  /* free all non-NULL strings */
  if (NULL != anchorStringCopy)
    GNUNET_free (anchorStringCopy);
  if (NULL != methodString)
    GNUNET_free (methodString);
  if (NULL != egoNameString)
    GNUNET_free (egoNameString);
  if (NULL != anchorDataString)
    GNUNET_free (anchorDataString);

  return anchor;
}


/**
 * Serialize an escrow anchor (struct GNUNET_ESCROW_Anchor) into a string
 * 
 * @param anchor the escrow anchor struct
 * 
 * @return the encoded escrow anchor string
 */
char *
GNUNET_ESCROW_anchor_data_to_string (const struct GNUNET_ESCROW_Anchor *anchor)
{
  char *anchorString, *ptr;
  const char *methodString, *egoNameString, *anchorData;
  char *methodStringEnc, *egoNameStringEnc, *anchorDataEnc;

  methodString = GNUNET_ESCROW_method_number_to_string (anchor->method);
  GNUNET_STRINGS_urlencode (methodString, strlen (methodString), &methodStringEnc);
  egoNameString = anchor->egoName;
  GNUNET_STRINGS_urlencode (egoNameString, strlen (egoNameString), &egoNameStringEnc);
  anchorData = (const char *)&anchor[1];
  GNUNET_STRINGS_urlencode (anchorData, anchor->size, &anchorDataEnc);

  anchorString = GNUNET_malloc (strlen (methodStringEnc) + 1
                                + strlen (egoNameStringEnc) + 1
                                + strlen (anchorDataEnc)
                                + 1);

  ptr = anchorString;
  GNUNET_memcpy (ptr, methodStringEnc, strlen (methodStringEnc));
  ptr += strlen (methodStringEnc);
  GNUNET_free (methodStringEnc);
  *(ptr++) = ':';
  GNUNET_memcpy (ptr, egoNameStringEnc, strlen (egoNameStringEnc));
  ptr += strlen (egoNameStringEnc);
  GNUNET_free (egoNameStringEnc);
  *(ptr++) = ':';
  GNUNET_memcpy (ptr, anchorDataEnc, strlen (anchorDataEnc));
  ptr += strlen (anchorDataEnc);
  GNUNET_free (anchorDataEnc);
  *(ptr++) = '\0';
  
  return anchorString;
}


/**
 * Convert a method name string to the respective enum number
 * 
 * @param methodString the method name string
 * 
 * @return the enum number
 */
enum GNUNET_ESCROW_Key_Escrow_Method
GNUNET_ESCROW_method_string_to_number (const char *methodString)
{
  if (!strcmp (plaintext_string, methodString))
    return GNUNET_ESCROW_KEY_PLAINTEXT;
  else if (!strcmp (gns_string, methodString))
    return GNUNET_ESCROW_KEY_GNS;
  else if (!strcmp (anastasis_string, methodString))
    return GNUNET_ESCROW_KEY_ANASTASIS;
  else
    return GNUNET_ESCROW_KEY_NONE;
}


/**
 * Convert a method enum number to the respective method string
 * 
 * @param method the method enum number
 * 
 * @return the method string
 */
const char *
GNUNET_ESCROW_method_number_to_string (enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  switch (method)
  {
    case GNUNET_ESCROW_KEY_PLAINTEXT:
      return plaintext_string;
    case GNUNET_ESCROW_KEY_GNS:
      return gns_string;
    case GNUNET_ESCROW_KEY_ANASTASIS:
      return anastasis_string;
    default:
      return none_string;
  }
}


/**
 * Cancel an escrow operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation.
 *
 * @param op operation to cancel
 */
void
GNUNET_ESCROW_cancel (struct GNUNET_ESCROW_Operation *op)
{
  const struct GNUNET_ESCROW_KeyPluginFunctions *api;

  api = init_plugin (op->h, op->method);
  api->cancel_plugin_operation (op->plugin_op_wrap);
  // TODO: check which callback is not NULL?
  op->cb_put = NULL;
  op->cb_verify = NULL;
  op->cb_get = NULL;
  GNUNET_free (op);
}


/* end of escrow_api.c */
