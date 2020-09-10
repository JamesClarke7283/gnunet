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
 * @file escrow/plugin_rest_escrow.c
 * @brief GNUnet Escrow REST plugin
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_escrow_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_rest_lib.h"
#include "microhttpd.h"
#include <jansson.h>

/**
 * Escrow Namespace
 */
#define GNUNET_REST_API_NS_ESCROW "/escrow"

/**
 * Escrow Put Namespace
 */
#define GNUNET_REST_API_NS_ESCROW_PUT "/escrow/put"

/**
 * Escrow Get Namespace
 */
#define GNUNET_REST_API_NS_ESCROW_GET "/escrow/get"

/**
 * Escrow Verify Namespace
 */
#define GNUNET_REST_API_NS_ESCROW_VERIFY "/escrow/verify"

/**
 * Escrow Status Namespace
 */
#define GNUNET_REST_API_NS_ESCROW_STATUS "/escrow/status"

/**
 * Error message Unknown Error
 */
#define GNUNET_REST_ESCROW_ERROR_UNKNOWN "Unknown Error"

/**
 * Error message Missing identity name
 */
#define GNUNET_REST_ESCROW_MISSING_NAME "Missing identity name"

/**
 * Error message Missing escrow anchor
 */
#define GNUNET_REST_ESCROW_MISSING_ANCHOR "Missing escrow anchor"

/**
 * Error message Identity not found
 */
#define GNUNET_REST_ESCROW_ID_NOT_FOUND "Identity not found"

/**
 * Error message Method not found
 */
#define GNUNET_REST_ESCROW_METHOD_NOT_FOUND "Method not found"

/**
 * Error message Escrow failed
 */
#define GNUNET_REST_ESCROW_ESCROW_FAILED "Escrow failed"

/**
 * Error message Restoration failed
 */
#define GNUNET_REST_ESCROW_RESTORE_FAILED "Restoration failed"

/**
 * Error message Got invalid status
 */
#define GNUNET_REST_ESCROW_INVALID_STATUS "Got invalid status"

/**
 * Error message No data
 */
#define GNUNET_REST_ERROR_NO_DATA "No data"

/**
 * Error message Data invalid
 */
#define GNUNET_REST_ERROR_DATA_INVALID "Data invalid"

/**
 * Error message Failed to parse anchor
 */
#define GNUNET_REST_ESCROW_ANCHOR_ERROR "Failed to parse anchor"

/**
 * Parameter anchor-data
 */
#define GNUNET_REST_ESCROW_PARAM_ANCHOR_DATA "anchorData"

/**
 * Parameter method
 */
#define GNUNET_REST_ESCROW_PARAM_METHOD "method"

/**
 * Parameter user-secret
 */
#define GNUNET_REST_ESCROW_PARAM_USER_SECRET "userSecret"

/**
 * Parameter pubkey
 */
#define GNUNET_REST_ESCROW_PARAM_PUBKEY "pubkey"

/**
 * Parameter name
 */
#define GNUNET_REST_ESCROW_PARAM_NAME "name"

/**
 * Parameter verification-result
 */
#define GNUNET_REST_ESCROW_PARAM_VERIFICATION_RESULT "verificationResult"

/**
 * Parameter last-method
 */
#define GNUNET_REST_ESCROW_PARAM_LAST_METHOD "lastMethod"

/**
 * Parameter last-successful-verification
 */
#define GNUNET_REST_ESCROW_PARAM_LAST_VERIF "lastSuccessfulVerification"

/**
 * Parameter next-recommended-verification
 */
#define GNUNET_REST_ESCROW_PARAM_NEXT_VERIF "nextRecommendedVerification"

/**
 * State while collecting all egos
 */
#define ID_REST_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ID_REST_STATE_POST_INIT 1

/**
 * The configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * HTTP methods allows for this plugin
 */
static char *allow_methods;

/**
 * Ego list
 */
static struct EgoEntry *ego_head;

/**
 * Ego list
 */
static struct EgoEntry *ego_tail;

/**
 * The processing state
 */
static int state;

/**
 * Handle to the identity service
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Handle to the escrow component
 */
static struct GNUNET_ESCROW_Handle *escrow_handle;

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

/**
 * The ego list
 */
struct EgoEntry
{
  /**
   * DLL
   */
  struct EgoEntry *next;

  /**
   * DLL
   */
  struct EgoEntry *prev;

  /**
   * Ego Identifier
   */
  char *identifier;

  /**
   * Public key string
   */
  char *keystring;

  /**
   * The Ego
   */
  struct GNUNET_IDENTITY_Ego *ego;
};

/**
 * The request handle
 */
struct RequestHandle
{
  /**
   * DLL
   */
  struct RequestHandle *next;

  /**
   * DLL
   */
  struct RequestHandle *prev;

  /**
   * The data from the REST request
   */
  const char *data;

  /**
   * The name to look up
   */
  char *name;

  /**
   * the length of the REST data
   */
  size_t data_size;

  /**
   * ESCROW Operation
   */
  struct GNUNET_ESCROW_Operation *op;

  /**
   * Rest connection
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * The url
   */
  char *url;

  /**
   * Error response message
   */
  char *emsg;

  /**
   * Response code
   */
  int response_code;

  /**
   * Response object
   */
  json_t *resp_object;
};

/**
 * DLL
 */
static struct RequestHandle *requests_head;

/**
 * DLL
 */
static struct RequestHandle *requests_tail;

/**
 * Cleanup lookup handle
 * @param handle Handle to clean up
 */
static void
cleanup_handle (void *cls)
{
  struct RequestHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
    handle->timeout_task = NULL;
  }

  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);
  if (NULL != handle->name)
    GNUNET_free (handle->name);
  GNUNET_CONTAINER_DLL_remove (requests_head,
                               requests_tail,
                               handle);
  GNUNET_free (handle);
}


/**
 * Task run on errors.  Reports an error and cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  json_t *json_error = json_object ();
  char *response;

  if (NULL == handle->emsg)
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_ERROR_UNKNOWN);

  json_object_set_new (json_error, "error", json_string (handle->emsg));

  if (0 == handle->response_code)
    handle->response_code = MHD_HTTP_OK;
  response = json_dumps (json_error, 0);
  resp = GNUNET_REST_create_response (response);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, handle->response_code);
  json_decref (json_error);
  GNUNET_free (response);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


static enum GNUNET_ESCROW_Key_Escrow_Method
determine_escrow_method (struct GNUNET_CONTAINER_MultiHashMap *url_param_map)
{
  struct GNUNET_HashCode method_key;
  char *method_string;
  enum GNUNET_ESCROW_Key_Escrow_Method method;

  GNUNET_CRYPTO_hash ("method", strlen ("method"), &method_key);
  method_string = GNUNET_CONTAINER_multihashmap_get (url_param_map,
                                                     &method_key);
  // default method is plaintext
  if (NULL == method_string)
    method = GNUNET_ESCROW_KEY_PLAINTEXT;
  else
    method = GNUNET_ESCROW_method_string_to_number (method_string);

  return method;
}


static char *
get_user_secret_from_payload (struct RequestHandle *handle)
{
  json_t *json_data;
  json_error_t err;
  char *user_secret, *user_secret_cpy;
  int json_unpack_state;
  char term_data[handle->data_size + 1];

  if (0 >= handle->data_size)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return NULL;
  }

  term_data[handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->data, handle->data_size);
  json_data = json_loads (term_data, JSON_DECODE_ANY, &err);
  if (NULL == json_data)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (json_data);
    return NULL;
  }

  json_unpack_state = 0;
  json_unpack_state =
    json_unpack (json_data, "{s:s}",
                 GNUNET_REST_ESCROW_PARAM_USER_SECRET, &user_secret);
  if (0 != json_unpack_state)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (json_data);
    return NULL;
  }

  if (NULL == user_secret)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (json_data);
    return NULL;
  }
  if (0 >= strlen (user_secret))
  {
    json_decref (json_data);
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return NULL;
  }

  user_secret_cpy = GNUNET_strdup (user_secret);
  json_decref (json_data);

  return user_secret_cpy;
}


static void
escrow_finished (void *cls,
                 struct GNUNET_ESCROW_Anchor *anchor,
                 const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  json_t *json_anchor;
  const char*anchor_data;
  char *anchor_data_enc, *result_string;

  if (NULL == anchor)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to escrow ego.\n");
    handle->response_code = MHD_HTTP_NO_CONTENT;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_ESCROW_FAILED);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  json_anchor = json_object ();
  json_object_set_new (json_anchor,
                       GNUNET_REST_ESCROW_PARAM_METHOD,
                       json_string (GNUNET_ESCROW_method_number_to_string (
                         anchor->method)));
  json_object_set_new (json_anchor,
                       GNUNET_REST_ESCROW_PARAM_NAME,
                       json_string (anchor->egoName));
  anchor_data = (const char *)&anchor[1];
  GNUNET_STRINGS_urlencode (anchor_data, anchor->size, &anchor_data_enc);
  json_object_set_new (json_anchor,
                       GNUNET_REST_ESCROW_PARAM_ANCHOR_DATA,
                       json_string (anchor_data_enc));

  result_string = json_dumps (json_anchor, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_string);
  resp = GNUNET_REST_create_response (result_string);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  
  json_decref (json_anchor);
  GNUNET_free (result_string);
  GNUNET_free (anchor_data_enc);

  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Respond to PUT (start_escrow) request
 * 
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
escrow_identity (struct GNUNET_REST_RequestHandle *con_handle,
                 const char *url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *identity, *userSecret;
  enum GNUNET_ESCROW_Key_Escrow_Method method;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Putting %s into escrow.\n",
              handle->url);

  if (strlen (GNUNET_REST_API_NS_ESCROW_PUT) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_MISSING_NAME);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_ESCROW_PUT) + 1;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;

  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Identity %s not found.\n",
                identity);
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_ID_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /* determine method */
  method = determine_escrow_method (handle->rest_handle->url_param_map);
  if (GNUNET_ESCROW_KEY_NONE == method)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Method not found.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_METHOD_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /* get user secret */
  if (GNUNET_ESCROW_KEY_PLAINTEXT != method)
  {
    userSecret = get_user_secret_from_payload (handle);
    if (NULL == userSecret)
      // get_user_secret_from_payload () already cleaned up
      return;
  }
  else
    userSecret = NULL;

  handle->op = GNUNET_ESCROW_put (escrow_handle,
                                  ego_entry->ego,
                                  userSecret,
                                  method,
                                  &escrow_finished,
                                  handle);

  if (NULL != userSecret)
    GNUNET_free (userSecret);
}


static struct GNUNET_ESCROW_Anchor *
build_anchor (const char *method_string,
              const char *ego_name,
              const char *anchor_data_enc)
{
  struct GNUNET_ESCROW_Anchor *anchor;
  char *ptr;
  enum GNUNET_ESCROW_Key_Escrow_Method method;
  char *anchor_data;

  method = GNUNET_ESCROW_method_string_to_number (method_string);
  if (GNUNET_ESCROW_KEY_NONE == method)
    return NULL;
  GNUNET_STRINGS_urldecode (anchor_data_enc,
                            strlen (anchor_data_enc),
                            &anchor_data);

  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor)
                          + strlen (anchor_data)
                          + strlen (ego_name) + 1);
  anchor->method = method;
  anchor->size = strlen (anchor_data);
  ptr = (char *)&anchor[1];
  GNUNET_memcpy (ptr, anchor_data, strlen (anchor_data));
  ptr += strlen (anchor_data);
  anchor->egoName = ptr;
  strcpy (ptr, ego_name);

  GNUNET_free (anchor_data);

  return anchor;
}


static struct GNUNET_ESCROW_Anchor *
get_anchor_from_payload (struct RequestHandle *handle)
{
  json_t *json_data;
  json_error_t err;
  char *method, *ego_name, *anchor_data_enc;
  int json_unpack_state;
  char term_data[handle->data_size + 1];
  struct GNUNET_ESCROW_Anchor *anchor;

  if (0 >= handle->data_size)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return NULL;
  }

  term_data[handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->data, handle->data_size);
  json_data = json_loads (term_data, JSON_DECODE_ANY, &err);
  if (NULL == json_data)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (json_data);
    return NULL;
  }

  json_unpack_state = 0;
  json_unpack_state =
    json_unpack (json_data, "{s:s, s:s, s:s}",
                 GNUNET_REST_ESCROW_PARAM_METHOD, &method,
                 GNUNET_REST_ESCROW_PARAM_NAME, &ego_name,
                 GNUNET_REST_ESCROW_PARAM_ANCHOR_DATA, &anchor_data_enc);
  if (0 != json_unpack_state)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (json_data);
    return NULL;
  }

  if (NULL == method || NULL == ego_name || NULL == anchor_data_enc)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (json_data);
    return NULL;
  }
  if (0 >= strlen (method) || 0 >= strlen (ego_name) || 0 >= strlen (anchor_data_enc))
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (json_data);
    return NULL;
  }

  anchor = build_anchor (method, ego_name, anchor_data_enc);
  if (NULL == anchor)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to parse anchor.\n");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_ANCHOR_ERROR);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (json_data);
    return NULL;
  }

  json_decref (json_data);

  return anchor;
}


static void
restore_finished (void *cls,
                  struct GNUNET_IDENTITY_Ego *ego,
                  const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct MHD_Response *resp;
  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub;
  json_t *json_ego;
  char *keystring, *result_string;

  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to restore ego.\n");
    handle->response_code = MHD_HTTP_NO_CONTENT;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_RESTORE_FAILED);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  GNUNET_IDENTITY_ego_get_public_key (ego, &ego_pub);
  keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&ego_pub);

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (keystring, ego_entry->keystring))
      break;

  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Identity not found despite successful restoration.\n");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_ID_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_free (keystring);
    return;
  }

  json_ego = json_object ();
  json_object_set_new (json_ego,
                       GNUNET_REST_ESCROW_PARAM_NAME,
                       json_string (ego_entry->identifier));
  json_object_set_new (json_ego,
                       GNUNET_REST_ESCROW_PARAM_PUBKEY,
                       json_string (ego_entry->keystring));

  result_string = json_dumps (json_ego, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_string);
  resp = GNUNET_REST_create_response (result_string);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  
  json_decref (json_ego);
  GNUNET_free (result_string);
  GNUNET_free (keystring);

  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Respond to GET (restore) request
 * 
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
get_escrowed_identity (struct GNUNET_REST_RequestHandle *con_handle,
                       const char *url,
                       void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_ESCROW_Anchor *anchor;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Getting %s from escrow.\n",
              handle->url);

  /* get anchor */
  anchor = get_anchor_from_payload (handle);
  if (NULL == anchor)
    // get_anchor_from_payload () already cleaned up
    return;

  handle->op = GNUNET_ESCROW_get (escrow_handle,
                                  anchor,
                                  &restore_finished,
                                  handle);
}


static void
verify_finished (void *cls,
                 int verificationResult,
                 const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  json_t *json_verif;
  const char *verif_string;
  char *result_string;

  switch (verificationResult)
  {
    case GNUNET_ESCROW_VALID:
      verif_string = "valid";
      break;
    case GNUNET_ESCROW_INVALID:
      verif_string = "invalid";
      break;
    case GNUNET_ESCROW_SHARES_MISSING:
      verif_string = "shares_missing";
      break;
    default:
      verif_string = "unknown";
  }

  json_verif = json_object ();
  json_object_set_new (json_verif,
                       GNUNET_REST_ESCROW_PARAM_VERIFICATION_RESULT,
                       json_string (verif_string));

  result_string = json_dumps (json_verif, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_string);
  resp = GNUNET_REST_create_response (result_string);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  
  json_decref (json_verif);
  GNUNET_free (result_string);

  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Respond to VERIFY request
 * 
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
verify_escrow (struct GNUNET_REST_RequestHandle *con_handle,
               const char *url,
               void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_ESCROW_Anchor *anchor;
  char *identity;
  enum GNUNET_ESCROW_Key_Escrow_Method method;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Verifying escrow of %s.\n",
              handle->url);

  if (strlen (GNUNET_REST_API_NS_ESCROW_VERIFY) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_MISSING_NAME);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_ESCROW_VERIFY) + 1;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;

  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Identity %s not found.\n",
                identity);
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_ID_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /* determine method */
  method = determine_escrow_method (handle->rest_handle->url_param_map);
  if (GNUNET_ESCROW_KEY_NONE == method)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Method not found.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_METHOD_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /* get anchor */
  anchor = get_anchor_from_payload (handle);
  if (NULL == anchor)
    // get_anchor_from_payload () already cleaned up
    return;

  handle->op = GNUNET_ESCROW_verify (escrow_handle,
                                     ego_entry->ego,
                                     anchor,
                                     method,
                                     &verify_finished,
                                     handle);
}


/**
 * Respond to STATUS request
 * 
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
get_escrow_status (struct GNUNET_REST_RequestHandle *con_handle,
                   const char *url,
                   void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_ESCROW_Status *status;
  struct MHD_Response *resp;
  char *identity;
  enum GNUNET_ESCROW_Key_Escrow_Method method;
  json_t *json_status;
  char *result_string;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Getting escrow status of %s.\n",
              handle->url);

  if (strlen (GNUNET_REST_API_NS_ESCROW_STATUS) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_MISSING_NAME);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_ESCROW_STATUS) + 1;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;

  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Identity %s not found.\n",
                identity);
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_ID_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /* determine method */
  method = determine_escrow_method (handle->rest_handle->url_param_map);
  if (GNUNET_ESCROW_KEY_NONE == method)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Method not found.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_METHOD_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  status = GNUNET_ESCROW_get_status (escrow_handle,
                                     ego_entry->ego,
                                     method);

  if (NULL == status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got invalid status.\n");
    handle->response_code = MHD_HTTP_NO_CONTENT;
    handle->emsg = GNUNET_strdup (GNUNET_REST_ESCROW_INVALID_STATUS);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /* create and send response */
  json_status = json_object ();
  if (GNUNET_ESCROW_KEY_NONE == status->last_method)
    json_object_set_new (json_status,
                         GNUNET_REST_ESCROW_PARAM_LAST_METHOD,
                         json_string ("none"));
  else
  {
    json_object_set_new (json_status,
                         GNUNET_REST_ESCROW_PARAM_LAST_METHOD,
                         json_string (
                           GNUNET_ESCROW_method_number_to_string (status->last_method)));
    json_object_set_new (json_status,
                         GNUNET_REST_ESCROW_PARAM_LAST_VERIF,
                         json_string (
                           GNUNET_STRINGS_absolute_time_to_string (
                             status->last_successful_verification_time)));
    json_object_set_new (json_status,
                         GNUNET_REST_ESCROW_PARAM_NEXT_VERIF,
                         json_string (
                           GNUNET_STRINGS_absolute_time_to_string (
                             status->next_recommended_verification_time)));
  }
  
  result_string = json_dumps (json_status, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_string);
  resp = GNUNET_REST_create_response (result_string);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  MHD_add_response_header (resp, "Content-Type", "application/json");

  json_decref (json_status);
  GNUNET_free (result_string);

  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
options_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char *url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  // For now, independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
  return;
}


/**
 * If listing is enabled, prints information about the egos.
 *
 * This function is initially called for all egos and then again
 * whenever a ego's identifier changes or if it is deleted.  At the
 * end of the initial pass over all egos, the function is once called
 * with 'NULL' for 'ego'. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with 'GNUNET_IDENTITY_create' or 'GNUNET_IDENTITY_get',
 * this function is only called ONCE, and 'NULL' being passed in
 * 'ego' does indicate an error (i.e. name is taken or no default
 * value is known).  If 'ego' is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of 'GNUNET_IDENTITY_connect' (if
 * that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) ego but the NEW identifier.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the 'identifier'.  In this case,
 * the 'ego' is henceforth invalid (and the 'ctx' should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
list_ego (void *cls,
          struct GNUNET_IDENTITY_Ego *ego,
          void **ctx,
          const char *identifier)
{
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;

  if ((NULL == ego) && (ID_REST_STATE_INIT == state))
  {
    state = ID_REST_STATE_POST_INIT;
    return;
  }
  if (ID_REST_STATE_INIT == state)
  {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
    ego_entry->keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
    ego_entry->ego = ego;
    ego_entry->identifier = GNUNET_strdup (identifier);
    GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                      ego_tail,
                                      ego_entry);
  }
  /* Ego renamed or added */
  if (identifier != NULL)
  {
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
      {
        /* Rename */
        GNUNET_free (ego_entry->identifier);
        ego_entry->identifier = GNUNET_strdup (identifier);
        break;
      }
    }
    if (NULL == ego_entry)
    {
      /* Add */
      ego_entry = GNUNET_new (struct EgoEntry);
      GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
      ego_entry->keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
      ego_entry->ego = ego;
      ego_entry->identifier = GNUNET_strdup (identifier);
      GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                        ego_tail,
                                        ego_entry);
    }
  }
  else
  {
    /* Delete */
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
        break;
    }
    if (NULL == ego_entry)
      return; /* Not found */

    GNUNET_CONTAINER_DLL_remove (ego_head,
                                 ego_tail,
                                 ego_entry);
    GNUNET_free (ego_entry->identifier);
    GNUNET_free (ego_entry->keystring);
    GNUNET_free (ego_entry);
    return;
  }

}


/**
 * Function processing the REST call
 *
 * @param method HTTP method
 * @param url URL of the HTTP request
 * @param data body of the HTTP request (optional)
 * @param data_size length of the body
 * @param proc callback function for the result
 * @param proc_cls closure for callback function
 * @return GNUNET_OK if request accepted
 */
static enum GNUNET_GenericReturnValue
rest_process_request (struct GNUNET_REST_RequestHandle *rest_handle,
                      GNUNET_REST_ResultProcessor proc,
                      void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] =
  { { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_ESCROW_STATUS, &get_escrow_status },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_ESCROW_VERIFY, &verify_escrow },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_ESCROW_GET, &get_escrowed_identity },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_ESCROW_PUT, &escrow_identity },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_ESCROW, &options_cont },
    GNUNET_REST_HANDLER_END };


  handle->response_code = 0;
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  handle->data = rest_handle->data;
  handle->data_size = rest_handle->data_size;

  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout, &do_error, handle);
  GNUNET_CONTAINER_DLL_insert (requests_head,
                               requests_tail,
                               handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting...\n");
  if (GNUNET_NO ==
      GNUNET_REST_handle_request (handle->rest_handle, handlers, &err, handle))
  {
    cleanup_handle (handle);
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected\n");
  return GNUNET_YES;
}


/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_escrow_init (void *cls)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  cfg = cls;
  if (NULL != plugin.cfg)
    return NULL; /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_ESCROW;
  api->process_request = &rest_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_OPTIONS);
  state = ID_REST_STATE_INIT;
  identity_handle = GNUNET_IDENTITY_connect (cfg, &list_ego, NULL);
  escrow_handle = GNUNET_ESCROW_init (cfg);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Escrow REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_escrow_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;

  plugin->cfg = NULL;
  while (NULL != requests_head)
    cleanup_handle (requests_head);
  if (NULL != escrow_handle)
    GNUNET_ESCROW_fini (escrow_handle);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
  for (ego_entry = ego_head; NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp->identifier);
    GNUNET_free (ego_tmp->keystring);
    GNUNET_free (ego_tmp);
  }

  GNUNET_free (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Escrow REST plugin is finished\n");
  return NULL;
}


/* end of plugin_rest_escrow.c */
