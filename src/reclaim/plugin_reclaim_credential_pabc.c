/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014, 2016 GNUnet e.V.

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
 * @file reclaim/plugin_reclaim_credential_pabc.c
 * @brief reclaim-credential-plugin-pabc attribute plugin to provide the API for
 *                                      pabc credentials.
 *
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include <inttypes.h>
#include <jansson.h>
#include <libpabc/libpabc.h>

/**
   * Convert the 'value' of an credential to a string.
   *
   * @param cls closure, unused
   * @param type type of the credential
   * @param data value in binary encoding
   * @param data_size number of bytes in @a data
   * @return NULL on error, otherwise human-readable representation of the value
   */
static char *
pabc_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  switch (type)
  {
  case GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC:
    return GNUNET_strndup (data, data_size);

  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of an credential to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the credential
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
pabc_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s) + 1;
    return GNUNET_OK;

  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of credential type numbers to human-readable
 * credential type names.
 */
static struct
{
  const char *name;
  uint32_t number;
} pabc_cred_name_map[] = { { "pabc", GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC },
                          { NULL, UINT32_MAX } };

/**
   * Convert a type name to the corresponding number.
   *
   * @param cls closure, unused
   * @param pabc_typename name to convert
   * @return corresponding number, UINT32_MAX on error
   */
static uint32_t
pabc_typename_to_number (void *cls, const char *pabc_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != pabc_cred_name_map[i].name) &&
         (0 != strcasecmp (pabc_typename, pabc_cred_name_map[i].name)))
    i++;
  return pabc_cred_name_map[i].number;
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
pabc_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != pabc_cred_name_map[i].name) && (type !=
                                                 pabc_cred_name_map[i].
                                                 number))
    i++;
  return pabc_cred_name_map[i].name;
}


/**
 * Parse a pabc and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
pabc_parse_attributes (void *cls,
                      const char *data,
                      size_t data_size)
{
  char *pabc_string;
  struct GNUNET_RECLAIM_AttributeList *attrs;
  char delim[] = ".";
  char *val_str = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing pabc attributes.\n");
  char *decoded_pabc;
  char *tmp;
  json_t *json_val;
  json_error_t *json_err = NULL;

  attrs = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);

  pabc_string = GNUNET_strndup (data, data_size);
  const char *pabc_body = strtok (pabc_string, delim);
  pabc_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (pabc_body, strlen (pabc_body),
                                   (void **) &decoded_pabc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decoded pabc: %s\n", decoded_pabc);
  GNUNET_assert (NULL != decoded_pabc);
  json_val = json_loads (decoded_pabc, JSON_DECODE_ANY, json_err);
  GNUNET_free (decoded_pabc);
  const char *key;
  const char *addr_key;
  json_t *value;
  json_t *addr_value;

  json_object_foreach (json_val, key, value) {
    if (0 == strcmp ("iss", key))
      continue;
    if (0 == strcmp ("jti", key))
      continue;
    if (0 == strcmp ("exp", key))
      continue;
    if (0 == strcmp ("iat", key))
      continue;
    if (0 == strcmp ("nbf", key))
      continue;
    if (0 == strcmp ("aud", key))
      continue;
    if (0 == strcmp ("address", key))
    {
      if (!json_is_object(value)) {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "address claim in wrong format!");
        continue;
      }
      json_object_foreach (value, addr_key, addr_value) {
        val_str = json_dumps (addr_value, JSON_ENCODE_ANY);
        tmp = val_str;
        //Remove leading " from jasson conversion
        if (tmp[0] == '"')
          tmp++;
        //Remove trailing " from jansson conversion
        if (tmp[strlen(tmp)-1] == '"')
          tmp[strlen(tmp)-1] = '\0';
        GNUNET_RECLAIM_attribute_list_add (attrs,
                                           addr_key,
                                           NULL,
                                           GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,
                                           tmp,
                                           strlen (val_str));
        GNUNET_free (val_str);
      }
      continue;
    }
    val_str = json_dumps (value, JSON_ENCODE_ANY);
    tmp = val_str;
    //Remove leading " from jasson conversion
    if (tmp[0] == '"')
      tmp++;
    //Remove trailing " from jansson conversion
    if (tmp[strlen(tmp)-1] == '"')
      tmp[strlen(tmp)-1] = '\0';
    GNUNET_RECLAIM_attribute_list_add (attrs,
                                       key,
                                       NULL,
                                       GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,// FIXME
                                       tmp,
                                       strlen (val_str));
    GNUNET_free (val_str);
  }
  json_decref (json_val);
  GNUNET_free (pabc_string);
  return attrs;
}


/**
 * Parse a pabc and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
pabc_parse_attributes_c (void *cls,
                        const struct GNUNET_RECLAIM_Credential *cred)
{
  return pabc_parse_attributes (cls, cred->data, cred->data_size);
}


/**
 * Parse a pabc and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
pabc_parse_attributes_p (void *cls,
                        const struct GNUNET_RECLAIM_Presentation *cred)
{
  return pabc_parse_attributes (cls, cred->data, cred->data_size);
}


/**
 * Parse a pabc and return the issuer
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
char *
pabc_get_issuer (void *cls,
                const char *data,
                size_t data_size)
{
  const char *pabc_body;
  char *pabc_string;
  char delim[] = ".";
  char *issuer = NULL;
  char *decoded_pabc;
  json_t *issuer_json;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing pabc attributes.\n");
  json_t *json_val;
  json_error_t *json_err = NULL;

  pabc_string = GNUNET_strndup (data, data_size);
  pabc_body = strtok (pabc_string, delim);
  pabc_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (pabc_body, strlen (pabc_body),
                                   (void **) &decoded_pabc);
  json_val = json_loads (decoded_pabc, JSON_DECODE_ANY, json_err);
  GNUNET_free (decoded_pabc);
  GNUNET_free (pabc_string);
  if (NULL == json_val)
    return NULL;
  issuer_json = json_object_get (json_val, "iss");
  if ((NULL == issuer_json) || (! json_is_string (issuer_json))) {
    json_decref (json_val);
    return NULL;
  }
  issuer = GNUNET_strdup (json_string_value (issuer_json));
  json_decref (json_val);
  return issuer;
}


/**
 * Parse a pabc and return the issuer
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
char *
pabc_get_issuer_c (void *cls,
                  const struct GNUNET_RECLAIM_Credential *cred)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC != cred->type)
    return NULL;
  return pabc_get_issuer (cls, cred->data, cred->data_size);
}


/**
 * Parse a pabc and return the issuer
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
char *
pabc_get_issuer_p (void *cls,
                  const struct GNUNET_RECLAIM_Presentation *cred)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC != cred->type)
    return NULL;
  return pabc_get_issuer (cls, cred->data, cred->data_size);
}


/**
 * Parse a pabc and return the expiration
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
int
pabc_get_expiration (void *cls,
                    const char *data,
                    size_t data_size,
                    struct GNUNET_TIME_Absolute *exp)
{
  const char *pabc_body;
  char *pabc_string;
  char delim[] = ".";
  char *decoded_pabc;
  json_t *exp_json;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing pabc attributes.\n");
  json_t *json_val;
  json_error_t *json_err = NULL;

  pabc_string = GNUNET_strndup (data, data_size);
  pabc_body = strtok (pabc_string, delim);
  pabc_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (pabc_body, strlen (pabc_body),
                                   (void **) &decoded_pabc);
  json_val = json_loads (decoded_pabc, JSON_DECODE_ANY, json_err);
  GNUNET_free (decoded_pabc);
  GNUNET_free (pabc_string);
  if (NULL == json_val)
    return GNUNET_SYSERR;
  exp_json = json_object_get (json_val, "exp");
  if ((NULL == exp_json) || (! json_is_integer (exp_json))) {
    json_decref (json_val);
    return GNUNET_SYSERR;
  }
  exp->abs_value_us = json_integer_value (exp_json) * 1000 * 1000;
  json_decref (json_val);
  return GNUNET_OK;
}


/**
 * Parse a pabc and return the expiration
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
int
pabc_get_expiration_c (void *cls,
                      const struct GNUNET_RECLAIM_Credential *cred,
                      struct GNUNET_TIME_Absolute *exp)
{
  return pabc_get_expiration (cls, cred->data, cred->data_size, exp);
}


/**
 * Parse a pabc and return the expiration
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
int
pabc_get_expiration_p (void *cls,
                      const struct GNUNET_RECLAIM_Presentation *cred,
                      struct GNUNET_TIME_Absolute *exp)
{
  return pabc_get_expiration (cls, cred->data, cred->data_size, exp);
}


int
pabc_create_presentation (void *cls,
                         const struct GNUNET_RECLAIM_Credential *cred,
                         const struct GNUNET_RECLAIM_AttributeList *attrs,
                         struct GNUNET_RECLAIM_Presentation **pres)
{
  // FIXME sanity checks??
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC != cred->type)
    return GNUNET_NO;
  *pres = GNUNET_RECLAIM_presentation_new (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC,
                                           cred->data,
                                           cred->data_size);
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_reclaim_credential_pabc_init (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api;
  struct pabc_context *ctx;

  if (PABC_OK != pabc_new_ctx (&ctx))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to initialize pabc context\n");
    return NULL;
  }

  api = GNUNET_new (struct GNUNET_RECLAIM_CredentialPluginFunctions);
  api->value_to_string = &pabc_value_to_string;
  api->string_to_value = &pabc_string_to_value;
  api->typename_to_number = &pabc_typename_to_number;
  api->number_to_typename = &pabc_number_to_typename;
  api->get_attributes = &pabc_parse_attributes_c;
  api->get_issuer = &pabc_get_issuer_c;
  api->get_expiration = &pabc_get_expiration_c;
  api->value_to_string_p = &pabc_value_to_string;
  api->string_to_value_p = &pabc_string_to_value;
  api->typename_to_number_p = &pabc_typename_to_number;
  api->number_to_typename_p = &pabc_number_to_typename;
  api->get_attributes_p = &pabc_parse_attributes_p;
  api->get_issuer_p = &pabc_get_issuer_p;
  api->get_expiration_p = &pabc_get_expiration_p;
  api->create_presentation = &pabc_create_presentation;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_credential_pabc_done (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_credential_type_pabc.c */
