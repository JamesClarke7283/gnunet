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
} pabc_cred_name_map[] = { { "PABC", GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC },
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
  const char *key;
  struct GNUNET_RECLAIM_AttributeList *attrs;
  char *val_str = NULL;
  char *tmp;
  json_t *value;
  json_t *attr;
  json_t *json_attrs;
  json_t *json_root;
  json_error_t *json_err = NULL;

  json_root = json_loads (data, JSON_DECODE_ANY, json_err);
  if ((NULL == json_root) ||
      (!json_is_object (json_root)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s is not a valid pabc credentials (not an object)\n",
                data);
    if (NULL != json_root)
      json_decref (json_root);
    return NULL;
  }
  json_attrs = json_object_get (json_root, "attributes");
  if ((NULL == json_attrs) ||
      (!json_is_array (json_attrs)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s is not a valid pabc credentials (attributes not an array)\n",
                data);
    json_decref (json_root);
    return NULL;
  }

  attrs = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
  for (int i = 0; i < json_array_size (json_attrs); i++)
  {
    attr = json_array_get (json_attrs, i);
    if (!json_is_object(attr))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Found json entry is not an object!\n");
      GNUNET_RECLAIM_attribute_list_destroy (attrs);
      json_decref (json_root);
      return NULL;
    }
    /**
     * This *should* only contain a single pair.
     */
    json_object_foreach (attr, key, value)
    {
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
                                         GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,
                                         tmp,
                                         strlen (tmp));
      GNUNET_free (val_str);
    }
  }
  json_decref (json_root);
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
  char *val_str = NULL;
  char *tmp;
  json_t *json_iss;
  json_t *json_root;
  json_error_t *json_err = NULL;

  json_root = json_loads (data, JSON_DECODE_ANY, json_err);
  if ((NULL == json_root) ||
      (!json_is_object (json_root)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s is not a valid pabc credentials (not an object)\n",
                data);
    if (NULL != json_root)
      json_decref (json_root);
    return NULL;
  }
  json_iss = json_object_get (json_root, "issuer");
  if (NULL == json_iss)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s is not a valid pabc credential (issuer malformed or missing)\n",
                data);
    json_decref (json_root);
    return NULL;
  }
  val_str = json_dumps (json_iss, JSON_ENCODE_ANY);
  tmp = val_str;
  //Remove leading " from jasson conversion
  if (tmp[0] == '"')
    tmp++;
  //Remove trailing " from jansson conversion
  if (tmp[strlen(tmp)-1] == '"')
    tmp[strlen(tmp)-1] = '\0';
  return tmp;
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
  json_t *json_exp;
  json_t *json_root;
  json_error_t *json_err = NULL;

  json_root = json_loads (data, JSON_DECODE_ANY, json_err);
  if ((NULL == json_root) ||
      (!json_is_object (json_root)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s is not a valid pabc credentials (not an object)\n",
                data);
    if (NULL != json_root)
      json_decref (json_root);
    return GNUNET_SYSERR;
  }
  json_exp = json_object_get (json_root, "expiration");
  if ((NULL == json_exp) || (! json_is_integer (json_exp)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s is not a valid pabc credential (expiration malformed or missing)\n",
                data);
    json_decref (json_root);
    return GNUNET_SYSERR;
  }
  exp->abs_value_us = json_integer_value (json_exp) * 1000 * 1000;
  json_decref (json_root);
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
                         const struct GNUNET_RECLAIM_Credential *credential,
                         const struct GNUNET_RECLAIM_AttributeList *attrs,
                         struct GNUNET_RECLAIM_Presentation **pres)
{
  struct pabc_context *ctx = NULL;
  struct pabc_user_context *usr_ctx = NULL;
  struct pabc_public_parameters *pp = NULL;
  struct pabc_credential *cred = NULL;
  struct pabc_blinded_proof *proof = NULL;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  enum pabc_status status;

  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC != credential->type)
    return GNUNET_NO;


  PABC_ASSERT (pabc_new_ctx (&ctx));
  /**
   * FIXME, how to get pp_name.
   * Ideal would be an API that allows us to load pp by
   * issuer name.
   */
  //status = load_public_parameters (ctx, "issuerXY", &pp);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read public parameters.\n");
    pabc_free_ctx (&ctx);
    return GNUNET_SYSERR;
  }
  //FIXME needs API
  //status = read_usr_ctx (usr_name, pp_name, ctx, pp, &usr_ctx);
  if (PABC_OK != status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read user context.\n");
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }

  status = pabc_new_credential (ctx, pp, &cred);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to allocate credential.\n");
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }

  status = pabc_decode_credential (ctx, pp, cred, credential->data);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to decode credential.\n");
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }

  status = pabc_new_proof (ctx, pp, &proof);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to allocate proof.\n");
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }

  // now we can parse the attributes to disclose and configure the proof
  for (ale = attrs->list_head; NULL != ale; ale = ale->next)
  {
    status = pabc_set_disclosure_by_attribute_name (ctx, pp, proof,
                                                    ale->attribute->name,
                                                    PABC_DISCLOSED, cred);
    if (status != PABC_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to configure proof.\n");
      pabc_free_credential (ctx, pp, &cred);
      pabc_free_user_context (ctx, pp, &usr_ctx);
      pabc_free_public_parameters (ctx, &pp);
      return GNUNET_SYSERR;
    }
  }

  // and finally -> sign the proof
  status = pabc_gen_proof (ctx, usr_ctx, pp, proof, cred);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to sign proof.\n");
    pabc_free_proof (ctx, pp, &proof);
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }
  // print the result
  char *json = NULL;
  pabc_encode_proof (ctx, pp, proof, &json);
  if (PABC_OK != status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to serialize proof.\n");
    pabc_free_proof (ctx, pp, &proof);
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }
  printf ("%s", json);
  // clean up
  *pres = GNUNET_RECLAIM_presentation_new (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC,
                                           json,
                                           strlen (json) + 1);
  PABC_FREE_NULL (json);
  pabc_free_proof (ctx, pp, &proof);
  pabc_free_credential (ctx, pp, &cred);
  pabc_free_user_context (ctx, pp, &usr_ctx);
  pabc_free_public_parameters (ctx, &pp);
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
