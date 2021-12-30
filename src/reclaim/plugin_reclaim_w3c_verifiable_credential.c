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
 * @file reclaim/plugin_reclaim_w3c_verfiable_credential.c
 * @brief reclaim-w3c-verifiable-credential-plugin attribute plugin to provide the API for
 *                                      W3C credentials.
 * @author Tristan Schwieren
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include <inttypes.h>
#include <jansson.h>

/**
   * Convert the 'value' of an verifiable credential to a string.
   *
   * @param cls closure
   * @param type type of the credential
   * @param data value in binary encoding
   * @param data_size number of bytes in @a data
   * @return NULL on error, otherwise human-readable representation of the value
   */
static char *
w3cvc_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  switch (type)
  {
  case GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE:
    return GNUNET_strndup (data, data_size);
    //return "A super cool verifiable credential\n";
  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of an credential to the binary
 * representation.
 *
 * @param cls closure
 * @param type type of the credential
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
w3cvc_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;

  switch (type)
  {
  case GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE:
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
} w3cvc_cred_name_map[] = { { "W3CVC", GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE},
                          { NULL, UINT32_MAX } };

/**
   * Convert a type name to the corresponding number.
   *
   * @param cls closure, unused
   * @param w3cvc_typename name to convert
   * @return corresponding number, UINT32_MAX on error
   */
static uint32_t
w3cvc_typename_to_number (void *cls, const char *w3cvc_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != w3cvc_cred_name_map[i].name) &&
         (0 != strcasecmp (w3cvc_typename, w3cvc_cred_name_map[i].name)))
    i++;
  return w3cvc_cred_name_map[i].number;
}


/**
 * Convert a type number to the corresponding type string (e.g. 1 to "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
w3cvc_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != w3cvc_cred_name_map[i].name) && (type !=
                                                 w3cvc_cred_name_map[i].
                                                 number))
    i++;
  return w3cvc_cred_name_map[i].name;
}


/**
 * Parse a W3C Verifiable Credential and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the W3C Verifiable credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
w3cvc_parse_attributes (void *cls,
                      const char *data,
                      size_t data_size)
{
  struct GNUNET_RECLAIM_AttributeList *attrs = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);

  GNUNET_RECLAIM_attribute_list_add (attrs,
                                     "astring",
                                     NULL,
                                     GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,
                                     data,
                                     strlen(data));

  return attrs;
}


/**
 * Parse a W3C verifiable credential and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
w3cvc_parse_attributes_c (void *cls,
                        const struct GNUNET_RECLAIM_Credential *cred)
{
  if (cred->type != GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE)
    return NULL;
  return w3cvc_parse_attributes (cls, cred->data, cred->data_size);
}


/**
 * Parse a W3C verifiable presentation and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
w3cvc_parse_attributes_p (void *cls,
                        const struct GNUNET_RECLAIM_Presentation *cred)
{
  if (cred->type != GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE)
    return NULL;
  return w3cvc_parse_attributes (cls, cred->data, cred->data_size);
}


/**
 * Parse a VC and return the issuer
 *
 * @param cls the plugin
 * @param cred the verifiable credential
 * @return a string, containing the isser
 */
char *
w3cvc_get_issuer (void *cls,
                const char *data,
                size_t data_size)
{
  return "some cool boi";
}


/**
 * Parse a Verifiable Credential and return the issuer
 *
 * @param cls the plugin
 * @param cred the verifiable credential
 * @return a string, containing the isser
 */
char *
w3cvc_get_issuer_c (void *cls,
                  const struct GNUNET_RECLAIM_Credential *cred)
{
  if (GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE != cred->type)
    return NULL;
  return w3cvc_get_issuer (cls, cred->data, cred->data_size);
}


/**
 * Parse a Verifiable Credential and return the issuer
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a string, containing the isser
 */
char *
w3cvc_get_issuer_p (void *cls,
                  const struct GNUNET_RECLAIM_Presentation *cred)
{
  if (GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE != cred->type)
    return NULL;
  return w3cvc_get_issuer (cls, cred->data, cred->data_size);
}


/**
 * Parse a Verifiable Credential and return the expiration
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a string, containing the expiration
 */
enum GNUNET_GenericReturnValue
w3cvc_get_expiration (void *cls,
                    const char *data,
                    size_t data_size,
                    struct GNUNET_TIME_Absolute *exp)
{
  exp->abs_value_us = UINT64_MAX;
  return GNUNET_OK;
}


/**
 * Parse a Verifiable Credential and return the expiration
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return the expirati
 */
enum GNUNET_GenericReturnValue
w3cvc_get_expiration_c (void *cls,
                      const struct GNUNET_RECLAIM_Credential *cred,
                      struct GNUNET_TIME_Absolute *exp)
{
  if (GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE != cred->type)
    return GNUNET_NO;
  return w3cvc_get_expiration (cls, cred->data, cred->data_size, exp);
}


/**
 * Parse a verifiable credential and return the expiration
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a string, containing the isser
 */
enum GNUNET_GenericReturnValue
w3cvc_get_expiration_p (void *cls,
                      const struct GNUNET_RECLAIM_Presentation *cred,
                      struct GNUNET_TIME_Absolute *exp)
{
  if (GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE  != cred->type)
    return GNUNET_NO;
  return w3cvc_get_expiration (cls, cred->data, cred->data_size, exp);
}


enum GNUNET_GenericReturnValue
w3cvc_create_presentation (void *cls,
                         const struct GNUNET_RECLAIM_Credential *cred,
                         const struct GNUNET_RECLAIM_AttributeList *attrs,
                         struct GNUNET_RECLAIM_Presentation **presentation)
{
  if (GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE != cred->type)
    return GNUNET_NO;
  *presentation = GNUNET_RECLAIM_presentation_new (
    GNUNET_RECLAIM_W3C_VERFIIABLE_CREDENTIAL_TYPE,
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
libgnunet_plugin_reclaim_credential_w3cvc_init (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_RECLAIM_CredentialPluginFunctions);
  api->value_to_string = &w3cvc_value_to_string;
  api->string_to_value = &w3cvc_string_to_value;
  api->typename_to_number = &w3cvc_typename_to_number;
  api->number_to_typename = &w3cvc_number_to_typename;
  api->get_attributes = &w3cvc_parse_attributes_c;
  api->get_issuer = &w3cvc_get_issuer_c;
  api->get_expiration = &w3cvc_get_expiration_c;
  api->value_to_string_p = &w3cvc_value_to_string;
  api->string_to_value_p = &w3cvc_string_to_value;
  api->typename_to_number_p = &w3cvc_typename_to_number;
  api->number_to_typename_p = &w3cvc_number_to_typename;
  api->get_attributes_p = &w3cvc_parse_attributes_p;
  api->get_issuer_p = &w3cvc_get_issuer_p;
  api->get_expiration_p = &w3cvc_get_expiration_p;
  api->create_presentation = &w3cvc_create_presentation;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_credential_w3cvc_done (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_w3c_verifiable_credential_type.c */
