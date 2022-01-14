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
#include "gnunet_identity_service.h"
#include "gnunet_signatures.h"
#include "vc_crypto.h"
#include <inttypes.h>
#include <jansson.h>

/**
 * TODO:
 *   - Do we want actual RDF/LD-PROOFs? (DANGER: A lot of work for parsing/canonicalization)
 *   - Do we want JSON Web Token VCs??
 *   - Specification for ReclaimPresentationSig2022
 *   - Refactor functions (such as pubkey extraction from DID) to library (maybe libgnunetreclaim{did,vc}
 *   - Sanity checks (for verification)
 */

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
value_to_string (void *cls,
                 uint32_t type,
                 const void *data,
                 size_t data_size)
{
  switch (type)
  {
  case GNUNET_RECLAIM_CREDENTIAL_TYPE_VC:
    return GNUNET_strndup (data, data_size);
  // return "A super cool verifiable credential\n";
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
string_to_value (void *cls,
                 uint32_t type,
                 const char *s,
                 void **data,
                 size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;

  switch (type)
  {
  case GNUNET_RECLAIM_CREDENTIAL_TYPE_VC:
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
} vc_cred_name_map[] = { { "VC", GNUNET_RECLAIM_CREDENTIAL_TYPE_VC},
                         { NULL, UINT32_MAX } };

/**
   * Convert a type name to the corresponding number.
   *
   * @param cls closure, unused
   * @param vc_typename name to convert
   * @return corresponding number, UINT32_MAX on error
   */
static uint32_t
vc_typename_to_number (void *cls, const char *vc_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != vc_cred_name_map[i].name) &&
         (0 != strcasecmp (vc_typename, vc_cred_name_map[i].name)))
    i++;
  return vc_cred_name_map[i].number;
}


/**
 * Convert a type number to the corresponding type string (e.g. 1 to "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
vc_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != vc_cred_name_map[i].name) && (type !=
                                                vc_cred_name_map[i].
                                                number))
    i++;
  return vc_cred_name_map[i].name;
}

/**
 *
 * @return
 */
static json_t *
get_json_vc_from_json_vp (json_t *cred)
{
  json_t *vc_array;
  json_t *vc;

  vc_array = json_object_get (cred, "verifiableCredential");

  if (vc_array == NULL)
  {
    printf (
      "The Verifiable Presentation has to contain an Array with Key \"verifiableCredential\"\n");
    return NULL;
  }

  vc = json_array_get (vc_array, 0);

  if (vc == NULL)
  {
    printf (
      "The \"verifiableCredential\" array in the Verifiable Presentation can not be empty\n");
    return NULL;
  }

  return vc;
}


/**
 * @brief Parse a json decoded verifiable credential and return the respective claim value as Attribute
 * @param cred a json decoded verifiable credential
 * @return a list of Attributes in the verifiable credential
 *
 */
static struct GNUNET_RECLAIM_AttributeList *
parse_attributes_from_json_vc (const json_t *cred)
{
  struct GNUNET_RECLAIM_AttributeList *attrs = GNUNET_new (struct
                                                           GNUNET_RECLAIM_AttributeList);

  json_t *subject;
  const char *key;
  json_t *value;
  const char *value_str;

  subject = json_object_get (cred, "credentialSubject");

  if (subject == NULL)
  {
    printf ("The verifiable credential has to contain a subject\n");
    return NULL;
  }

  json_object_foreach (subject, key, value) {
    if (json_is_string (value))
    {
      value_str = json_string_value (value);

      GNUNET_RECLAIM_attribute_list_add (attrs,
                                         key,
                                         NULL,
                                         GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,
                                         value_str,
                                         (strlen (value_str) + 1));
    }
  }

  return attrs;
}


/**
 * Parse a verifiable credential and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
parse_attributes_c (void *cls,
                    const struct GNUNET_RECLAIM_Credential *cred)
{
  struct GNUNET_RECLAIM_AttributeList *attrs;
  json_t *root;

  if (cred->type != GNUNET_RECLAIM_CREDENTIAL_TYPE_VC)
    return NULL;

  root = json_loads (cred->data, JSON_DECODE_ANY, NULL);
  attrs =  parse_attributes_from_json_vc (root);
  json_decref (root);
  return attrs;
}


/**
 * Parse a verifiable presentation and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
vc_parse_attributes_p (void *cls,
                       const struct GNUNET_RECLAIM_Presentation *pres)
{
  struct GNUNET_RECLAIM_AttributeList *attrs;
  json_t *root;
  json_t *cred;
  json_error_t *error;

  if (pres->type != GNUNET_RECLAIM_CREDENTIAL_TYPE_VC)
    return NULL;

  root = json_loads (pres->data, JSON_DECODE_ANY, error);

  if (root == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not decode the verifiable presentation\n");
    return NULL;
  }

  cred = get_json_vc_from_json_vp (root);
  attrs =  parse_attributes_from_json_vc (cred);
  json_decref (root);
  return attrs;
}


/**
 * @brief Return the issuer of the credential
 * @param vc decoded json containing a verifiable credential
 * @return a string containg the issuer
 *
 */
char *
get_issuer_from_json_vc (json_t *vc)
{
  json_t *issuer;
  json_t *issuer_id;
  const char *issuer_id_str;

  issuer = json_object_get (vc, "issuer");

  if (issuer == NULL)
  {
    printf ("The verifiable credential has to contain an issuer\n");
    return NULL;
  }

  issuer_id = json_object_get (issuer, "id");

  if (issuer_id == NULL)
  {
    printf (
      "The issuer object of the verifiable credential has to contain an id\n");
    return NULL;
  }

  issuer_id_str = json_string_value (issuer_id);

  return GNUNET_strndup (issuer_id_str, strlen (issuer_id_str));
}


/**
 * Parse a Verifiable Credential and return the issuer
 * Does not work for URI Issuer. https://www.w3.org/TR/vc-data-model/#issuer
 *
 * @param cls the plugin
 * @param cred the verifiable credential
 * @return a string, containing the isser
 */
char *
get_issuer_c (void *cls,
              const struct GNUNET_RECLAIM_Credential *cred)
{
  json_t *root;
  char *issuer_id_str;

  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_VC != cred->type)
    return NULL;
  root = json_loads (cred->data, JSON_DECODE_ANY, NULL);
  issuer_id_str = get_issuer_from_json_vc (root);
  json_decref (root);
  return issuer_id_str;
}


/**
 * Parse a Verifiable Presentation and return the issuer
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a string, containing the isser
 */
char *
get_issuer_p (void *cls,
              const struct GNUNET_RECLAIM_Presentation *pres)
{
  json_t *root;
  json_t *cred;
  char *issuer_id_str;

  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_VC != pres->type)
    return NULL;
  root = json_loads (pres->data, JSON_DECODE_ANY, NULL);
  cred = get_json_vc_from_json_vp (root);
  issuer_id_str = get_issuer_from_json_vc (cred);
  json_decref (root);
  return issuer_id_str;
}

enum GNUNET_GenericReturnValue
get_expiration_from_json_vc (json_t *cred,
                             struct GNUNET_TIME_Absolute *exp)
{
  json_t *expiration_date_json;
  const char *expiration_date_str;

  expiration_date_json = json_object_get (cred, "issuanceDate");

  if (expiration_date_json == NULL)
    return GNUNET_NO;

  expiration_date_str = json_string_value (expiration_date_json);
  GNUNET_STRINGS_rfc3339_time_to_absolute (expiration_date_str, exp);
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
vc_get_expiration_c (void *cls,
                     const struct GNUNET_RECLAIM_Credential *cred,
                     struct GNUNET_TIME_Absolute *exp)
{
  json_t *root;
  enum GNUNET_GenericReturnValue ret;
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_VC != cred->type)
    return GNUNET_SYSERR;

  root = json_loads (cred->data, JSON_DECODE_ANY, NULL);
  ret = get_expiration_from_json_vc (root, exp);
  json_decref (root);
  return ret;
}


/**
 * Parse a verifiable credential and return the expiration
 *
 * @param cls the plugin
 * @param cred the w3cvc credential
 * @return a string, containing the isser
 */
enum GNUNET_GenericReturnValue
vc_get_expiration_p (void *cls,
                     const struct GNUNET_RECLAIM_Presentation *pres,
                     struct GNUNET_TIME_Absolute *exp)
{
  json_t *root;
  json_t *cred;
  char *issuer_id_str;
  enum GNUNET_GenericReturnValue ret;

  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_VC != pres->type)
    return GNUNET_SYSERR;
  root = json_loads (pres->data, JSON_DECODE_ANY, NULL);
  cred = get_json_vc_from_json_vp (root);
  ret = get_expiration_from_json_vc (cred, exp);
  json_decref (root);
  return ret;
}


enum GNUNET_GenericReturnValue
vc_create_presentation (void *cls,
                        const struct GNUNET_RECLAIM_Credential *cred,
                        const struct GNUNET_RECLAIM_AttributeList *attrs,
                        const struct GNUNET_IDENTITY_PrivateKey *pk,
                        struct GNUNET_RECLAIM_Presentation **presentation)
{
  json_t *root;
  json_t *context_array;
  json_t *credential_array;
  json_t *credential;
  json_t *proof;

  struct GNUNET_IDENTITY_PublicKey *pubk;

  char *pubk_str;
  char *verification_method;
  char *json_str;
  char *presentation_str;
  char *sig;
  const char *now;

  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_VC != cred->type)
    return GNUNET_NO;

  // Get current time
  now = GNUNET_STRINGS_absolute_time_to_rfc3339 (GNUNET_TIME_absolute_get ());

  root = json_object ();

  context_array = json_array ();
  json_array_append_new (context_array, json_string (
                       "https://www.w3.org/2018/credentials/v1"));
  json_object_set_new (root, "@context", context_array);

  json_object_set_new (root, "type", json_string ("VerifiablePresentation"));

  credential_array = json_array ();
  credential = json_loads (cred->data, JSON_DECODE_ANY, NULL);
  if (NULL == credential)
  {
    json_decref (root);
    return GNUNET_SYSERR;
  }
  json_array_append_new (credential_array, credential);
  json_object_set_new (root, "verifiableCredential", credential_array);

  // Generate verification method did key ref from private key
  GNUNET_IDENTITY_key_get_public (pk,
                                  pubk);
  pubk_str = GNUNET_IDENTITY_public_key_to_string (pubk);
  sprintf (verification_method, "did:reclaim:%s#key-1", pubk_str);
  GNUNET_asprintf (&verification_method, "did:reclaim:%s#key-1", pubk_str);
  GNUNET_free (pubk_str);

  proof = json_object ();
  json_object_set_new (proof, "type", json_string ("ReclaimPresentationSig2022"));
  json_object_set_new (proof, "created", json_string (now));
  json_object_set_new (proof, "proofPurpose", json_string ("assertionMethod"));
  json_object_set_new (proof, "verificationMethod", json_string (
                     verification_method));
  json_object_set_new (root, "proof", proof);

  GNUNET_free (verification_method);
  sig = generate_signature_vp (root, pk);
  json_object_set_new (proof, "signature", json_string (sig));

  // Encode JSON and append \0 character
  json_str = json_dumps (root, JSON_INDENT (2));
  if (NULL == json_str)
  {
    json_decref (root);
    return GNUNET_SYSERR;
  }
  *presentation = GNUNET_RECLAIM_presentation_new (
    GNUNET_RECLAIM_CREDENTIAL_TYPE_VC,
    json_str,
    strlen (json_str) + 1);

  GNUNET_free (json_str);
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_reclaim_credential_vc_init (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_RECLAIM_CredentialPluginFunctions);
  api->value_to_string = &value_to_string;
  api->string_to_value = &string_to_value;
  api->typename_to_number = &vc_typename_to_number;
  api->number_to_typename = &vc_number_to_typename;
  api->get_attributes = &parse_attributes_c;
  api->get_issuer = &get_issuer_c;
  api->get_expiration = &vc_get_expiration_c;
  api->value_to_string_p = &value_to_string;
  api->string_to_value_p = &string_to_value;
  api->typename_to_number_p = &vc_typename_to_number;
  api->number_to_typename_p = &vc_number_to_typename;
  api->get_attributes_p = &vc_parse_attributes_p;
  api->get_issuer_p = &get_issuer_p;
  api->get_expiration_p = &vc_get_expiration_p;
  api->create_presentation = &vc_create_presentation;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_credential_vc_done (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_credential_vc.c */
