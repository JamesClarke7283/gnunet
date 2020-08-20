/*
   This file is part of GNUnet
   Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file reclaim/reclaim_credential.c
 * @brief helper library to manage identity attribute credentials
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include "reclaim_credential.h"


/**
 * Handle for a plugin
 */
struct Plugin
{
  /**
   * Name of the plugin
   */
  char *library_name;

  /**
   * Plugin API
   */
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api;
};


/**
 * Plugins
 */
static struct Plugin **credential_plugins;


/**
 * Number of plugins
 */
static unsigned int num_plugins;


/**
 * Init canary
 */
static int initialized;


/**
 * Add a plugin
 *
 * @param cls closure
 * @param library_name name of the API library
 * @param lib_ret the plugin API pointer
 */
static void
add_plugin (void *cls, const char *library_name, void *lib_ret)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api = lib_ret;
  struct Plugin *plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading credential plugin `%s'\n",
              library_name);
  plugin = GNUNET_new (struct Plugin);
  plugin->api = api;
  plugin->library_name = GNUNET_strdup (library_name);
  GNUNET_array_append (credential_plugins, num_plugins, plugin);
}


/**
 * Load plugins
 */
static void
init ()
{
  if (GNUNET_YES == initialized)
    return;
  initialized = GNUNET_YES;
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_reclaim_credential_",
                          NULL,
                          &add_plugin,
                          NULL);
}


/**
 * Convert an credential type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_credential_typename_to_number (const char *typename)
{
  unsigned int i;
  struct Plugin *plugin;
  uint32_t ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (UINT32_MAX !=
        (ret = plugin->api->typename_to_number (plugin->api->cls,
                                                typename)))
      return ret;
  }
  return UINT32_MAX;
}


/**
 * Convert an credential type number to the corresponding credential type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_credential_number_to_typename (uint32_t type)
{
  unsigned int i;
  struct Plugin *plugin;
  const char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->number_to_typename (plugin->api->cls, type)))
      return ret;
  }
  return NULL;
}


/**
 * Convert human-readable version of a 'claim' of an credential to the binary
 * representation
 *
 * @param type type of the claim
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_RECLAIM_credential_string_to_value (uint32_t type,
                                            const char *s,
                                            void **data,
                                            size_t *data_size)
{
  unsigned int i;
  struct Plugin *plugin;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (GNUNET_OK == plugin->api->string_to_value (plugin->api->cls,
                                                   type,
                                                   s,
                                                   data,
                                                   data_size))
      return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Convert the 'claim' of an credential to a string
 *
 * @param type the type of credential
 * @param data claim in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the claim
 */
char *
GNUNET_RECLAIM_credential_value_to_string (uint32_t type,
                                            const void *data,
                                            size_t data_size)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL != (ret = plugin->api->value_to_string (plugin->api->cls,
                                                     type,
                                                     data,
                                                     data_size)))
      return ret;
  }
  return NULL;
}


/**
   * Create a new credential.
   *
   * @param attr_name the credential name
   * @param type the credential type
   * @param data the credential value
   * @param data_size the credential value size
   * @return the new credential
   */
struct GNUNET_RECLAIM_Credential *
GNUNET_RECLAIM_credential_new (const char *attr_name,
                                uint32_t type,
                                const void *data,
                                size_t data_size)
{
  struct GNUNET_RECLAIM_Credential *attr;
  char *write_ptr;
  char *attr_name_tmp = GNUNET_strdup (attr_name);

  GNUNET_STRINGS_utf8_tolower (attr_name, attr_name_tmp);

  attr = GNUNET_malloc (sizeof(struct GNUNET_RECLAIM_Credential)
                        + strlen (attr_name_tmp) + 1 + data_size);
  attr->type = type;
  attr->data_size = data_size;
  attr->flag = 0;
  write_ptr = (char *) &attr[1];
  GNUNET_memcpy (write_ptr, attr_name_tmp, strlen (attr_name_tmp) + 1);
  attr->name = write_ptr;
  write_ptr += strlen (attr->name) + 1;
  GNUNET_memcpy (write_ptr, data, data_size);
  attr->data = write_ptr;
  GNUNET_free (attr_name_tmp);
  return attr;
}


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_credential_list_serialize_get_size (
  const struct GNUNET_RECLAIM_CredentialList *credentials)
{
  struct GNUNET_RECLAIM_CredentialListEntry *le;
  size_t len = 0;

  for (le = credentials->list_head; NULL != le; le = le->next)
  {
    GNUNET_assert (NULL != le->credential);
    len += GNUNET_RECLAIM_credential_serialize_get_size (le->credential);
    len += sizeof(struct GNUNET_RECLAIM_CredentialListEntry);
  }
  return len;
}


/**
 * Serialize an attribute list
 *
 * @param attrs the attribute list to serialize
 * @param result the serialized attribute
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_credential_list_serialize (
  const struct GNUNET_RECLAIM_CredentialList *credentials,
  char *result)
{
  struct GNUNET_RECLAIM_CredentialListEntry *le;
  size_t len;
  size_t total_len;
  char *write_ptr;
  write_ptr = result;
  total_len = 0;
  for (le = credentials->list_head; NULL != le; le = le->next)
  {
    GNUNET_assert (NULL != le->credential);
    len = GNUNET_RECLAIM_credential_serialize (le->credential, write_ptr);
    total_len += len;
    write_ptr += len;
  }
  return total_len;
}


/**
 * Deserialize an credential list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_CredentialList *
GNUNET_RECLAIM_credential_list_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_CredentialList *al;
  struct GNUNET_RECLAIM_CredentialListEntry *ale;
  size_t att_len;
  const char *read_ptr;

  al = GNUNET_new (struct GNUNET_RECLAIM_CredentialList);

  if ((data_size < sizeof(struct
                          Credential)
       + sizeof(struct GNUNET_RECLAIM_CredentialListEntry)))
    return al;

  read_ptr = data;
  while (((data + data_size) - read_ptr) >= sizeof(struct Credential))
  {
    ale = GNUNET_new (struct GNUNET_RECLAIM_CredentialListEntry);
    ale->credential =
      GNUNET_RECLAIM_credential_deserialize (read_ptr,
                                              data_size - (read_ptr - data));
    if (NULL == ale->credential)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to deserialize malformed credential.\n");
      GNUNET_free (ale);
      return al;
    }
    GNUNET_CONTAINER_DLL_insert (al->list_head, al->list_tail, ale);
    att_len = GNUNET_RECLAIM_credential_serialize_get_size (ale->credential);
    read_ptr += att_len;
  }
  return al;
}


/**
 * Make a (deep) copy of the credential list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_CredentialList *
GNUNET_RECLAIM_credential_list_dup (
  const struct GNUNET_RECLAIM_CredentialList *al)
{
  struct GNUNET_RECLAIM_CredentialListEntry *ale;
  struct GNUNET_RECLAIM_CredentialListEntry *result_ale;
  struct GNUNET_RECLAIM_CredentialList *result;

  result = GNUNET_new (struct GNUNET_RECLAIM_CredentialList);
  for (ale = al->list_head; NULL != ale; ale = ale->next)
  {
    result_ale = GNUNET_new (struct GNUNET_RECLAIM_CredentialListEntry);
    GNUNET_assert (NULL != ale->credential);
    result_ale->credential =
      GNUNET_RECLAIM_credential_new (ale->credential->name,
                                      ale->credential->type,
                                      ale->credential->data,
                                      ale->credential->data_size);
    result_ale->credential->id = ale->credential->id;
    GNUNET_CONTAINER_DLL_insert (result->list_head,
                                 result->list_tail,
                                 result_ale);
  }
  return result;
}


/**
 * Destroy credential list
 *
 * @param attrs list to destroy
 */
void
GNUNET_RECLAIM_credential_list_destroy (
  struct GNUNET_RECLAIM_CredentialList *al)
{
  struct GNUNET_RECLAIM_CredentialListEntry *ale;
  struct GNUNET_RECLAIM_CredentialListEntry *tmp_ale;

  for (ale = al->list_head; NULL != ale;)
  {
    if (NULL != ale->credential)
      GNUNET_free (ale->credential);
    tmp_ale = ale;
    ale = ale->next;
    GNUNET_free (tmp_ale);
  }
  GNUNET_free (al);
}


/**
 * Get required size for serialization buffer
 *
 * @param attr the credential to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_credential_serialize_get_size (
  const struct GNUNET_RECLAIM_Credential *credential)
{
  return sizeof(struct Credential) + strlen (credential->name)
         + credential->data_size;
}


/**
 * Serialize an credential
 *
 * @param attr the credential to serialize
 * @param result the serialized credential
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_credential_serialize (
  const struct GNUNET_RECLAIM_Credential *credential,
  char *result)
{
  size_t data_len_ser;
  size_t name_len;
  struct Credential *atts;
  char *write_ptr;

  atts = (struct Credential *) result;
  atts->credential_type = htons (credential->type);
  atts->credential_flag = htonl (credential->flag);
  atts->credential_id = credential->id;
  name_len = strlen (credential->name);
  atts->name_len = htons (name_len);
  write_ptr = (char *) &atts[1];
  GNUNET_memcpy (write_ptr, credential->name, name_len);
  write_ptr += name_len;
  // TODO plugin-ize
  // data_len_ser = plugin->serialize_attribute_value (attr,
  //                                                  &attr_ser[1]);
  data_len_ser = credential->data_size;
  GNUNET_memcpy (write_ptr, credential->data, credential->data_size);
  atts->data_size = htons (data_len_ser);

  return sizeof(struct Credential) + strlen (credential->name)
         + credential->data_size;
}


/**
 * Deserialize an credential
 *
 * @param data the serialized credential
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_Credential *
GNUNET_RECLAIM_credential_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_Credential *credential;
  struct Credential *atts;
  size_t data_len;
  size_t name_len;
  char *write_ptr;

  if (data_size < sizeof(struct Credential))
    return NULL;

  atts = (struct Credential *) data;
  data_len = ntohs (atts->data_size);
  name_len = ntohs (atts->name_len);
  if (data_size < sizeof(struct Credential) + data_len + name_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Buffer too small to deserialize\n");
    return NULL;
  }
  credential = GNUNET_malloc (sizeof(struct GNUNET_RECLAIM_Credential)
                               + data_len + name_len + 1);
  credential->type = ntohs (atts->credential_type);
  credential->flag = ntohl (atts->credential_flag);
  credential->id = atts->credential_id;
  credential->data_size = data_len;

  write_ptr = (char *) &credential[1];
  GNUNET_memcpy (write_ptr, &atts[1], name_len);
  write_ptr[name_len] = '\0';
  credential->name = write_ptr;

  write_ptr += name_len + 1;
  GNUNET_memcpy (write_ptr, (char *) &atts[1] + name_len,
                 credential->data_size);
  credential->data = write_ptr;
  return credential;
}


struct GNUNET_RECLAIM_AttributeList*
GNUNET_RECLAIM_credential_get_attributes (const struct
                                           GNUNET_RECLAIM_Credential *credential)
{
  unsigned int i;
  struct Plugin *plugin;
  struct GNUNET_RECLAIM_AttributeList *ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->get_attributes (plugin->api->cls,
                                            credential)))
      return ret;
  }
  return NULL;
}


char*
GNUNET_RECLAIM_credential_get_issuer (const struct
                                       GNUNET_RECLAIM_Credential *credential)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->get_issuer (plugin->api->cls,
                                        credential)))
      return ret;
  }
  return NULL;
}


int
GNUNET_RECLAIM_credential_get_expiration (const struct
                                           GNUNET_RECLAIM_Credential *credential,
                                           struct GNUNET_TIME_Absolute*exp)
{
  unsigned int i;
  struct Plugin *plugin;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (GNUNET_OK !=  plugin->api->get_expiration (plugin->api->cls,
                                                   credential,
                                                   exp))
      continue;
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}
