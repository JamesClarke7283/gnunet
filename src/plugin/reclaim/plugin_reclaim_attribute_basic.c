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
 * @file reclaim-attribute/plugin_reclaim_attribute_gnuid.c
 * @brief reclaim-attribute-plugin-gnuid attribute plugin to provide the API for
 *                                       fundamental
 *                                       attribute types.
 *
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include <inttypes.h>


/**
 * Convert the 'value' of an attribute to a string.
 *
 * @param cls closure, unused
 * @param type type of the attribute
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
static char *
basic_value_to_string (void *cls,
                       uint32_t type,
                       const void *data,
                       size_t data_size)
{
  switch (type)
  {
  case GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING:
    return GNUNET_strndup (data, data_size);

  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of an attribute to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the attribute
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
basic_string_to_value (void *cls,
                       uint32_t type,
                       const char *s,
                       void **data,
                       size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s) + 1;
    return GNUNET_OK;

  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of attribute type numbers to human-readable
 * attribute type names.
 */
static struct
{
  const char *name;
  uint32_t number;
} basic_name_map[] = { { "STRING", GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING },
                       { NULL, UINT32_MAX } };


/**
 * Convert a type name to the corresponding number.
 *
 * @param cls closure, unused
 * @param basic_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
static uint32_t
basic_typename_to_number (void *cls, const char *basic_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != basic_name_map[i].name) &&
         (0 != strcasecmp (basic_typename, basic_name_map[i].name)))
    i++;
  return basic_name_map[i].number;
}


/**
 * Convert a type number to the corresponding type string (e.g. 1 to "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
basic_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != basic_name_map[i].name) && (type != basic_name_map[i].number))
    i++;
  return basic_name_map[i].name;
}

void *
libgnunet_plugin_reclaim_attribute_basic_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_reclaim_attribute_basic_init (void *cls)
{
  struct GNUNET_RECLAIM_AttributePluginFunctions *api;

  api = GNUNET_new (struct GNUNET_RECLAIM_AttributePluginFunctions);
  api->value_to_string = &basic_value_to_string;
  api->string_to_value = &basic_string_to_value;
  api->typename_to_number = &basic_typename_to_number;
  api->number_to_typename = &basic_number_to_typename;
  return api;
}

void *
libgnunet_plugin_reclaim_attribute_basic_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_attribute_basic_done (void *cls)
{
  struct GNUNET_RECLAIM_AttributePluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_attribute_type_gnuid.c */
