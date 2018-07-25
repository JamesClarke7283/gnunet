/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

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
*/

/**
 * @file gnsrecord/gnsrecord.c
 * @brief API to access GNS record data
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gnsrecord_plugin.h"
#include "gnunet_json_lib.h"
#include "gnunet_tun_lib.h"
#include <jansson.h>


#define LOG(kind,...) GNUNET_log_from (kind, "gnsrecord",__VA_ARGS__)


/**
 * Handle for a plugin.
 */
struct Plugin
{
  /**
   * Name of the shared library.
   */
  char *library_name;

  /**
   * Plugin API.
   */
  struct GNUNET_GNSRECORD_PluginFunctions *api;
};


/**
 * Array of our plugins.
 */
static struct Plugin **gns_plugins;

/**
 * Size of the 'plugins' array.
 */
static unsigned int num_plugins;

/**
 * Global to mark if we've run the initialization.
 */
static int once;


/**
 * Add a plugin to the list managed by the block library.
 *
 * @param cls NULL
 * @param library_name name of the plugin
 * @param lib_ret the plugin API
 */
static void
add_plugin (void *cls,
	    const char *library_name,
	    void *lib_ret)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = lib_ret;
  struct Plugin *plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Loading block plugin `%s'\n",
              library_name);
  plugin = GNUNET_new (struct Plugin);
  plugin->api = api;
  plugin->library_name = GNUNET_strdup (library_name);
  GNUNET_array_append (gns_plugins, num_plugins, plugin);
}


/**
 * Loads all plugins (lazy initialization).
 */
static void
init ()
{
  if (1 == once)
    return;
  once = 1;
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_gnsrecord_", NULL,
                          &add_plugin, NULL);
}


/**
 * Dual function to #init().
 */
void __attribute__ ((destructor))
GNSRECORD_fini ()
{
  struct Plugin *plugin;

  for (unsigned int i = 0; i < num_plugins; i++)
  {
    plugin = gns_plugins[i];
    GNUNET_break (NULL ==
                  GNUNET_PLUGIN_unload (plugin->library_name,
                                        plugin->api));
    GNUNET_free (plugin->library_name);
    GNUNET_free (plugin);
  }
  GNUNET_free_non_null (gns_plugins);
  gns_plugins = NULL;
  once = 0;
  num_plugins = 0;
}


/**
 * Convert the 'value' of a record to a string.
 *
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
char *
GNUNET_GNSRECORD_value_to_string (uint32_t type,
				  const void *data,
				  size_t data_size)
{
  struct Plugin *plugin;
  char *ret;

  init ();
  for (unsigned int i = 0; i < num_plugins; i++)
  {
    plugin = gns_plugins[i];
    if (NULL != (ret = plugin->api->value_to_string (plugin->api->cls,
                                                     type,
                                                     data,
                                                     data_size)))
      return ret;
  }
  return NULL;
}


/**
 * Convert human-readable version of a 'value' of a record to the binary
 * representation.
 *
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_GNSRECORD_string_to_value (uint32_t type,
				  const char *s,
				  void **data,
				  size_t *data_size)
{
  struct Plugin *plugin;

  init ();
  for (unsigned int i = 0; i < num_plugins; i++)
  {
    plugin = gns_plugins[i];
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
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_GNSRECORD_typename_to_number (const char *dns_typename)
{
  struct Plugin *plugin;
  uint32_t ret;

  if (0 == strcasecmp (dns_typename,
                       "ANY"))
    return GNUNET_GNSRECORD_TYPE_ANY;
  init ();
  for (unsigned int i = 0; i < num_plugins; i++)
  {
    plugin = gns_plugins[i];
    if (UINT32_MAX != (ret = plugin->api->typename_to_number (plugin->api->cls,
                                                              dns_typename)))
      return ret;
  }
  return UINT32_MAX;
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_GNSRECORD_number_to_typename (uint32_t type)
{
  struct Plugin *plugin;
  const char * ret;

  if (GNUNET_GNSRECORD_TYPE_ANY == type)
    return "ANY";
  init ();
  for (unsigned int i = 0; i < num_plugins; i++)
  {
    plugin = gns_plugins[i];
    if (NULL != (ret = plugin->api->number_to_typename (plugin->api->cls,
                                                        type)))
      return ret;
  }
  return NULL;
}

/**
 * Parse given JSON object to gns record
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_gnsrecordobject (void *cls,
		       json_t *root,
		       struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_GNSRECORD_Data *gnsrecord_object;
  struct GNUNET_TIME_Absolute abs_expiration_time;
  int unpack_state=0;
  const char *data;
  const char *expiration_date;
  const char *record_type;
  const char *dummy_value;
  int flag;
  void *rdata;
  size_t rdata_size;

  if(!json_is_object(root))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Error json is not array nor object!\n");
    return GNUNET_SYSERR;
  }
  //interpret single gns record
  unpack_state = json_unpack(root,
			     "{s:s, s:s, s:s, s?:i, s:s!}",
			     "value", &data,
			     "type", &record_type,
			     "expiration_time", &expiration_date,
			     "flag", &flag,
			     "label", &dummy_value);
  GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
	     "{value:%s, type:%s, expire:%s, flag:%i}",
	     data,
	     record_type,
	     expiration_date,
	     flag);
  if (GNUNET_SYSERR == unpack_state)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
	       "Error json object has a wrong format!\n");
    return GNUNET_SYSERR;
  }
  //TODO test
  gnsrecord_object = GNUNET_new (struct GNUNET_GNSRECORD_Data);
  gnsrecord_object->record_type = GNUNET_GNSRECORD_typename_to_number(record_type);
  if (GNUNET_OK
      != GNUNET_GNSRECORD_string_to_value (gnsrecord_object->record_type,
					   data, &rdata,
					   &rdata_size))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,"Value invalid for record type");
    return GNUNET_SYSERR;
  }
  gnsrecord_object->data = rdata;
  gnsrecord_object->data_size = rdata_size;

  if (0 == strcmp (expiration_date, "never"))
  {
    gnsrecord_object->expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  }
  else if (GNUNET_OK
      == GNUNET_STRINGS_fancy_time_to_absolute (expiration_date,
						&abs_expiration_time))
  {
    gnsrecord_object->expiration_time = abs_expiration_time.abs_value_us;
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Value invalid for record type");
    return GNUNET_SYSERR;
  }
  gnsrecord_object->flags = (enum GNUNET_GNSRECORD_Flags)flag;
  *(struct GNUNET_GNSRECORD_Data **) spec->ptr = gnsrecord_object;
  return GNUNET_OK;
}

/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_gnsrecordobject (void *cls, struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_GNSRECORD_Data **gnsrecord_object;
  gnsrecord_object = (struct GNUNET_GNSRECORD_Data **) spec->ptr;
  if (NULL != *gnsrecord_object)
  {
    if (NULL != (*gnsrecord_object)->data)
      GNUNET_free((char*)(*gnsrecord_object)->data);
    GNUNET_free(*gnsrecord_object);
    *gnsrecord_object = NULL;
  }
}

/**
 * JSON Specification for GNS Records.
 *
 * @param gnsrecord_object struct of GNUNET_GNSRECORD_Data to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_gnsrecord_data (struct GNUNET_GNSRECORD_Data **gnsrecord_object)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_gnsrecordobject,
    .cleaner = &clean_gnsrecordobject,
    .cls = NULL,
    .field = NULL,
    .ptr = gnsrecord_object,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *gnsrecord_object = NULL;
  return ret;
}

/* end of gnsrecord.c */
