/*
   This file is part of GNUnet
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
 * @file escrow/escrow_plugin.c
 * 
 * @brief helper functions for escrow plugins
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_escrow_plugin.h"


/**
 * Maintains the ego list for an escrow plugin.
 * This function is an implementation of GNUNET_IDENTITY_Callback.
 *
 * It is initially called for all egos and then again
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
 * @param cls plugin handle
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
void
ESCROW_list_ego (void *cls,
                 struct GNUNET_IDENTITY_Ego *ego,
                 void **ctx,
                 const char *identifier)
{
  struct ESCROW_PluginHandle *ph = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;

  // TODO: error when this method is called at cleanup if init is not yet finished
  if ((NULL == ego) && (ESCROW_PLUGIN_STATE_INIT == ph->state))
  {
    ph->state = ESCROW_PLUGIN_STATE_POST_INIT;
    /* call IdentityInitContinuation */
    ph->id_init_cont ();
    return;
  }
  GNUNET_assert (NULL != ego);

  if (ESCROW_PLUGIN_STATE_INIT == ph->state)
  {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
    ego_entry->keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
    ego_entry->ego = ego;
    ego_entry->identifier = GNUNET_strdup (identifier);
    GNUNET_CONTAINER_DLL_insert_tail (ph->ego_head,
                                      ph->ego_tail,
                                      ego_entry);
    return;
  }
  /* Ego renamed or added */
  if (identifier != NULL)
  {
    for (ego_entry = ph->ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
      {
        /* Rename */
        GNUNET_free (ego_entry->identifier);
        ego_entry->identifier = GNUNET_strdup (identifier);
        /* TODO: this handles an edge case when the user restores an ego
           that already exists. In that case, @param ego is the same for the
           new as for the existing ego and this method thinks it is a rename. */
        if (NULL != ph->ego_create_cont)
          ph->ego_create_cont (ego);
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
      GNUNET_CONTAINER_DLL_insert_tail (ph->ego_head,
                                        ph->ego_tail,
                                        ego_entry);
      /* new ego is added to the list, call ego_create_cont if this was
         because of an ESCROW_get operation, i.e. ego_create_cont != NULL */
      if (NULL != ph->ego_create_cont)
        ph->ego_create_cont (ego);
    }
  }
  else
  {
    /* Delete */
    for (ego_entry = ph->ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
        break;
    }
    if (NULL == ego_entry)
      return; /* Not found */

    GNUNET_CONTAINER_DLL_remove (ph->ego_head,
                                 ph->ego_tail,
                                 ego_entry);
    GNUNET_free (ego_entry->identifier);
    GNUNET_free (ego_entry->keystring);
    GNUNET_free (ego_entry);
    return;
  }
}


/**
 * Cleanup the ego list of an escrow plugin.
 * 
 * @param ph handle for the plugin
 */
void
ESCROW_cleanup_ego_list (struct ESCROW_PluginHandle *ph)
{
  struct EgoEntry *ego_entry;

  while (NULL != (ego_entry = ph->ego_head))
  {
    GNUNET_CONTAINER_DLL_remove (ph->ego_head, ph->ego_tail, ego_entry);
    GNUNET_free (ego_entry->identifier);
    GNUNET_free (ego_entry->keystring);
    GNUNET_free (ego_entry);
  }
}


char *
string_to_upper (const char *str)
{
  char *str_upper;
  uint16_t i;

  str_upper = GNUNET_strdup (str);

  for (i = 0; i < strlen(str_upper); i++)
  {
    if (str_upper[i] >= 'a' && str_upper[i] <= 'z')
      str_upper[i] -= 32; // 'a' - 'A' = 32
  }

  return str_upper;
}


/**
 * Update the status of an escrow in the configuration.
 * 
 * @param h handle for the escrow component
 * @param ego the ego of which the escrow status is updated
 * @param plugin_name the name of the used plugin
 * 
 * @return GNUNET_OK on success
 */
int
ESCROW_update_escrow_status (struct GNUNET_ESCROW_Handle *h,
                             struct GNUNET_IDENTITY_Ego *ego,
                             const char *plugin_name)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey *pub;
  char *config_section, *pubkey_string, *config_option, *plugin_name_upper;
  struct GNUNET_TIME_Absolute now, next_escrow;
  struct GNUNET_TIME_Relative escrow_interval;
  char *conf_file;

  pub = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
  GNUNET_IDENTITY_ego_get_public_key (ego, pub);
  pubkey_string = GNUNET_CRYPTO_ecdsa_public_key_to_string (pub);

  // allocate enough space for "escrow-PUBKEY"
  config_section = GNUNET_malloc (7 + strlen (pubkey_string) + 1);
  sprintf (config_section, "escrow-%s", pubkey_string);

  // allocate enough space for "<plugin_name>_INTERVAL"
  config_option = GNUNET_malloc (strlen (plugin_name) + 9 + 1);
  plugin_name_upper = string_to_upper (plugin_name);
  sprintf (config_option, "%s_INTERVAL", plugin_name_upper);

  now = GNUNET_TIME_absolute_get ();
  GNUNET_CONFIGURATION_set_value_number (h->cfg,
                                         config_section,
                                         "LAST_ESCROW_TIME",
                                         (unsigned long long)now.abs_value_us);
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (h->cfg,
                                                        "escrow",
                                                        config_option,
                                                        &escrow_interval))
  {
    fprintf (stderr, "could not find config value for escrow interval\n");
    GNUNET_free (pub);
    GNUNET_free (config_section);
    GNUNET_free (pubkey_string);
    GNUNET_free (config_option);
    GNUNET_free (plugin_name_upper);
    return GNUNET_NO;
  }
  next_escrow = GNUNET_TIME_absolute_add (now, escrow_interval);
  GNUNET_CONFIGURATION_set_value_number (h->cfg,
                                         config_section,
                                         "NEXT_RECOMMENDED_ESCROW_TIME",
                                         (unsigned long long)next_escrow.abs_value_us);

  GNUNET_CONFIGURATION_set_value_string (h->cfg,
                                         config_section,
                                         "ESCROW_METHOD",
                                         plugin_name);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_filename (h->cfg,
                                                          "PATHS",
                                                          "DEFAULTCONFIG",
                                                          &conf_file));
  if (GNUNET_OK != GNUNET_CONFIGURATION_write (h->cfg, conf_file))
  {
    fprintf (stderr, "unable to write config file\n");
    GNUNET_free (pub);
    GNUNET_free (config_section);
    GNUNET_free (pubkey_string);
    GNUNET_free (config_option);
    GNUNET_free (plugin_name_upper);
    GNUNET_free (conf_file);
    return GNUNET_NO;
  }

  GNUNET_free (pub);
  GNUNET_free (config_section);
  GNUNET_free (pubkey_string);
  GNUNET_free (config_option);
  GNUNET_free (plugin_name_upper);
  GNUNET_free (conf_file);

  return GNUNET_OK;
}


/**
 * Get the status of an escrow from the configuration.
 * 
 * @param h handle for the escrow component
 * @param ego the ego of which the escrow status has to be obtained
 * 
 * @return the status of the escrow, packed into a GNUNET_ESCROW_Status struct
 */
struct GNUNET_ESCROW_Status *
ESCROW_get_escrow_status (struct GNUNET_ESCROW_Handle *h,
                          struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_ESCROW_Status *status;
  unsigned long long conf_last_escrow, conf_next_escrow;
  struct GNUNET_CRYPTO_EcdsaPublicKey *pub;
  char *config_section, *pubkey_string, *conf_escrow_method;

  pub = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
  GNUNET_IDENTITY_ego_get_public_key (ego, pub);
  pubkey_string = GNUNET_CRYPTO_ecdsa_public_key_to_string (pub);

  // allocate enough space for "escrow-PUBKEY"
  config_section = GNUNET_malloc (7 + strlen (pubkey_string) + 1);
  sprintf (config_section, "escrow-%s", pubkey_string);
  
  status = GNUNET_new (struct GNUNET_ESCROW_Status);
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (h->cfg,
                                                          config_section,
                                                          "LAST_ESCROW_TIME",
                                                          &conf_last_escrow))
  {
    // TODO: is that the behavior when the section is not defined?
    status->last_escrow_time = GNUNET_TIME_absolute_get_zero_();
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (h->cfg,
                                                          config_section,
                                                          "NEXT_RECOMMENDED_ESCROW_TIME",
                                                          &conf_next_escrow))
  {
    // TODO: is that the behavior when the section is not defined?
    status->next_recommended_escrow_time = GNUNET_TIME_absolute_get ();
  }
  status->last_method = GNUNET_ESCROW_KEY_NONE;
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (h->cfg,
                                                          config_section,
                                                          "ESCROW_METHOD",
                                                          &conf_escrow_method))
  {
    // TODO: error handling?
  }
  status->last_escrow_time.abs_value_us = (uint64_t)conf_last_escrow;
  status->next_recommended_escrow_time.abs_value_us = (uint64_t)conf_next_escrow;
  if (NULL != conf_escrow_method)
  {
    if (NULL != conf_escrow_method && 0 == strcmp (conf_escrow_method, "plaintext"))
      status->last_method = GNUNET_ESCROW_KEY_PLAINTEXT;
    else if (0 == strcmp (conf_escrow_method, "gns"))
      status->last_method = GNUNET_ESCROW_KEY_GNS;
    else if (0 == strcmp (conf_escrow_method, "anastasis"))
      status->last_method = GNUNET_ESCROW_KEY_ANASTASIS;
    else
      status->last_method = GNUNET_ESCROW_KEY_NONE;
  }
  

  GNUNET_free (config_section);
  GNUNET_free (pubkey_string);
  GNUNET_free (pub);
  GNUNET_free (conf_escrow_method);
  
  return status;
}


/**
 * Deserialize an escrow anchor string into a GNUNET_ESCROW_Anchor struct
 * 
 * @param anchorString the encoded escrow anchor string
 * @param method the escrow plugin calling this function
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct,
 *         NULL if we failed to parse the string
 */
struct GNUNET_ESCROW_Anchor *
ESCROW_anchor_string_to_data (char *anchorString,
                              enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  struct GNUNET_ESCROW_Anchor *anchor;
  uint32_t data_size;
  char *anchorStringCopy, *ptr, *egoNameCopy;
  char delimiter[] = ":";
  
  anchorStringCopy = GNUNET_strdup (anchorString);

  // split the string at the first occurrence of the delimiter
  ptr = strtok (anchorStringCopy, delimiter);
  egoNameCopy = GNUNET_strdup (ptr);
  ptr = strtok (NULL, delimiter);

  if (NULL == ptr)
  {
    // delimiter was not found
    GNUNET_free (egoNameCopy);
    GNUNET_free (anchorStringCopy);
    return NULL;
  }

  data_size = strlen (ptr) + 1;
  anchor = GNUNET_malloc (sizeof (struct GNUNET_ESCROW_Anchor) + data_size);
  anchor->size = data_size;
  anchor->egoName = egoNameCopy;
  anchor->method = method;
  
  // TODO: deserialize?
  GNUNET_memcpy (&anchor[1], ptr, data_size);

  GNUNET_free (anchorStringCopy);

  return anchor;
}


/**
 * Serialize an escrow anchor struct into a string
 * 
 * @param escrowAnchor the escrow anchor struct
 * @param method the escrow plugin calling this function
 * 
 * @return the encoded escrow anchor string
 */
char *
ESCROW_anchor_data_to_string (struct GNUNET_ESCROW_Anchor *escrowAnchor,
                              enum GNUNET_ESCROW_Key_Escrow_Method method)
{
  char *anchorString;
  size_t egoNameSize;

  egoNameSize = strlen (escrowAnchor->egoName);

  anchorString = GNUNET_malloc (egoNameSize + 1 + escrowAnchor->size);
  GNUNET_memcpy (anchorString, escrowAnchor->egoName, egoNameSize);
  anchorString[egoNameSize] = ':';
  GNUNET_memcpy (anchorString + egoNameSize + 1, &escrowAnchor[1], escrowAnchor->size);

  return anchorString;
}


/* end of escrow_plugin.c */
