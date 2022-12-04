/*
     This file is part of GNUnet
     Copyright (C) 2010, 2013, 2021 GNUnet e.V.

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
 * @file fs/plugin_block_fs.c
 * @brief blocks used for file-sharing
 * @author Christian Grothoff
 */
#include "platform.h"
#include "platform.h"
#include "gnunet_block_plugin.h"
#include "gnunet_fs_service.h"
#include "block_fs.h"
#include "gnunet_signatures.h"
#include "gnunet_block_group_lib.h"


/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change!
 */
#define BLOOMFILTER_K 16


/**
 * Create a new block group.
 *
 * @param ctx block context in which the block group is created
 * @param type type of the block for which we are creating the group
 * @param raw_data optional serialized prior state of the group, NULL if unavailable/fresh
 * @param raw_data_size number of bytes in @a raw_data, 0 if unavailable/fresh
 * @param va variable arguments specific to @a type
 * @return block group handle, NULL if block groups are not supported
 *         by this @a type of block (this is not an error)
 */
static struct GNUNET_BLOCK_Group *
block_plugin_fs_create_group (void *cls,
                              enum GNUNET_BLOCK_Type type,
                              const void *raw_data,
                              size_t raw_data_size,
                              va_list va)
{
  unsigned int size;
  const char *guard;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
    GNUNET_break (NULL == va_arg (va, const char *));
    return NULL;
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    GNUNET_break (NULL == va_arg (va, const char *));
    return NULL;
  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    guard = va_arg (va, const char *);
    if (0 == strcmp (guard,
                     "seen-set-size"))
    {
      size = GNUNET_BLOCK_GROUP_compute_bloomfilter_size (va_arg (va, unsigned
                                                                  int),
                                                          BLOOMFILTER_K);
    }
    else if (0 == strcmp (guard,
                          "filter-size"))
    {
      size = va_arg (va, unsigned int);
    }
    else
    {
      /* va-args invalid! bad bug, complain! */
      GNUNET_break (0);
      size = 8;
    }
    if (0 == size)
      size = raw_data_size;   /* not for us to determine, use what we got! */
    GNUNET_break (NULL == va_arg (va, const char *));
    return GNUNET_BLOCK_GROUP_bf_create (cls,
                                         size,
                                         BLOOMFILTER_K,
                                         type,
                                         raw_data,
                                         raw_data_size);

  default:
    GNUNET_break (NULL == va_arg (va, const char *));
    GNUNET_break (0);
    return NULL;
  }
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static enum GNUNET_GenericReturnValue
block_plugin_fs_get_key (void *cls,
                         enum GNUNET_BLOCK_Type type,
                         const void *block,
                         size_t block_size,
                         struct GNUNET_HashCode *key)
{
  const struct UBlock *ub;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    GNUNET_CRYPTO_hash (block,
                        block_size,
                        key);
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    if (block_size < sizeof(struct UBlock))
    {
      GNUNET_break_op (0);
      memset (key,
              0,
              sizeof (*key));
      return GNUNET_OK;
    }
    ub = block;
    GNUNET_CRYPTO_hash (&ub->verification_key,
                        sizeof(ub->verification_key),
                        key);
    return GNUNET_OK;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Function called to validate a query.
 *
 * @param cls closure
 * @param type block type
 * @param query original query (hash)
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @return #GNUNET_OK if the query is fine, #GNUNET_NO if not
 */
static enum GNUNET_GenericReturnValue
block_plugin_fs_check_query (void *cls,
                             enum GNUNET_BLOCK_Type type,
                             const struct GNUNET_HashCode *query,
                             const void *xquery,
                             size_t xquery_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    if (0 != xquery_size)
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    return GNUNET_OK;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Function called to validate a block for storage.
 *
 * @param cls closure
 * @param type block type
 * @param block block data to validate
 * @param block_size number of bytes in @a block
 * @return #GNUNET_OK if the block is fine, #GNUNET_NO if not
 */
static enum GNUNET_GenericReturnValue
block_plugin_fs_check_block (void *cls,
                             enum GNUNET_BLOCK_Type type,
                             const void *block,
                             size_t block_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    {
      const struct UBlock *ub;

      if (block_size < sizeof(struct UBlock))
      {
        GNUNET_break_op (0);
        return GNUNET_NO;
      }
      ub = block;
      if (block_size !=
          ntohl (ub->purpose.size)
          + sizeof (struct GNUNET_CRYPTO_EcdsaSignature))
      {
        GNUNET_break_op (0);
        return GNUNET_NO;
      }
      if (GNUNET_OK !=
          GNUNET_CRYPTO_ecdsa_verify_ (GNUNET_SIGNATURE_PURPOSE_FS_UBLOCK,
                                       &ub->purpose,
                                       &ub->signature,
                                       &ub->verification_key))
      {
        GNUNET_break_op (0);
        return GNUNET_NO;
      }
      return GNUNET_OK;
    }
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Function called to validate a reply to a request.  Note that it is assumed
 * that the reply has already been matched to the key (and signatures checked)
 * as it would be done with the GetKeyFunction and the
 * BlockEvaluationFunction.
 *
 * @param cls closure
 * @param type block type
 * @param group which block group to use for evaluation
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_ReplyEvaluationResult
block_plugin_fs_check_reply (void *cls,
                             enum GNUNET_BLOCK_Type type,
                             struct GNUNET_BLOCK_Group *group,
                             const struct GNUNET_HashCode *query,
                             const void *xquery,
                             size_t xquery_size,
                             const void *reply_block,
                             size_t reply_block_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    return GNUNET_BLOCK_REPLY_OK_LAST;
  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    {
      struct GNUNET_HashCode chash;

      GNUNET_CRYPTO_hash (reply_block,
                          reply_block_size,
                          &chash);
      if (GNUNET_YES ==
          GNUNET_BLOCK_GROUP_bf_test_and_set (group,
                                              &chash))
        return GNUNET_BLOCK_REPLY_OK_DUPLICATE;
      return GNUNET_BLOCK_REPLY_OK_MORE;
    }
  default:
    GNUNET_break (0);
    return GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED;
  }
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_fs_init (void *cls)
{
  static const enum GNUNET_BLOCK_Type types[] = {
    GNUNET_BLOCK_TYPE_FS_DBLOCK,
    GNUNET_BLOCK_TYPE_FS_IBLOCK,
    GNUNET_BLOCK_TYPE_FS_UBLOCK,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->get_key = &block_plugin_fs_get_key;
  api->create_group = &block_plugin_fs_create_group;
  api->check_query = &block_plugin_fs_check_query;
  api->check_block = &block_plugin_fs_check_block;
  api->check_reply = &block_plugin_fs_check_reply;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_fs_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_block_fs.c */
