/*
   This file is part of GNUnet.
   Copyright (C) 2020--2024 GNUnet e.V.

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
 * @author Tobias Frisch
 * @file src/messenger/messenger_api_message_kind.c
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#include "messenger_api_message_kind.h"

#include "messenger_api_message.h"

struct GNUNET_MESSENGER_Message*
create_message_join (const struct GNUNET_CRYPTO_PrivateKey *key)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! key)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_JOIN);

  if (! message)
    return NULL;

  GNUNET_CRYPTO_key_get_public (key, &(message->body.join.key));
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_leave (void)
{
  return create_message (GNUNET_MESSENGER_KIND_LEAVE);
}


struct GNUNET_MESSENGER_Message*
create_message_name (const char *name)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! name)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_NAME);

  if (! message)
    return NULL;

  message->body.name.name = GNUNET_strdup (name);
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_key (const struct GNUNET_CRYPTO_PrivateKey *key)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! key)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_KEY);

  if (! message)
    return NULL;

  GNUNET_CRYPTO_key_get_public (key, &(message->body.key.key));
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_id (const struct GNUNET_ShortHashCode *unique_id)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! unique_id)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_ID);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.id.id), unique_id,
    sizeof(struct GNUNET_ShortHashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_request (const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! hash)
    return NULL;

  {
    struct GNUNET_HashCode zero;
    memset (&zero, 0, sizeof(zero));

    if (0 == GNUNET_CRYPTO_hash_cmp (hash, &zero))
      return NULL;
  }

  message = create_message (GNUNET_MESSENGER_KIND_REQUEST);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.request.hash), hash, sizeof(struct
                                                             GNUNET_HashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_delete (const struct GNUNET_HashCode *hash,
                       const struct GNUNET_TIME_Relative delay)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! hash)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_DELETE);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.deletion.hash), hash, sizeof(struct
                                                              GNUNET_HashCode));
  message->body.deletion.delay = GNUNET_TIME_relative_hton (delay);

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_subscribe (const struct GNUNET_ShortHashCode *discourse,
                          const struct GNUNET_TIME_Relative time,
                          uint32_t flags)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! discourse)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_SUBSCRIBE);
  
  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.subscribe.discourse), discourse,
                 sizeof (struct GNUNET_ShortHashCode));
  
  message->body.subscribe.time = GNUNET_TIME_relative_hton (time);
  message->body.subscribe.flags = flags;

  return message;
}
