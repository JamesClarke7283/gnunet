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
 * @file src/messenger/gnunet-service-messenger_message_kind.c
 * @brief GNUnet MESSENGER service
 */

#include "messenger_api_message_kind.h"

#include "messenger_api_message.h"

struct GNUNET_MESSENGER_Message*
create_message_join (const struct GNUNET_CRYPTO_PrivateKey *key)
{
  if (! key)
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_JOIN);

  if (! message)
    return NULL;

  GNUNET_CRYPTO_key_get_public (key, &(message->body.join.key));
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_leave ()
{
  return create_message (GNUNET_MESSENGER_KIND_LEAVE);
}


struct GNUNET_MESSENGER_Message*
create_message_name (const char *name)
{
  if (! name)
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_NAME);

  if (! message)
    return NULL;

  message->body.name.name = GNUNET_strdup (name);
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_key (const struct GNUNET_CRYPTO_PrivateKey *key)
{
  if (! key)
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_KEY);

  if (! message)
    return NULL;

  GNUNET_CRYPTO_key_get_public (key, &(message->body.key.key));
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_id (const struct GNUNET_ShortHashCode *unique_id)
{
  if (! unique_id)
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_ID);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.id.id), unique_id, sizeof(struct
                                                           GNUNET_ShortHashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_request (const struct GNUNET_HashCode *hash)
{
  if (! hash)
    return NULL;

  struct GNUNET_HashCode zero;
  memset (&zero, 0, sizeof(zero));

  if (0 == GNUNET_CRYPTO_hash_cmp (hash, &zero))
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_REQUEST);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.request.hash), hash, sizeof(struct
                                                             GNUNET_HashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_invite (const struct GNUNET_PeerIdentity *door,
                       const struct GNUNET_HashCode *key)
{
  if ((! door) || (! key))
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_INVITE);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.invite.door), door, sizeof(struct
                                                            GNUNET_PeerIdentity));
  GNUNET_memcpy (&(message->body.invite.key), key, sizeof(struct
                                                          GNUNET_HashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_text (const char *text)
{
  if (! text)
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_TEXT);

  if (! message)
    return NULL;

  message->body.text.text = GNUNET_strdup (text);
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_delete (const struct GNUNET_HashCode *hash,
                       const struct GNUNET_TIME_Relative delay)
{
  if (! hash)
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_DELETE);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.deletion.hash), hash, sizeof(struct
                                                              GNUNET_HashCode));
  message->body.deletion.delay = GNUNET_TIME_relative_hton (delay);

  return message;
}

struct GNUNET_MESSENGER_Message*
create_message_ticket (const struct GNUNET_RECLAIM_Identifier *identifier)
{
  if (! identifier)
    return NULL;

  struct GNUNET_MESSENGER_Message *message = create_message (
    GNUNET_MESSENGER_KIND_TICKET);
  
  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.ticket.identifier), identifier, 
    sizeof(struct GNUNET_RECLAIM_Identifier));
  
  return message;
}
