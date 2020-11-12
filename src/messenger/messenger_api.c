/*
   This file is part of GNUnet.
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
 * @author Tobias Frisch
 * @file src/messenger/messenger_api.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "gnunet_messenger_service.h"

#include "gnunet-service-messenger.h"

#include "messenger_api_handle.h"
#include "messenger_api_message.h"

const char*
GNUNET_MESSENGER_name_of_kind (enum GNUNET_MESSENGER_MessageKind kind)
{
  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    return "INFO";
  case GNUNET_MESSENGER_KIND_JOIN:
    return "JOIN";
  case GNUNET_MESSENGER_KIND_LEAVE:
    return "LEAVE";
  case GNUNET_MESSENGER_KIND_NAME:
    return "NAME";
  case GNUNET_MESSENGER_KIND_KEY:
    return "KEY";
  case GNUNET_MESSENGER_KIND_PEER:
    return "PEER";
  case GNUNET_MESSENGER_KIND_ID:
    return "ID";
  case GNUNET_MESSENGER_KIND_MISS:
    return "MISS";
  case GNUNET_MESSENGER_KIND_MERGE:
    return "MERGE";
  case GNUNET_MESSENGER_KIND_REQUEST:
    return "REQUEST";
  case GNUNET_MESSENGER_KIND_INVITE:
    return "INVITE";
  case GNUNET_MESSENGER_KIND_TEXT:
    return "TEXT";
  case GNUNET_MESSENGER_KIND_FILE:
    return "FILE";
  default:
    return "UNKNOWN";
  }
}

static int
check_get_name (void *cls, const struct GNUNET_MESSENGER_NameMessage *msg)
{
  GNUNET_MQ_check_zero_termination(msg);
  return GNUNET_OK;
}

static void
handle_get_name (void *cls, const struct GNUNET_MESSENGER_NameMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  const char *name = ((const char*) msg) + sizeof(*msg);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Set name of handle: %s\n", name);

  set_handle_name (handle, strlen(name) > 0? name : NULL);
}

static void
handle_get_key (void *cls, const struct GNUNET_MESSENGER_KeyMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  const struct GNUNET_IDENTITY_PublicKey *pubkey = &(msg->pubkey);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Set key of handle: %s\n", GNUNET_IDENTITY_public_key_to_string (pubkey));

  set_handle_key (handle, pubkey);

  if (handle->identity_callback)
    handle->identity_callback (handle->identity_cls, handle);
}

static void
handle_member_id (void *cls, const struct GNUNET_MESSENGER_MemberMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  const struct GNUNET_HashCode *key = &(msg->key);
  const struct GNUNET_ShortHashCode *id = &(msg->id);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Set id of handle in room: %s\n", GNUNET_h2s (key));

  struct GNUNET_MESSENGER_Room *room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (room)
  {
    if (!room->contact_id)
      room->contact_id = GNUNET_new(struct GNUNET_ShortHashCode);

    GNUNET_memcpy(room->contact_id, id, sizeof(*id));
  }
}

static void
handle_room_open (void *cls, const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  const struct GNUNET_HashCode *key = &(msg->key);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Opened room: %s\n", GNUNET_h2s (key));

  open_handle_room (handle, key);
}

static void
handle_room_entry (void *cls, const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  const struct GNUNET_PeerIdentity *door = &(msg->door);
  const struct GNUNET_HashCode *key = &(msg->key);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Entered room: %s\n", GNUNET_h2s (key));

  entry_handle_room_at (handle, door, key);
}

static void
handle_room_close (void *cls, const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  const struct GNUNET_HashCode *key = &(msg->key);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Closed room: %s\n", GNUNET_h2s (key));

  close_handle_room (handle, key);
}

static int
check_recv_message (void *cls, const struct GNUNET_MESSENGER_RecvMessage *msg)
{
  const uint16_t full_length = ntohs (msg->header.size) - sizeof(msg->header);

  if (full_length < sizeof(msg->hash))
    return GNUNET_NO;

  const uint16_t length = full_length - sizeof(msg->hash);
  const char *buffer = ((const char*) msg) + sizeof(*msg);

  struct GNUNET_MESSENGER_Message message;

  if (length < sizeof(message.header))
    return GNUNET_NO;

  if (GNUNET_YES != decode_message (&message, length, buffer))
    return GNUNET_NO;

  return GNUNET_OK;
}

static void
handle_recv_message (void *cls, const struct GNUNET_MESSENGER_RecvMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  const struct GNUNET_HashCode *key = &(msg->key);
  const struct GNUNET_HashCode *hash = &(msg->hash);

  const char *buffer = ((const char*) msg) + sizeof(*msg);

  const uint16_t length = ntohs (msg->header.size) - sizeof(*msg);

  struct GNUNET_MESSENGER_Message message;
  decode_message (&message, length, buffer);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Receiving message: %s\n", GNUNET_MESSENGER_name_of_kind (message.header.kind));

  struct GNUNET_MESSENGER_Room *room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (room)
  {
    handle_room_message (room, &message, hash);

    if (handle->msg_callback)
      handle->msg_callback (handle->msg_cls, room, &message, hash);
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "MESSENGER ERROR: Room not found\n");
}

static void
reconnect (struct GNUNET_MESSENGER_Handle *handle);

static void
send_open_room (struct GNUNET_MESSENGER_Handle *handle, struct GNUNET_MESSENGER_Room *room)
{
  struct GNUNET_MESSENGER_RoomMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN);
  GNUNET_memcpy(&(msg->key), &(room->key), sizeof(room->key));
  GNUNET_MQ_send (handle->mq, env);
}

static void
send_entry_room (struct GNUNET_MESSENGER_Handle *handle, struct GNUNET_MESSENGER_Room *room,
                 const struct GNUNET_PeerIdentity *door)
{
  struct GNUNET_MESSENGER_RoomMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY);
  GNUNET_memcpy(&(msg->door), door, sizeof(*door));
  GNUNET_memcpy(&(msg->key), &(room->key), sizeof(room->key));
  GNUNET_MQ_send (handle->mq, env);
}

static void
send_close_room (struct GNUNET_MESSENGER_Handle *handle, struct GNUNET_MESSENGER_Room *room)
{
  struct GNUNET_MESSENGER_RoomMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE);
  GNUNET_memcpy(&(msg->key), &(room->key), sizeof(room->key));
  GNUNET_MQ_send (handle->mq, env);
}

static int
iterate_reset_room (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;
  struct GNUNET_MESSENGER_Room *room = value;

  if (GNUNET_YES == room->opened)
    send_open_room (handle, room);

  struct GNUNET_MESSENGER_ListTunnel *entry = room->entries.head;

  struct GNUNET_PeerIdentity door;

  while (entry)
  {
    GNUNET_PEER_resolve (entry->peer, &door);

    send_entry_room (handle, room, &door);

    entry = entry->next;
  }

  return GNUNET_YES;
}

static void
callback_reconnect (void *cls)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  handle->reconnect_task = NULL;
  handle->reconnect_time = GNUNET_TIME_STD_BACKOFF(handle->reconnect_time)
  ;

  reconnect (handle);

  GNUNET_CONTAINER_multihashmap_iterate (handle->rooms, iterate_reset_room, handle);
}

static int
iterate_close_room (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;
  struct GNUNET_MESSENGER_Room *room = value;

  send_close_room (handle, room);

  return GNUNET_YES;
}

static void
callback_mq_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "MQ ERROR: %u\n", error);

  GNUNET_CONTAINER_multihashmap_iterate (handle->rooms, iterate_close_room, handle);

  if (handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }

  handle->reconnect_task = GNUNET_SCHEDULER_add_delayed (handle->reconnect_time, &callback_reconnect, handle);
}

static void
reconnect (struct GNUNET_MESSENGER_Handle *handle)
{
  const struct GNUNET_MQ_MessageHandler handlers[] = { GNUNET_MQ_hd_var_size(
      get_name, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_GET_NAME, struct GNUNET_MESSENGER_NameMessage, handle),
                                                       GNUNET_MQ_hd_fixed_size(
                                                           get_key, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_GET_KEY,
                                                           struct GNUNET_MESSENGER_KeyMessage, handle),
                                                       GNUNET_MQ_hd_fixed_size(
                                                           member_id,
                                                           GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_MEMBER_ID,
                                                           struct GNUNET_MESSENGER_MemberMessage, handle),
                                                       GNUNET_MQ_hd_fixed_size(room_open,
                                                                               GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN,
                                                                               struct GNUNET_MESSENGER_RoomMessage,
                                                                               handle),
                                                       GNUNET_MQ_hd_fixed_size(room_entry,
                                                                               GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY,
                                                                               struct GNUNET_MESSENGER_RoomMessage,
                                                                               handle),
                                                       GNUNET_MQ_hd_fixed_size(room_close,
                                                                               GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE,
                                                                               struct GNUNET_MESSENGER_RoomMessage,
                                                                               handle),
                                                       GNUNET_MQ_hd_var_size(
                                                           recv_message,
                                                           GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_RECV_MESSAGE,
                                                           struct GNUNET_MESSENGER_RecvMessage, handle),
                                                       GNUNET_MQ_handler_end() };

  handle->mq = GNUNET_CLIENT_connect (handle->cfg,
  GNUNET_MESSENGER_SERVICE_NAME,
                                      handlers, &callback_mq_error, handle);
}

struct GNUNET_MESSENGER_Handle*
GNUNET_MESSENGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg, const char *name,
                          GNUNET_MESSENGER_IdentityCallback identity_callback, void *identity_cls,
                          GNUNET_MESSENGER_MessageCallback msg_callback, void *msg_cls)
{
  struct GNUNET_MESSENGER_Handle *handle = create_handle (cfg, identity_callback, identity_cls, msg_callback, msg_cls);

  reconnect (handle);

  if (handle->mq)
  {
    const uint16_t name_len = name ? strlen (name) : 0;

    struct GNUNET_MESSENGER_CreateMessage *msg;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg_extra(msg, name_len + 1, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_CREATE);

    char *extra = ((char*) msg) + sizeof(*msg);

    if (name_len)
      GNUNET_memcpy(extra, name, name_len);

    extra[name_len] = '\0';

    GNUNET_MQ_send (handle->mq, env);
    return handle;
  }
  else
  {
    destroy_handle (handle);
    return NULL;
  }
}

int
GNUNET_MESSENGER_update (struct GNUNET_MESSENGER_Handle *handle)
{
  if ((!handle) || (!get_handle_name(handle)))
    return GNUNET_SYSERR;

  struct GNUNET_MESSENGER_UpdateMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_UPDATE);
  GNUNET_MQ_send (handle->mq, env);
  return GNUNET_OK;
}

void
GNUNET_MESSENGER_disconnect (struct GNUNET_MESSENGER_Handle *handle)
{
  if (!handle)
    return;

  struct GNUNET_MESSENGER_DestroyMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_DESTROY);
  GNUNET_MQ_send (handle->mq, env);

  destroy_handle (handle);
}

const char*
GNUNET_MESSENGER_get_name (const struct GNUNET_MESSENGER_Handle *handle)
{
  if (!handle)
    return NULL;

  return get_handle_name (handle);
}

int
GNUNET_MESSENGER_set_name (struct GNUNET_MESSENGER_Handle *handle, const char *name)
{
  if (!handle)
    return GNUNET_SYSERR;

  const uint16_t name_len = name ? strlen (name) : 0;

  struct GNUNET_MESSENGER_NameMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg_extra(msg, name_len + 1, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_SET_NAME);

  char *extra = ((char*) msg) + sizeof(*msg);

  if (name_len)
    GNUNET_memcpy(extra, name, name_len);

  extra[name_len] = '\0';

  GNUNET_MQ_send (handle->mq, env);
  return GNUNET_YES;
}

const struct GNUNET_IDENTITY_PublicKey*
GNUNET_MESSENGER_get_key (const struct GNUNET_MESSENGER_Handle *handle)
{
  if (!handle)
    return NULL;

  return get_handle_key (handle);
}

struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_open_room (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_Room *room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (!room)
  {
    room = create_room (handle, key);

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->rooms, key, room,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      destroy_room (room);
      return NULL;
    }
  }

  send_open_room (handle, room);
  return room;
}

struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_entry_room (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_PeerIdentity *door,
                             const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_Room *room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (!room)
  {
    room = create_room (handle, key);

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->rooms, key, room,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      destroy_room (room);
      return NULL;
    }
  }

  send_entry_room (handle, room, door);
  return room;
}

void
GNUNET_MESSENGER_close_room (struct GNUNET_MESSENGER_Room *room)
{
  send_close_room (room->handle, room);
}

struct GNUNET_MESSENGER_Contact*
GNUNET_MESSENGER_get_member (const struct GNUNET_MESSENGER_Room *room, const struct GNUNET_ShortHashCode *id)
{
  return GNUNET_CONTAINER_multishortmap_get (room->members, id);
}

const char*
GNUNET_MESSENGER_contact_get_name (const struct GNUNET_MESSENGER_Contact *contact)
{
  if (!contact)
    return NULL;

  return get_contact_name (contact);
}

const struct GNUNET_IDENTITY_PublicKey*
GNUNET_MESSENGER_contact_get_key (const struct GNUNET_MESSENGER_Contact *contact)
{
  if (!contact)
    return NULL;

  return get_contact_key (contact);
}

void
GNUNET_MESSENGER_send_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message)
{
  const uint16_t length = get_message_size (message);

  struct GNUNET_MESSENGER_SendMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg_extra(msg, length, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SEND_MESSAGE);

  GNUNET_memcpy(&(msg->key), &(room->key), sizeof(room->key));

  char *buffer = ((char*) msg) + sizeof(*msg);
  encode_message (message, length, buffer);

  GNUNET_MQ_send (room->handle->mq, env);
}

const struct GNUNET_MESSENGER_Message*
GNUNET_MESSENGER_get_message (const struct GNUNET_MESSENGER_Room *room, const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_Message *message = get_room_message (room, hash);

  if (!message)
  {
    struct GNUNET_MESSENGER_RecvMessage *msg;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_GET_MESSAGE);
    GNUNET_memcpy(&(msg->key), &(room->key), sizeof(room->key));
    GNUNET_memcpy(&(msg->hash), hash, sizeof(*hash));
    GNUNET_MQ_send (room->handle->mq, env);
  }

  return message;
}
