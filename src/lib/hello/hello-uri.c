/*
     This file is part of GNUnet.
     Copyright (C) 2022 GNUnet e.V.

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
 * @file hello/hello-uri.c
 * @brief helper library for handling URI-based HELLOs
 * @author Christian Grothoff
 *
 * Note:
 * - Current API does not support deserializing HELLO of
 *   another peer and then serializing it into another
 *   format (we always require the private key).
 *   Not sure if we need this, but if we do, we need
 *   to extend the builder and the API.
 * - Current API does not allow overriding the default
 *   HELLO expiration time. We may want to add a function
 *   that does this to create bootstrap HELLOs shipped with
 *   the TGZ.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_protocols.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Binary block we sign when we sign an address.
 */
struct SignedAddress
{
  /**
   * Purpose must be #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_ADDRESS
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * When was the address generated.
   */
  struct GNUNET_TIME_AbsoluteNBO mono_time;

  /**
   * Hash of the address.
   */
  struct GNUNET_HashCode addr_hash GNUNET_PACKED;
};

/**
 * Message signed as part of a HELLO block/URL.
 */
struct HelloSignaturePurpose
{
  /**
   * Purpose must be #GNUNET_SIGNATURE_PURPOSE_HELLO
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * When does the signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Hash over all addresses.
   */
  struct GNUNET_HashCode h_addrs;

};

/**
 * Message used when gossiping HELLOs between peers.
 */
struct HelloUriMessage
{
  /**
   * Type must be #GNUNET_MESSAGE_TYPE_HELLO_URI
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved. 0.
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * Number of URLs encoded after the end of the struct, in NBO.
   */
  uint16_t url_counter GNUNET_PACKED;

  /* followed by a 'block' */
};


/**
 * Start of a 'block'.
 */
struct BlockHeader
{
  /**
   * Public key of the peer.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Signature over the block, of purpose #GNUNET_SIGNATURE_PURPOSE_HELLO.
   */
  struct GNUNET_CRYPTO_EddsaSignature sig;

  /**
   * When does the HELLO expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

};


/**
 * Message used when a DHT provides its HELLO to direct
 * neighbours.
 */
struct DhtHelloMessage
{
  /**
   * Type must be #GNUNET_MESSAGE_TYPE_DHT_P2P_HELLO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved. 0.
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * Number of URLs encoded after the end of the struct, in NBO.
   */
  uint16_t url_counter GNUNET_PACKED;

  /**
   * Signature over the block, of purpose #GNUNET_SIGNATURE_PURPOSE_HELLO.
   */
  struct GNUNET_CRYPTO_EddsaSignature sig;

  /**
   * When does the HELLO expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /* followed by the serialized addresses of the 'block' */
};


GNUNET_NETWORK_STRUCT_END


/**
 * Address of a peer.
 */
struct Address
{
  /**
   * Kept in a DLL.
   */
  struct Address *next;

  /**
   * Kept in a DLL.
   */
  struct Address *prev;

  /**
   * Actual URI, allocated at the end of this struct.
   */
  const char *uri;

  /**
   * Length of @a uri including 0-terminator.
   */
  size_t uri_len;
};


/**
 * Context for building (or parsing) HELLO URIs.
 */
struct GNUNET_HELLO_Builder
{
  /**
   * Public key of the peer.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Head of the addresses DLL.
   */
  struct Address *a_head;

  /**
   * Tail of the addresses DLL.
   */
  struct Address *a_tail;

  /**
   * Length of the @a a_head DLL.
   */
  unsigned int a_length;

};

/**
 * Struct to wrap data to do the merge of to hello uris.
 */
struct AddressUriMergeResult
{
  /**
   * The builder of the hello uri we merge with.
   */
  struct GNUNET_HELLO_Builder *builder;

  /**
   * The actual address to check, if it is already in the hello uri we merge with.
   */
  const char *address_uri;

  /**
   * Did we found the actual address to check.
   */
  unsigned int found;

  /**
   * Did we found at least one address to merge.
   */
  unsigned int merged;
};

/**
 * Context for parsing HELLOs.
 */
struct GNUNET_HELLO_Parser
{
  /**
   * Public key of the peer.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Head of the addresses DLL.
   */
  struct Address *a_head;

  /**
   * Tail of the addresses DLL.
   */
  struct Address *a_tail;

  /**
   * Length of the @a a_head DLL.
   */
  unsigned int a_length;

  /**
   * The signature (may have been provided)
   */
  struct GNUNET_CRYPTO_EddsaSignature sig;

  /**
   * Expiration time parsed
   */
  struct GNUNET_TIME_Absolute et;
};

/**
 * Compute @a hash over addresses in @a builder.
 *
 * @param builder the builder to hash addresses of
 * @param[out] hash where to write the hash
 */
static void
hash_addresses (const struct Address *a_head,
                struct GNUNET_HashCode *hash)
{
  struct GNUNET_HashContext *hc;

  hc = GNUNET_CRYPTO_hash_context_start ();
  for (const struct Address *a = a_head;
       NULL != a;
       a = a->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Hashing over %.*s\n",
                (int) a->uri_len,
                a->uri);
    GNUNET_CRYPTO_hash_context_read (hc,
                                     a->uri,
                                     a->uri_len);
  }
  GNUNET_CRYPTO_hash_context_finish (hc,
                                     hash);

}


/**
 * Create HELLO signature.
 *
 * @param builder the builder to use
 * @param et expiration time to sign
 * @param priv key to sign with
 * @param[out] sig where to write the signature
 */
static void
sign_hello (const struct GNUNET_HELLO_Builder *builder,
            struct GNUNET_TIME_Absolute et,
            const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
            struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct HelloSignaturePurpose hsp = {
    .purpose.size = htonl (sizeof (hsp)),
    .purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_HELLO),
    .expiration_time = GNUNET_TIME_absolute_hton (et)
  };

  hash_addresses (builder->a_head,
                  &hsp.h_addrs);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Address hash is %s\n",
              GNUNET_h2s_full (&hsp.h_addrs));
  GNUNET_CRYPTO_eddsa_sign (priv,
                            &hsp,
                            sig);
}


/**
 * Verify HELLO signature.
 *
 * @param builder the builder to use
 * @param et expiration time to verify
 * @param sig signature to verify
 * @return #GNUNET_OK if everything is ok, #GNUNET_NO if the
 *    HELLO expired, #GNUNET_SYSERR if the signature is wrong
 */
static enum GNUNET_GenericReturnValue
verify_hello (const struct GNUNET_HELLO_Parser *parser,
              struct GNUNET_TIME_Absolute et,
              const struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct HelloSignaturePurpose hsp = {
    .purpose.size = htonl (sizeof (hsp)),
    .purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_HELLO),
    .expiration_time = GNUNET_TIME_absolute_hton (et)
  };

  hash_addresses (parser->a_head,
                  &hsp.h_addrs);
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_HELLO,
                                  &hsp,
                                  sig,
                                  &parser->pid.public_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_TIME_absolute_is_past (et))
    return GNUNET_NO;
  return GNUNET_OK;
}


static struct GNUNET_HELLO_Parser *
parser_new (const struct GNUNET_PeerIdentity *pid)
{
  struct GNUNET_HELLO_Parser *p;

  p = GNUNET_new (struct GNUNET_HELLO_Parser);
  p->pid = *pid;
  return p;
}


struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_new (const struct GNUNET_PeerIdentity *pid)
{
  struct GNUNET_HELLO_Builder *builder;

  builder = GNUNET_new (struct GNUNET_HELLO_Builder);
  builder->pid = *pid;
  return builder;
}


const struct GNUNET_PeerIdentity *
GNUNET_HELLO_parser_get_id (const struct GNUNET_HELLO_Parser *parser)
{
  return &parser->pid;
}


struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_from_parser (const struct GNUNET_HELLO_Parser *p)
{
  struct GNUNET_HELLO_Builder *builder;
  struct Address *a;

  builder = GNUNET_HELLO_builder_new (&p->pid);
  /* check for duplicates */
  for (a = p->a_head;
       NULL != a;
       a = a->next)
    GNUNET_HELLO_builder_add_address (builder, a->uri);
  return builder;
}


void
GNUNET_HELLO_parser_free (struct GNUNET_HELLO_Parser *parser)
{
  struct Address *a;

  while (NULL != (a = parser->a_head))
  {
    GNUNET_CONTAINER_DLL_remove (parser->a_head,
                                 parser->a_tail,
                                 a);
    parser->a_length--;
    GNUNET_free (a);
  }
  GNUNET_assert (0 == parser->a_length);
  GNUNET_free (parser);
}


void
GNUNET_HELLO_builder_free (struct GNUNET_HELLO_Builder *builder)
{
  struct Address *a;

  while (NULL != (a = builder->a_head))
  {
    GNUNET_CONTAINER_DLL_remove (builder->a_head,
                                 builder->a_tail,
                                 a);
    builder->a_length--;
    GNUNET_free (a);
  }
  GNUNET_assert (0 == builder->a_length);
  GNUNET_free (builder);
}


struct GNUNET_HELLO_Parser *
GNUNET_HELLO_parser_from_msg (const struct GNUNET_MessageHeader *msg)
{
  const struct HelloUriMessage *h;
  uint16_t size = ntohs (msg->size);

  if (GNUNET_MESSAGE_TYPE_HELLO_URI != ntohs (msg->type))
  {
    GNUNET_break (0);
    return NULL;
  }
  if (sizeof (struct HelloUriMessage) > size)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  h = (const struct HelloUriMessage *) msg;
  size -= sizeof (*h);
  return GNUNET_HELLO_parser_from_block (&h[1],
                                         size);
}


static enum GNUNET_GenericReturnValue
check_address (const char *address)
{
  const char *e;

  if (NULL == (e = strstr (address,
                           "://")))
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid address `%s'\n",
                address);
    return GNUNET_SYSERR;
  }
  if (e == address)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  for (const char *p = address; p != e; p++)
    if ( (! isalpha ((unsigned char) *p)) &&
         ('+' != *p) )
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

static enum GNUNET_GenericReturnValue
parser_add_address (struct GNUNET_HELLO_Parser *parser,
                    const char *address)
{
  struct Address *a;
  enum GNUNET_GenericReturnValue ret;
  size_t alen = strlen (address) + 1;

  ret = check_address (address);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to add address to builder\n");
    return ret;
  }
  /* check for duplicates */
  for (a = parser->a_head;
       NULL != a;
       a = a->next)
    if (0 == strcmp (address,
                     a->uri))
      return GNUNET_NO;
  a = GNUNET_malloc (sizeof (struct Address) + alen);
  a->uri_len = alen;
  memcpy (&a[1],
          address,
          alen);
  a->uri = (const char *) &a[1];
  GNUNET_CONTAINER_DLL_insert_tail (parser->a_head,
                                    parser->a_tail,
                                    a);
  parser->a_length++;
  return GNUNET_OK;
}


struct GNUNET_HELLO_Parser *
GNUNET_HELLO_parser_from_block (const void *block,
                                size_t block_size)
{
  const struct BlockHeader *bh = block;
  struct GNUNET_HELLO_Parser *p;

  if (block_size < sizeof (*bh))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  p = parser_new (&bh->pid);
  block += sizeof (*bh);
  block_size -= sizeof (*bh);
  while (block_size > 0)
  {
    const void *end = memchr (block,
                              '\0',
                              block_size);

    if (NULL == end)
    {
      GNUNET_break_op (0);
      GNUNET_HELLO_parser_free (p);
      return NULL;
    }
    if (GNUNET_OK !=
        parser_add_address (p,
                            block))
    {
      GNUNET_break_op (0);
      GNUNET_HELLO_parser_free (p);
      return NULL;
    }
    end++;
    block_size -= (end - block);
    block = end;
  }
  {
    enum GNUNET_GenericReturnValue ret;
    struct GNUNET_TIME_Absolute et;

    et = GNUNET_TIME_absolute_ntoh (bh->expiration_time);
    ret = verify_hello (p,
                        et,
                        &bh->sig);
    GNUNET_break (GNUNET_SYSERR != ret);
    if (GNUNET_OK != ret)
    {
      GNUNET_HELLO_parser_free (p);
      return NULL;
    }
    p->et = GNUNET_TIME_absolute_ntoh (bh->expiration_time);
    p->sig = bh->sig;
  }
  return p;
}


struct GNUNET_TIME_Absolute
GNUNET_HELLO_get_expiration_time_from_msg (const struct
                                           GNUNET_MessageHeader *msg)
{
  struct GNUNET_TIME_Absolute et;
  if (GNUNET_MESSAGE_TYPE_HELLO_URI == ntohs (msg->type))
  {
    const struct HelloUriMessage *h = (const struct HelloUriMessage *) msg;
    const struct BlockHeader *bh = (const struct BlockHeader *) &h[1];

    et = GNUNET_TIME_absolute_ntoh (bh->expiration_time);
    return et;
  }
  else if (GNUNET_MESSAGE_TYPE_DHT_P2P_HELLO == ntohs (msg->type))
  {
    const struct DhtHelloMessage *dht_hello
      = (const struct DhtHelloMessage *) msg;

    et = GNUNET_TIME_absolute_ntoh (dht_hello->expiration_time);
    return et;
  }
  else
    GNUNET_break (0);
  return GNUNET_TIME_UNIT_ZERO_ABS;
}


enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_add_address (struct GNUNET_HELLO_Builder *builder,
                                  const char *address)
{
  struct Address *a;
  enum GNUNET_GenericReturnValue ret;
  size_t alen = strlen (address) + 1;

  ret = check_address (address);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to add address to builder\n");
    return ret;
  }
  /* check for duplicates */
  for (a = builder->a_head;
       NULL != a;
       a = a->next)
    if (0 == strcmp (address,
                     a->uri))
      return GNUNET_NO;
  a = GNUNET_malloc (sizeof (struct Address) + alen);
  a->uri_len = alen;
  memcpy (&a[1],
          address,
          alen);
  a->uri = (const char *) &a[1];
  GNUNET_CONTAINER_DLL_insert_tail (builder->a_head,
                                    builder->a_tail,
                                    a);
  builder->a_length++;
  return GNUNET_OK;
}


struct GNUNET_HELLO_Parser *
GNUNET_HELLO_parser_from_url (const char *url)
{
  const char *q;
  const char *s1;
  const char *s2;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_TIME_Absolute et;
  size_t len;
  struct GNUNET_HELLO_Parser *p;
  struct GNUNET_CRYPTO_EddsaSignature sig;

  if (0 != strncasecmp (url,
                        "gnunet://hello/",
                        strlen ("gnunet://hello/")))
    return NULL;
  url += strlen ("gnunet://hello/");
  s1 = strchr (url, '/');
  if (NULL == s1)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  s2 = strchr (s1 + 1, '/');
  if (NULL == s1)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  q = strchr (url, '?');
  if (NULL == q)
    q = url + strlen (url);
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (url,
                                     s1 - url,
                                     &pid,
                                     sizeof(pid)))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (s1 + 1,
                                     s2 - (s1 + 1),
                                     &sig,
                                     sizeof(sig)))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  {
    uint64_t sec;
    char dummy = '?';

    if ( (0 == sscanf (s2 + 1,
                       "%" PRIu64 "%c",
                       &sec,
                       &dummy)) ||
         ('?' != dummy) )
    {
      GNUNET_break_op (0);
      return NULL;
    }
    et.abs_value_us = sec;
  }

  p = parser_new (&pid);
  p->et = et;
  p->sig = sig;
  len = strlen (q);
  while (len > 0)
  {
    const char *eq;
    const char *amp;
    char *addr = NULL;
    char *uri;

    /* skip ?/& separator */
    len--;
    q++;
    eq = strchr (q, '=');
    if ( (eq == q) ||
         (NULL == eq) )
    {
      GNUNET_break_op (0);
      GNUNET_HELLO_parser_free (p);
      return NULL;
    }
    amp = strchr (eq, '&');
    if (NULL == amp)
      amp = &q[len];
    GNUNET_STRINGS_urldecode (eq + 1,
                              amp - (eq + 1),
                              &addr);
    if ( (NULL == addr) ||
         (0 == strlen (addr)) )
    {
      GNUNET_free (addr);
      GNUNET_break_op (0);
      GNUNET_HELLO_parser_free (p);
      return NULL;
    }
    GNUNET_asprintf (&uri,
                     "%.*s://%s",
                     (int) (eq - q),
                     q,
                     addr);
    GNUNET_free (addr);
    if (GNUNET_OK !=
        parser_add_address (p,
                            uri))
    {
      GNUNET_break_op (0);
      GNUNET_free (uri);
      GNUNET_HELLO_parser_free (p);
      return NULL;
    }
    GNUNET_free (uri);
    /* move to next URL */
    len -= (amp - q);
    q = amp;
  }

  {
    enum GNUNET_GenericReturnValue ret;

    ret = verify_hello (p,
                        et,
                        &p->sig);
    GNUNET_break (GNUNET_SYSERR != ret);
    if (GNUNET_OK != ret)
    {
      GNUNET_HELLO_parser_free (p);
      return NULL;
    }
  }
  return p;
}


struct GNUNET_MessageHeader *
GNUNET_HELLO_builder_to_dht_hello_msg (
  const struct GNUNET_HELLO_Builder *builder,
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  struct GNUNET_TIME_Relative expiration_time)
{
  struct DhtHelloMessage *msg;
  size_t blen;

  if (builder->a_length > UINT16_MAX)
  {
    GNUNET_break (0);
    return NULL;
  }
  blen = 0;
  GNUNET_assert (GNUNET_NO ==
                 GNUNET_HELLO_builder_to_block (builder,
                                                priv,
                                                NULL,
                                                &blen,
                                                expiration_time));
  GNUNET_assert (blen < UINT16_MAX);
  GNUNET_assert (blen >= sizeof (struct BlockHeader));
  {
    char buf[blen] GNUNET_ALIGN;
    const struct BlockHeader *block = (const struct BlockHeader *) buf;

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_HELLO_builder_to_block (builder,
                                                  priv,
                                                  buf,
                                                  &blen,
                                                  expiration_time));
    msg = GNUNET_malloc (sizeof (*msg)
                         + blen
                         - sizeof (*block));
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_HELLO);
    msg->header.size = htons (sizeof (*msg)
                              + blen
                              - sizeof (*block));
    memcpy (&msg[1],
            &block[1],
            blen - sizeof (*block));
    msg->sig = block->sig;
    msg->expiration_time = block->expiration_time;
  }
  msg->url_counter = htons ((uint16_t) builder->a_length);
  return &msg->header;
}


char *
GNUNET_HELLO_builder_to_url2 (const struct GNUNET_HELLO_Builder *builder,
                              const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                              struct GNUNET_TIME_Relative validity)
{
  struct GNUNET_CRYPTO_EddsaSignature sig;
  struct GNUNET_TIME_Absolute et;
  char *result;
  char *pids;
  char *sigs;
  const char *sep = "?";

  et = GNUNET_TIME_relative_to_absolute (validity);
  GNUNET_assert (NULL != priv);
  sign_hello (builder,
              et,
              priv,
              &sig);
  pids = GNUNET_STRINGS_data_to_string_alloc (&builder->pid,
                                              sizeof (builder->pid));
  sigs = GNUNET_STRINGS_data_to_string_alloc (&sig,
                                              sizeof (sig));
  GNUNET_asprintf (&result,
                   "gnunet://hello/%s/%s/%" PRIu64,
                   pids,
                   sigs,
                   et.abs_value_us);
  GNUNET_free (sigs);
  GNUNET_free (pids);
  for (struct Address *a = builder->a_head;
       NULL != a;
       a = a->next)
  {
    char *ue;
    char *tmp;
    int pfx_len;
    const char *eou;

    eou = strstr (a->uri,
                  "://");
    if (NULL == eou)
    {
      GNUNET_break (0);
      GNUNET_free (result);
      return NULL;
    }
    pfx_len = eou - a->uri;
    eou += 3;
    GNUNET_STRINGS_urlencode (a->uri_len - 4 - pfx_len,
                              eou,
                              &ue);
    GNUNET_asprintf (&tmp,
                     "%s%s%.*s=%s",
                     result,
                     sep,
                     pfx_len,
                     a->uri,
                     ue);
    GNUNET_free (ue);
    GNUNET_free (result);
    result = tmp;
    sep = "&";
  }
  return result;
}


char *
GNUNET_HELLO_parser_to_url (const struct GNUNET_HELLO_Parser *parser)
{
  char *result;
  char *pids;
  char *sigs;
  const char *sep = "?";

  pids = GNUNET_STRINGS_data_to_string_alloc (&parser->pid,
                                              sizeof (parser->pid));
  sigs = GNUNET_STRINGS_data_to_string_alloc (&parser->sig,
                                              sizeof (parser->sig));
  GNUNET_asprintf (&result,
                   "gnunet://hello/%s/%s/%" PRIu64,
                   pids,
                   sigs,
                   parser->et.abs_value_us);
  GNUNET_free (sigs);
  GNUNET_free (pids);
  for (struct Address *a = parser->a_head;
       NULL != a;
       a = a->next)
  {
    char *ue;
    char *tmp;
    int pfx_len;
    const char *eou;

    eou = strstr (a->uri,
                  "://");
    if (NULL == eou)
    {
      GNUNET_break (0);
      GNUNET_free (result);
      return NULL;
    }
    pfx_len = eou - a->uri;
    eou += 3;
    GNUNET_STRINGS_urlencode (a->uri_len - 4 - pfx_len,
                              eou,
                              &ue);
    GNUNET_asprintf (&tmp,
                     "%s%s%.*s=%s",
                     result,
                     sep,
                     pfx_len,
                     a->uri,
                     ue);
    GNUNET_free (ue);
    GNUNET_free (result);
    result = tmp;
    sep = "&";
  }
  return result;
}


char *
GNUNET_HELLO_builder_to_url (const struct GNUNET_HELLO_Builder *builder,
                             const struct GNUNET_CRYPTO_EddsaPrivateKey *priv)
{
  return GNUNET_HELLO_builder_to_url2 (builder, priv,
                                       GNUNET_HELLO_ADDRESS_EXPIRATION);
}


enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_to_block (const struct GNUNET_HELLO_Builder *builder,
                               const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                               void *block,
                               size_t *block_size,
                               struct GNUNET_TIME_Relative expiration_time)
{
  struct BlockHeader bh;
  size_t needed = sizeof (bh);
  char *pos;
  struct GNUNET_TIME_Absolute et;

  GNUNET_assert (NULL != priv);
  for (struct Address *a = builder->a_head;
       NULL != a;
       a = a->next)
  {
    GNUNET_assert (needed + a->uri_len > needed);
    needed += a->uri_len;
  }
  if ( (NULL == block) ||
       (needed < *block_size) )
  {
    *block_size = needed;
    return GNUNET_NO;
  }
  bh.pid = builder->pid;
  if (GNUNET_TIME_UNIT_ZERO.rel_value_us == expiration_time.rel_value_us)
    et = GNUNET_TIME_relative_to_absolute (GNUNET_HELLO_ADDRESS_EXPIRATION);
  else
    et = GNUNET_TIME_relative_to_absolute (expiration_time);
  bh.expiration_time = GNUNET_TIME_absolute_hton (et);
  sign_hello (builder,
              et,
              priv,
              &bh.sig);
  memcpy (block,
          &bh,
          sizeof (bh));
  pos = block + sizeof (bh);
  for (struct Address *a = builder->a_head;
       NULL != a;
       a = a->next)
  {
    memcpy (pos,
            a->uri,
            a->uri_len);
    pos += a->uri_len;
  }
  *block_size = needed;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_HELLO_parser_to_block (const struct GNUNET_HELLO_Parser *parser,
                              void *block,
                              size_t *block_size)
{
  struct BlockHeader bh;
  size_t needed = sizeof (bh);
  char *pos;

  for (struct Address *a = parser->a_head;
       NULL != a;
       a = a->next)
  {
    GNUNET_assert (needed + a->uri_len > needed);
    needed += a->uri_len;
  }
  if ( (NULL == block) ||
       (needed < *block_size) )
  {
    *block_size = needed;
    return GNUNET_NO;
  }
  bh.pid = parser->pid;
  bh.sig = parser->sig;
  bh.expiration_time = GNUNET_TIME_absolute_hton (parser->et);
  memcpy (block,
          &bh,
          sizeof (bh));
  pos = block + sizeof (bh);
  for (struct Address *a = parser->a_head;
       NULL != a;
       a = a->next)
  {
    memcpy (pos,
            a->uri,
            a->uri_len);
    pos += a->uri_len;
  }
  *block_size = needed;
  return GNUNET_OK;
}


struct GNUNET_MQ_Envelope *
GNUNET_HELLO_parser_to_env (const struct GNUNET_HELLO_Parser *parser)
{
  struct GNUNET_MQ_Envelope *env;
  struct HelloUriMessage *msg;
  size_t blen;

  if (parser->a_length > UINT16_MAX)
  {
    GNUNET_break (0);
    return NULL;
  }
  blen = 0;
  GNUNET_assert (GNUNET_NO ==
                 GNUNET_HELLO_parser_to_block (parser,
                                               NULL,
                                               &blen));
  env = GNUNET_MQ_msg_extra (msg,
                             blen,
                             GNUNET_MESSAGE_TYPE_HELLO_URI);
  msg->url_counter = htons ((uint16_t) parser->a_length);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_parser_to_block (parser,
                                               &msg[1],
                                               &blen));
  return env;
}


static struct GNUNET_MQ_Envelope *
GNUNET_HELLO_builder_to_env_ (const struct GNUNET_HELLO_Builder *builder,
                              const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                              struct GNUNET_TIME_Relative expiration_time,
                              const struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct GNUNET_MQ_Envelope *env;
  struct HelloUriMessage *msg;
  size_t blen;

  if (builder->a_length > UINT16_MAX)
  {
    GNUNET_break (0);
    return NULL;
  }
  blen = 0;
  GNUNET_assert (GNUNET_NO ==
                 GNUNET_HELLO_builder_to_block (builder,
                                                priv,
                                                NULL,
                                                &blen,
                                                expiration_time));
  env = GNUNET_MQ_msg_extra (msg,
                             blen,
                             GNUNET_MESSAGE_TYPE_HELLO_URI);
  msg->url_counter = htons ((uint16_t) builder->a_length);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_builder_to_block (builder,
                                                priv,
                                                &msg[1],
                                                &blen,
                                                expiration_time));
  return env;
}


struct GNUNET_MQ_Envelope *
GNUNET_HELLO_builder_to_env (const struct GNUNET_HELLO_Builder *builder,
                             const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                             struct GNUNET_TIME_Relative expiration_time)
{
  return GNUNET_HELLO_builder_to_env_ (builder, priv, expiration_time, NULL);
}


enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_del_address (struct GNUNET_HELLO_Builder *builder,
                                  const char *address)
{
  struct Address *a;

  /* check for duplicates */
  for (a = builder->a_head;
       NULL != a;
       a = a->next)
    if (0 == strcmp (address,
                     a->uri))
      break;
  if (NULL == a)
    return GNUNET_NO;
  GNUNET_CONTAINER_DLL_remove (builder->a_head,
                               builder->a_tail,
                               a);
  builder->a_length--;
  GNUNET_free (a);
  return GNUNET_OK;
}


const struct GNUNET_PeerIdentity*
GNUNET_HELLO_parser_iterate (const struct GNUNET_HELLO_Parser *parser,
                             GNUNET_HELLO_UriCallback uc,
                             void *uc_cls)
{
  struct Address *nxt;

  if (NULL == uc)
    return &parser->pid;
  for (struct Address *a = parser->a_head;
       NULL != a;
       a = nxt)
  {
    nxt = a->next;
    uc (uc_cls,
        &parser->pid,
        a->uri);
  }
  return &parser->pid;
}


enum GNUNET_GenericReturnValue
GNUNET_HELLO_dht_msg_to_block (const struct GNUNET_MessageHeader *hello,
                               const struct GNUNET_PeerIdentity *pid,
                               void **block,
                               size_t *block_size,
                               struct GNUNET_TIME_Absolute *block_expiration)
{
  const struct DhtHelloMessage *msg
    = (const struct DhtHelloMessage *) hello;
  uint16_t len = ntohs (hello->size);
  struct BlockHeader *bh;
  struct GNUNET_HELLO_Parser *b;
  enum GNUNET_GenericReturnValue ret;

  if (GNUNET_MESSAGE_TYPE_DHT_P2P_HELLO != ntohs (hello->type))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (len < sizeof (*msg))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  len -= sizeof (*msg);
  *block_size = len + sizeof (*bh);
  *block = GNUNET_malloc (*block_size);
  bh = *block;
  bh->pid = *pid;
  bh->sig = msg->sig;
  bh->expiration_time = msg->expiration_time;
  *block_expiration = GNUNET_TIME_absolute_ntoh (msg->expiration_time);
  memcpy (&bh[1],
          &msg[1],
          len);
  b = GNUNET_HELLO_parser_from_block (*block,
                                      *block_size);
  if (NULL == b)
  {
    GNUNET_break_op (0);
    GNUNET_free (*block);
    *block_size = 0;
    return GNUNET_SYSERR;
  }
  ret = verify_hello (b,
                      *block_expiration,
                      &msg->sig);
  GNUNET_HELLO_parser_free (b);
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_free (*block);
    *block_size = 0;
    return GNUNET_SYSERR;
  }
  return ret;
}


/**
 * Given an address as a string, extract the prefix that identifies
 * the communicator offering transmissions to that address.
 *
 * @param address a peer's address
 * @return NULL if the address is mal-formed, otherwise the prefix
 */
char *
GNUNET_HELLO_address_to_prefix (const char *address)
{
  const char *dash;

  dash = strchr (address, '-');
  if (NULL == dash)
    return NULL;
  return GNUNET_strndup (address, dash - address);
}


/**
 * Build address record by signing raw information with private key.
 *
 * @param address text address at @a communicator to sign
 * @param nt network type of @a address
 * @param mono_time monotonic time at which @a address was valid
 * @param private_key signing key to use
 * @param[out] result where to write address record (allocated)
 * @param[out] result_size set to size of @a result
 */
void
GNUNET_HELLO_sign_address (
  const char *address,
  enum GNUNET_NetworkType nt,
  struct GNUNET_TIME_Absolute mono_time,
  const struct GNUNET_CRYPTO_EddsaPrivateKey *private_key,
  void **result,
  size_t *result_size)
{
  struct SignedAddress sa;
  struct GNUNET_CRYPTO_EddsaSignature sig;
  char *sig_str;

  sa.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_ADDRESS);
  sa.purpose.size = htonl (sizeof(sa));
  sa.mono_time = GNUNET_TIME_absolute_hton (mono_time);
  GNUNET_CRYPTO_hash (address, strlen (address), &sa.addr_hash);
  GNUNET_CRYPTO_eddsa_sign (private_key, &sa, &sig);
  sig_str = NULL;
  (void) GNUNET_STRINGS_base64_encode (&sig, sizeof(sig), &sig_str);
  *result_size =
    1 + GNUNET_asprintf ((char **) result,
                         "%s;%llu;%u;%s",
                         sig_str,
                         (unsigned long long) mono_time.abs_value_us,
                         (unsigned int) nt,
                         address);
  GNUNET_free (sig_str);
}
