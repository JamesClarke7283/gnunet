/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014 GNUnet e.V.

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
 * @file gnsrecord/plugin_gnsrecord_dns.c
 * @brief gnsrecord plugin to provide the API for basic DNS records
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_plugin.h"


/**
 * Convert the 'value' of a record to a string.
 *
 * @param cls closure, unused
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
static char *
dns_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  char *result;
  char tmp[INET6_ADDRSTRLEN];

  switch (type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    if (data_size != sizeof(struct in_addr))
      return NULL;
    if (NULL == inet_ntop (AF_INET, data, tmp, sizeof(tmp)))
      return NULL;
    return GNUNET_strdup (tmp);

  case GNUNET_DNSPARSER_TYPE_NS: {
      char *ns;
      size_t off;

      off = 0;
      ns = GNUNET_DNSPARSER_parse_name (data, data_size, &off);
      if ((NULL == ns) || (off != data_size))
      {
        GNUNET_break_op (0);
        GNUNET_free (ns);
        return NULL;
      }
      return ns;
    }

  case GNUNET_DNSPARSER_TYPE_CNAME: {
      char *cname;
      size_t off;

      off = 0;
      cname = GNUNET_DNSPARSER_parse_name (data, data_size, &off);
      if ((NULL == cname) || (off != data_size))
      {
        GNUNET_break_op (0);
        GNUNET_free (cname);
        return NULL;
      }
      return cname;
    }

  case GNUNET_DNSPARSER_TYPE_SOA: {
      struct GNUNET_DNSPARSER_SoaRecord *soa;
      size_t off;

      off = 0;
      soa = GNUNET_DNSPARSER_parse_soa (data, data_size, &off);
      if ((NULL == soa) || (off != data_size))
      {
        GNUNET_break_op (0);
        if (NULL != soa)
          GNUNET_DNSPARSER_free_soa (soa);
        return NULL;
      }
      GNUNET_asprintf (&result,
                       "%s %s ( %u %u %u %u %u )",
                       soa->rname,
                       soa->mname,
                       soa->serial,
                       soa->refresh,
                       soa->retry,
                       soa->expire,
                       soa->minimum_ttl);
      GNUNET_DNSPARSER_free_soa (soa);
      return result;
    }

  case GNUNET_DNSPARSER_TYPE_PTR: {
      char *ptr;
      size_t off;

      off = 0;
      ptr = GNUNET_DNSPARSER_parse_name (data, data_size, &off);
      if ((NULL == ptr) || (off != data_size))
      {
        GNUNET_break_op (0);
        GNUNET_free (ptr);
        return NULL;
      }
      return ptr;
    }

  case GNUNET_DNSPARSER_TYPE_CERT: {
      struct GNUNET_DNSPARSER_CertRecord *cert;
      size_t off;
      char *base64;
      int len;

      off = 0;
      cert = GNUNET_DNSPARSER_parse_cert (data, data_size, &off);
      if ((NULL == cert) || (off != data_size))
      {
        GNUNET_break_op (0);
        GNUNET_DNSPARSER_free_cert (cert);
        return NULL;
      }
      len = GNUNET_STRINGS_base64_encode (cert->certificate_data,
                                          cert->certificate_size,
                                          &base64);
      GNUNET_asprintf (&result,
                       "%u %u %u %.*s",
                       cert->cert_type,
                       cert->cert_tag,
                       cert->algorithm,
                       len,
                       base64);
      GNUNET_free (base64);
      GNUNET_DNSPARSER_free_cert (cert);
      return result;
    }

  case GNUNET_DNSPARSER_TYPE_MX: {
      struct GNUNET_DNSPARSER_MxRecord *mx;
      size_t off;

      off = 0;
      mx = GNUNET_DNSPARSER_parse_mx (data, data_size, &off);
      if ((NULL == mx) || (off != data_size))
      {
        GNUNET_break_op (0);
        GNUNET_DNSPARSER_free_mx (mx);
        return NULL;
      }
      GNUNET_asprintf (&result,
                       "%u %s",
                       (unsigned int) mx->preference,
                       mx->mxhost);
      GNUNET_DNSPARSER_free_mx (mx);
      return result;
    }

  case GNUNET_DNSPARSER_TYPE_TXT:
    return GNUNET_strndup (data, data_size);

  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (data_size != sizeof(struct in6_addr))
      return NULL;
    if (NULL == inet_ntop (AF_INET6, data, tmp, sizeof(tmp)))
      return NULL;
    return GNUNET_strdup (tmp);

  case GNUNET_DNSPARSER_TYPE_SRV: {
      struct GNUNET_DNSPARSER_SrvRecord *srv;
      size_t off;

      off = 0;
      srv = GNUNET_DNSPARSER_parse_srv (data, data_size, &off);
      if ((NULL == srv) || (off != data_size))
      {
        GNUNET_break_op (0);
        if (NULL != srv)
          GNUNET_DNSPARSER_free_srv (srv);
        return NULL;
      }
      GNUNET_asprintf (&result,
                       "%d %d %d %s",
                       srv->priority,
                       srv->weight,
                       srv->port,
                       srv->target);
      GNUNET_DNSPARSER_free_srv (srv);
      return result;
    }

  case GNUNET_DNSPARSER_TYPE_URI: {   // RFC7553
      struct GNUNET_DNSPARSER_UriRecord *uri;
      size_t off;

      off = 0;
      uri = GNUNET_DNSPARSER_parse_uri (data, data_size, &off);
      if ((NULL == uri) || (off != data_size))
      {
        GNUNET_break_op (0);
        if (NULL != uri)
          GNUNET_DNSPARSER_free_uri (uri);
        return NULL;
      }
      GNUNET_asprintf (&result,
                       "%d %d \"%s\"",
                       uri->priority,
                       uri->weight,
                       uri->target);
      GNUNET_DNSPARSER_free_uri (uri);
      return result;
    }

  case GNUNET_DNSPARSER_TYPE_SMIMEA:
  case GNUNET_DNSPARSER_TYPE_TLSA: {
      const struct GNUNET_TUN_DnsTlsaRecord *tlsa;
      char *tlsa_str;
      char *hex;

      if (data_size < sizeof(struct GNUNET_TUN_DnsTlsaRecord))
        return NULL; /* malformed */
      tlsa = data;
      hex =
        GNUNET_DNSPARSER_bin_to_hex (&tlsa[1],
                                     data_size
                                     - sizeof(struct GNUNET_TUN_DnsTlsaRecord));
      if (0 == GNUNET_asprintf (&tlsa_str,
                                "%u %u %u %s",
                                (unsigned int) tlsa->usage,
                                (unsigned int) tlsa->selector,
                                (unsigned int) tlsa->matching_type,
                                hex))
      {
        GNUNET_free (hex);
        GNUNET_free (tlsa_str);
        return NULL;
      }
      GNUNET_free (hex);
      return tlsa_str;
    }

  case GNUNET_DNSPARSER_TYPE_CAA: {   // RFC6844
      const struct GNUNET_DNSPARSER_CaaRecord *caa;
      char tag[15]; // between 1 and 15 bytes
      char value[data_size];
      char *caa_str;
      if (data_size < sizeof(struct GNUNET_DNSPARSER_CaaRecord))
        return NULL; /* malformed */
      caa = data;
      if ((1 > caa->tag_len) || (15 < caa->tag_len))
        return NULL; /* malformed */
      memset (tag, 0, sizeof(tag));
      memset (value, 0, data_size);
      memcpy (tag, &caa[1], caa->tag_len);
      memcpy (value,
              (char *) &caa[1] + caa->tag_len,
              data_size - caa->tag_len - 2);
      if (0 == GNUNET_asprintf (&caa_str,
                                "%u %s %s",
                                (unsigned int) caa->flags,
                                tag,
                                value))
      {
        GNUNET_free (caa_str);
        return NULL;
      }
      return caa_str;
    }

  default:
    return NULL;
  }
}


/**
 * Convert RFC 4394 Mnemonics to the corresponding integer values.
 *
 * @param mnemonic string to look up
 * @return the value, 0 if not found
 */
static unsigned int
rfc4398_mnemonic_to_value (const char *mnemonic)
{
  static struct
  {
    const char *mnemonic;
    unsigned int val;
  } table[] = { { "PKIX", 1 },
                { "SPKI", 2 },
                { "PGP", 3 },
                { "IPKIX", 4 },
                { "ISPKI", 5 },
                { "IPGP", 6 },
                { "ACPKIX", 7 },
                { "IACPKIX", 8 },
                { "URI", 253 },
                { "OID", 254 },
                { NULL, 0 } };
  unsigned int i;

  for (i = 0; NULL != table[i].mnemonic; i++)
    if (0 == strcasecmp (mnemonic, table[i].mnemonic))
      return table[i].val;
  return 0;
}


/**
 * Convert RFC 4034 algorithm types to the corresponding integer values.
 *
 * @param mnemonic string to look up
 * @return the value, 0 if not found
 */
static unsigned int
rfc4034_mnemonic_to_value (const char *mnemonic)
{
  static struct
  {
    const char *mnemonic;
    unsigned int val;
  } table[] = { { "RSAMD5", 1 },
                { "DH", 2 },
                { "DSA", 3 },
                { "ECC", 4 },
                { "RSASHA1", 5 },
                { "INDIRECT", 252 },
                { "PRIVATEDNS", 253 },
                { "PRIVATEOID", 254 },
                { NULL, 0 } };
  unsigned int i;

  for (i = 0; NULL != table[i].mnemonic; i++)
    if (0 == strcasecmp (mnemonic, table[i].mnemonic))
      return table[i].val;
  return 0;
}


/**
 * Convert human-readable version of a 'value' of a record to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
dns_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  struct in_addr value_a;
  struct in6_addr value_aaaa;
  struct GNUNET_TUN_DnsTlsaRecord *tlsa;

  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    if (1 != inet_pton (AF_INET, s, &value_a))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Unable to parse IPv4 address `%s'\n"),
                  s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_new (struct in_addr);
    GNUNET_memcpy (*data, &value_a, sizeof(value_a));
    *data_size = sizeof(value_a);
    return GNUNET_OK;

  case GNUNET_DNSPARSER_TYPE_NS: {
      char nsbuf[256];
      size_t off;

      off = 0;
      if (GNUNET_OK !=
          GNUNET_DNSPARSER_builder_add_name (nsbuf, sizeof(nsbuf), &off, s))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to serialize NS record with value `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      GNUNET_memcpy (*data, nsbuf, off);
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_CNAME: {
      char cnamebuf[256];
      size_t off;

      off = 0;
      if (GNUNET_OK != GNUNET_DNSPARSER_builder_add_name (cnamebuf,
                                                          sizeof(cnamebuf),
                                                          &off,
                                                          s))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to serialize CNAME record with value `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      GNUNET_memcpy (*data, cnamebuf, off);
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_CERT: {
      char *sdup;
      const char *typep;
      const char *keyp;
      const char *algp;
      const char *certp;
      unsigned int cert_rrtype;
      unsigned int key;
      unsigned int alg;
      size_t cert_size;
      char *cert_data;
      struct GNUNET_DNSPARSER_CertRecord cert;

      sdup = GNUNET_strdup (s);
      typep = strtok (sdup, " ");
      if ((NULL == typep) ||
          ((0 == (cert_rrtype = rfc4398_mnemonic_to_value (typep))) &&
           ((1 != sscanf (typep, "%u", &cert_rrtype)) || (cert_rrtype >
                                                          UINT16_MAX))))
      {
        GNUNET_free (sdup);
        return GNUNET_SYSERR;
      }
      keyp = strtok (NULL, " ");
      if ((NULL == keyp) || (1 != sscanf (keyp, "%u", &key)) ||
          (key > UINT16_MAX))
      {
        GNUNET_free (sdup);
        return GNUNET_SYSERR;
      }
      alg = 0;
      algp = strtok (NULL, " ");
      if ((NULL == algp) ||
          ((0 == (cert_rrtype = rfc4034_mnemonic_to_value (typep))) &&
           ((1 != sscanf (algp, "%u", &alg)) || (alg > UINT8_MAX))))
      {
        GNUNET_free (sdup);
        return GNUNET_SYSERR;
      }
      certp = strtok (NULL, " ");
      if ((NULL == certp) || (0 == strlen (certp)))
      {
        GNUNET_free (sdup);
        return GNUNET_SYSERR;
      }
      cert_size = GNUNET_STRINGS_base64_decode (certp,
                                                strlen (certp),
                                                (void **) &cert_data);
      GNUNET_free (sdup);
      cert.cert_type = cert_rrtype;
      cert.cert_tag = key;
      cert.algorithm = alg;
      cert.certificate_size = cert_size;
      cert.certificate_data = cert_data;
      {
        char certbuf[cert_size + sizeof(struct GNUNET_TUN_DnsCertRecord)];
        size_t off;

        off = 0;
        if (GNUNET_OK != GNUNET_DNSPARSER_builder_add_cert (certbuf,
                                                            sizeof(certbuf),
                                                            &off,
                                                            &cert))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _ ("Failed to serialize CERT record with %u bytes\n"),
                      (unsigned int) cert_size);
          GNUNET_free (cert_data);
          return GNUNET_SYSERR;
        }
        *data_size = off;
        *data = GNUNET_malloc (off);
        GNUNET_memcpy (*data, certbuf, off);
      }
      GNUNET_free (cert_data);
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_SOA: {
      struct GNUNET_DNSPARSER_SoaRecord soa;
      char soabuf[540];
      char soa_rname[253 + 1];
      char soa_mname[253 + 1];
      unsigned int soa_serial;
      unsigned int soa_refresh;
      unsigned int soa_retry;
      unsigned int soa_expire;
      unsigned int soa_min;
      size_t off;

      if (7 != sscanf (s,
                       "%253s %253s ( %u %u %u %u %u )",
                       soa_rname,
                       soa_mname,
                       &soa_serial,
                       &soa_refresh,
                       &soa_retry,
                       &soa_expire,
                       &soa_min))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse SOA record `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      soa.mname = soa_mname;
      soa.rname = soa_rname;
      soa.serial = (uint32_t) soa_serial;
      soa.refresh = (uint32_t) soa_refresh;
      soa.retry = (uint32_t) soa_retry;
      soa.expire = (uint32_t) soa_expire;
      soa.minimum_ttl = (uint32_t) soa_min;
      off = 0;
      if (GNUNET_OK !=
          GNUNET_DNSPARSER_builder_add_soa (soabuf, sizeof(soabuf), &off, &soa))
      {
        GNUNET_log (
          GNUNET_ERROR_TYPE_ERROR,
          _ ("Failed to serialize SOA record with mname `%s' and rname `%s'\n"),
          soa_mname,
          soa_rname);
        return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      GNUNET_memcpy (*data, soabuf, off);
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_PTR: {
      char ptrbuf[256];
      size_t off;

      off = 0;
      if (GNUNET_OK !=
          GNUNET_DNSPARSER_builder_add_name (ptrbuf, sizeof(ptrbuf), &off, s))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to serialize PTR record with value `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      GNUNET_memcpy (*data, ptrbuf, off);
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_MX: {
      struct GNUNET_DNSPARSER_MxRecord mx;
      char mxbuf[258];
      char mxhost[253 + 1];
      unsigned int mx_pref;
      size_t off;

      if (2 != sscanf (s, "%u %253s", &mx_pref, mxhost))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse MX record `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      mx.preference = (uint16_t) mx_pref;
      mx.mxhost = mxhost;
      off = 0;

      if (GNUNET_OK !=
          GNUNET_DNSPARSER_builder_add_mx (mxbuf, sizeof(mxbuf), &off, &mx))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to serialize MX record with hostname `%s'\n"),
                    mxhost);
        return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      GNUNET_memcpy (*data, mxbuf, off);
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_SRV: {
      struct GNUNET_DNSPARSER_SrvRecord srv;
      char srvbuf[270];
      char srvtarget[253 + 1];
      unsigned int priority;
      unsigned int weight;
      unsigned int port;
      size_t off;

      if (4 != sscanf (s, "%u %u %u %253s", &priority, &weight, &port,
                       srvtarget))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse SRV record `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      srv.priority = (uint16_t) priority;
      srv.weight = (uint16_t) weight;
      srv.port = (uint16_t) port;
      srv.target = srvtarget;
      off = 0;
      if (GNUNET_OK !=
          GNUNET_DNSPARSER_builder_add_srv (srvbuf, sizeof(srvbuf), &off, &srv))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to serialize SRV record with target `%s'\n"),
                    srvtarget);
        return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      GNUNET_memcpy (*data, srvbuf, off);
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_URI: {
      struct GNUNET_DNSPARSER_UriRecord uri;
      char target[strlen (s) + 1];
      unsigned int priority;
      unsigned int weight;
      size_t off;

      if (3 != sscanf (s, "%u %u \"%s", &priority, &weight, &target[0])) // only \" before %s because %s will consume the ending " of the presentation of the URI record
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse URI record `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      target[strlen (target) - 1] = '\0'; // Removing the last " of the presentation of the URI record

      uri.priority = (uint16_t) priority;
      uri.weight = (uint16_t) weight;
      uri.target = target;
      off = 0;

      // TODO add more precise uri checking (RFC3986)
      if (strstr (target, ":") == NULL ||
          target[0] == 58 ||
          target[strlen (target) - 1] == 58)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to serialize URI record with target `%s'\n"),
                    target);
        return GNUNET_SYSERR;
      }
      {
        char uribuf[sizeof(struct GNUNET_TUN_DnsUriRecord) + strlen (target) + 1
        ];

        if (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_uri (uribuf, sizeof(uribuf), &off, &uri
                                              ))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _ ("Failed to serialize URI record with target `%s'\n"),
                      target);
          return GNUNET_SYSERR;
        }
        *data_size = off;
        *data = GNUNET_malloc (off);
        GNUNET_memcpy (*data, uribuf, off);
      }
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_TXT:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;

  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (1 != inet_pton (AF_INET6, s, &value_aaaa))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Unable to parse IPv6 address `%s'\n"),
                  s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_new (struct in6_addr);
    *data_size = sizeof(struct in6_addr);
    GNUNET_memcpy (*data, &value_aaaa, sizeof(value_aaaa));
    return GNUNET_OK;

  case GNUNET_DNSPARSER_TYPE_SMIMEA:
  case GNUNET_DNSPARSER_TYPE_TLSA: {
      unsigned int usage;
      unsigned int selector;
      unsigned int matching_type;
      size_t slen = strlen (s) + 1;
      char hex[slen];

      if (4 != sscanf (s, "%u %u %u %s", &usage, &selector, &matching_type,
                       hex))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse TLSA/SMIMEA record string `%s'\n"),
                    s);
        *data_size = 0;
        return GNUNET_SYSERR;
      }

      *data_size = sizeof(struct GNUNET_TUN_DnsTlsaRecord) + strlen (hex) / 2;
      *data = tlsa = GNUNET_malloc (*data_size);
      tlsa->usage = (uint8_t) usage;
      tlsa->selector = (uint8_t) selector;
      tlsa->matching_type = (uint8_t) matching_type;
      if (strlen (hex) / 2 != GNUNET_DNSPARSER_hex_to_bin (hex, &tlsa[1]))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse TLSA/SMIMEA record string `%s'\n"),
                    s);
        GNUNET_free (*data);
        *data = NULL;
        *data_size = 0;
        return GNUNET_SYSERR;
      }
      return GNUNET_OK;
    }

  case GNUNET_DNSPARSER_TYPE_CAA: {   // RFC6844
      struct GNUNET_DNSPARSER_CaaRecord *caa;
      unsigned int flags;
      char tag[15]; // Max tag length 15
      char value[strlen (s) + 1]; // Should be more than enough

      if (3 != sscanf (s, "%u %s %[^\n]", &flags, tag, value))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse CAA record string `%s'\n"),
                    s);
        *data_size = 0;
        return GNUNET_SYSERR;
      }
      *data_size = sizeof(struct GNUNET_DNSPARSER_CaaRecord) + strlen (tag)
                   + strlen (value);
      *data = caa = GNUNET_malloc (*data_size);
      caa->flags = flags;
      memcpy (&caa[1], tag, strlen (tag));
      caa->tag_len = strlen (tag);
      memcpy ((char *) &caa[1] + caa->tag_len, value, strlen (value));
      return GNUNET_OK;
    }

  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of record type numbers to human-readable
 * record type names.
 */
static struct
{
  const char *name;
  uint32_t number;
} name_map[] = { { "A", GNUNET_DNSPARSER_TYPE_A },
                 { "NS", GNUNET_DNSPARSER_TYPE_NS },
                 { "CNAME", GNUNET_DNSPARSER_TYPE_CNAME },
                 { "SOA", GNUNET_DNSPARSER_TYPE_SOA },
                 { "PTR", GNUNET_DNSPARSER_TYPE_PTR },
                 { "MX", GNUNET_DNSPARSER_TYPE_MX },
                 { "TXT", GNUNET_DNSPARSER_TYPE_TXT },
                 { "AAAA", GNUNET_DNSPARSER_TYPE_AAAA },
                 { "SRV", GNUNET_DNSPARSER_TYPE_SRV },
                 { "URI", GNUNET_DNSPARSER_TYPE_URI },
                 { "TLSA", GNUNET_DNSPARSER_TYPE_TLSA },
                 { "SMIMEA", GNUNET_DNSPARSER_TYPE_SMIMEA },
                 { "CERT", GNUNET_DNSPARSER_TYPE_CERT },
                 { "CAA", GNUNET_DNSPARSER_TYPE_CAA },
                 { NULL, UINT32_MAX } };


/**
 * Convert a type name (e.g. "AAAA") to the corresponding number.
 *
 * @param cls closure, unused
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
static uint32_t
dns_typename_to_number (void *cls, const char *dns_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != name_map[i].name) &&
         (0 != strcasecmp (dns_typename, name_map[i].name)))
    i++;
  return name_map[i].number;
}


/**
 * Convert a type number to the corresponding type string (e.g. 1 to "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
dns_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != name_map[i].name) && (type != name_map[i].number))
    i++;
  return name_map[i].name;
}


static enum GNUNET_GenericReturnValue
dns_is_critical (void *cls, uint32_t type)
{
  return GNUNET_NO;
}


void *
libgnunet_plugin_gnsrecord_dns_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_gnsrecord_dns_init (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_GNSRECORD_PluginFunctions);
  api->value_to_string = &dns_value_to_string;
  api->string_to_value = &dns_string_to_value;
  api->typename_to_number = &dns_typename_to_number;
  api->number_to_typename = &dns_number_to_typename;
  api->is_critical = &dns_is_critical;
  return api;
}


void *
libgnunet_plugin_gnsrecord_dns_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_plugin_gnsrecord_dns_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_gnsrecord_dns.c */
