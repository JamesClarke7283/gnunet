/*
      This file is part of GNUnet
      Copyright (C) 2013, 2016 GNUnet e.V.

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
 * @file revocation/revocation_api.c
 * @brief API to perform and access key revocations
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_revocation_service.h"
#include "gnunet_signatures.h"
#include "gnunet_protocols.h"
#include "revocation.h"
#include <inttypes.h>

/**
 * Handle for the key revocation query.
 */
struct GNUNET_REVOCATION_Query
{
  /**
   * Message queue to the service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call with the result.
   */
  GNUNET_REVOCATION_Callback func;

  /**
   * Closure for @e func.
   */
  void *func_cls;
};


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NSE_Handle *`
 * @param error error code
 */
static void
query_mq_error_handler (void *cls,
                        enum GNUNET_MQ_Error error)
{
  struct GNUNET_REVOCATION_Query *q = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Revocation query MQ error\n");
  q->func (q->func_cls,
           GNUNET_SYSERR);
  GNUNET_REVOCATION_query_cancel (q);
}


/**
 * Handle response to our revocation query.
 *
 * @param cls our `struct GNUNET_REVOCATION_Query` handle
 * @param qrm response we got
 */
static void
handle_revocation_query_response (void *cls,
                                  const struct QueryResponseMessage *qrm)
{
  struct GNUNET_REVOCATION_Query *q = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Revocation query result: %d\n",
              (uint32_t) ntohl (qrm->is_valid));
  q->func (q->func_cls,
           ntohl (qrm->is_valid));
  GNUNET_REVOCATION_query_cancel (q);
}


/**
 * Check if a key was revoked.
 *
 * @param cfg the configuration to use
 * @param key key to check for revocation
 * @param func function to call with the result of the check
 * @param func_cls closure to pass to @a func
 * @return handle to use in #GNUNET_REVOCATION_query_cancel to stop REVOCATION from invoking the callback
 */
struct GNUNET_REVOCATION_Query *
GNUNET_REVOCATION_query (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         const struct GNUNET_CRYPTO_PublicKey *key,
                         GNUNET_REVOCATION_Callback func,
                         void *func_cls)
{
  struct GNUNET_REVOCATION_Query *q
    = GNUNET_new (struct GNUNET_REVOCATION_Query);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (revocation_query_response,
                             GNUNET_MESSAGE_TYPE_REVOCATION_QUERY_RESPONSE,
                             struct QueryResponseMessage,
                             q),
    GNUNET_MQ_handler_end ()
  };
  struct QueryMessage *qm;
  struct GNUNET_MQ_Envelope *env;
  size_t key_len;

  q->mq = GNUNET_CLIENT_connect (cfg,
                                 "revocation",
                                 handlers,
                                 &query_mq_error_handler,
                                 q);
  if (NULL == q->mq)
  {
    GNUNET_free (q);
    return NULL;
  }
  q->func = func;
  q->func_cls = func_cls;
  key_len = GNUNET_CRYPTO_public_key_get_length (key);
  env = GNUNET_MQ_msg_extra (qm, key_len,
                             GNUNET_MESSAGE_TYPE_REVOCATION_QUERY);
  GNUNET_CRYPTO_write_public_key_to_buffer (key, &qm[1], key_len);
  qm->key_len = htonl (key_len);
  GNUNET_MQ_send (q->mq,
                  env);
  return q;
}


/**
 * Cancel key revocation check.
 *
 * @param q query to cancel
 */
void
GNUNET_REVOCATION_query_cancel (struct GNUNET_REVOCATION_Query *q)
{
  if (NULL != q->mq)
  {
    GNUNET_MQ_destroy (q->mq);
    q->mq = NULL;
  }
  GNUNET_free (q);
}


/**
 * Handle for the key revocation operation.
 */
struct GNUNET_REVOCATION_Handle
{
  /**
   * Message queue to the service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call once we are done.
   */
  GNUNET_REVOCATION_Callback func;

  /**
   * Closure for @e func.
   */
  void *func_cls;
};


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NSE_Handle *`
 * @param error error code
 */
static void
revocation_mq_error_handler (void *cls,
                             enum GNUNET_MQ_Error error)
{
  struct GNUNET_REVOCATION_Handle *h = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Revocation MQ error\n");
  h->func (h->func_cls,
           GNUNET_SYSERR);
  GNUNET_REVOCATION_revoke_cancel (h);
}


/**
 * Handle response to our revocation query.
 *
 * @param cls our `struct GNUNET_REVOCATION_Handle` handle
 * @param rrm response we got
 */
static void
handle_revocation_response (void *cls,
                            const struct RevocationResponseMessage *rrm)
{
  struct GNUNET_REVOCATION_Handle *h = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Revocation transmission result: %d\n",
              (uint32_t) ntohl (rrm->is_valid));
  h->func (h->func_cls,
           ntohl (rrm->is_valid));
  GNUNET_REVOCATION_revoke_cancel (h);
}


/**
 * Perform key revocation.
 *
 * @param cfg the configuration to use
 * @param key public key of the key to revoke
 * @param sig signature to use on the revocation (should have been
 *            created using #GNUNET_REVOCATION_sign_revocation).
 * @param ts  revocation timestamp
 * @param pow proof of work to use (should have been created by
 *            iteratively calling #GNUNET_REVOCATION_check_pow)
 * @param func function to call with the result of the check
 *             (called with `is_valid` being #GNUNET_NO if
 *              the revocation worked).
 * @param func_cls closure to pass to @a func
 * @return handle to use in #GNUNET_REVOCATION_revoke_cancel to stop REVOCATION from invoking the callback
 */
struct GNUNET_REVOCATION_Handle *
GNUNET_REVOCATION_revoke (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_GNSRECORD_PowP *pow,
                          GNUNET_REVOCATION_Callback func,
                          void *func_cls)
{
  struct GNUNET_REVOCATION_Handle *h
    = GNUNET_new (struct GNUNET_REVOCATION_Handle);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (revocation_response,
                             GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE,
                             struct RevocationResponseMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };
  unsigned long long matching_bits;
  struct GNUNET_TIME_Relative epoch_duration;
  struct RevokeMessage *rm;
  struct GNUNET_MQ_Envelope *env;

  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (cfg,
                                              "REVOCATION",
                                              "WORKBITS",
                                              &matching_bits)))
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_time (cfg,
                                            "REVOCATION",
                                            "EPOCH_DURATION",
                                            &epoch_duration)))
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  if (GNUNET_YES != GNUNET_GNSRECORD_check_pow (pow,
                                                (unsigned int) matching_bits,
                                                epoch_duration))
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }


  h->mq = GNUNET_CLIENT_connect (cfg,
                                 "revocation",
                                 handlers,
                                 &revocation_mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  h->func = func;
  h->func_cls = func_cls;
  {
    size_t extra_len = GNUNET_GNSRECORD_proof_get_size (pow);
    env = GNUNET_MQ_msg_extra (rm,
                               extra_len,
                               GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE);
    rm->pow_size = htonl (extra_len);
    memcpy (&rm[1], pow, extra_len);
  }
  GNUNET_MQ_send (h->mq,
                  env);
  return h;
}


void
GNUNET_REVOCATION_revoke_cancel (struct GNUNET_REVOCATION_Handle *h)
{
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h);
}


/* end of revocation_api.c */
