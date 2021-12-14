/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016, 2020 GNUnet e.V.

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
 * @file pq/pq_query_helper.c
 * @brief functions to initialize parameter arrays
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_null (void *cls,
            const void *data,
            size_t data_len,
            void *param_values[],
            int param_lengths[],
            int param_formats[],
            unsigned int param_length,
            void *scratch[],
            unsigned int scratch_length)
{
  (void) scratch;
  (void) scratch_length;
  (void) data;
  (void) data_len;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  param_values[0] = NULL;
  param_lengths[0] = 0;
  param_formats[0] = 1;
  return 0;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_null (void)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_null,
    .num_params = 1
  };

  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_fixed (void *cls,
             const void *data,
             size_t data_len,
             void *param_values[],
             int param_lengths[],
             int param_formats[],
             unsigned int param_length,
             void *scratch[],
             unsigned int scratch_length)
{
  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  param_values[0] = (void *) data;
  param_lengths[0] = data_len;
  param_formats[0] = 1;
  return 0;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_fixed_size (const void *ptr,
                                  size_t ptr_size)
{
  struct GNUNET_PQ_QueryParam res = {
    &qconv_fixed, NULL, ptr, ptr_size, 1
  };

  return res;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_string (const char *ptr)
{
  return GNUNET_PQ_query_param_fixed_size (ptr,
                                           strlen (ptr));
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_bool (bool b)
{
  static uint8_t bt = 1;
  static uint8_t bf = 0;

  return GNUNET_PQ_query_param_fixed_size (b ? &bt : &bf,
                                           sizeof (uint8_t));
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_uint16 (void *cls,
              const void *data,
              size_t data_len,
              void *param_values[],
              int param_lengths[],
              int param_formats[],
              unsigned int param_length,
              void *scratch[],
              unsigned int scratch_length)
{
  const uint16_t *u_hbo = data;
  uint16_t *u_nbo;

  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint16_t);
  scratch[0] = u_nbo;
  *u_nbo = htons (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint16_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint16 (const uint16_t *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_uint16,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_uint32 (void *cls,
              const void *data,
              size_t data_len,
              void *param_values[],
              int param_lengths[],
              int param_formats[],
              unsigned int param_length,
              void *scratch[],
              unsigned int scratch_length)
{
  const uint32_t *u_hbo = data;
  uint32_t *u_nbo;

  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint32_t);
  scratch[0] = u_nbo;
  *u_nbo = htonl (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint32_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint32 (const uint32_t *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_uint32,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_uint64 (void *cls,
              const void *data,
              size_t data_len,
              void *param_values[],
              int param_lengths[],
              int param_formats[],
              unsigned int param_length,
              void *scratch[],
              unsigned int scratch_length)
{
  const uint64_t *u_hbo = data;
  uint64_t *u_nbo;

  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint64_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint64 (const uint64_t *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_uint64,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_rsa_public_key (void *cls,
                      const void *data,
                      size_t data_len,
                      void *param_values[],
                      int param_lengths[],
                      int param_formats[],
                      unsigned int param_length,
                      void *scratch[],
                      unsigned int scratch_length)
{
  const struct GNUNET_CRYPTO_RsaPublicKey *rsa = data;
  void *buf;
  size_t buf_size;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  buf_size = GNUNET_CRYPTO_rsa_public_key_encode (rsa,
                                                  &buf);
  scratch[0] = buf;
  param_values[0] = (void *) buf;
  param_lengths[0] = buf_size;
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_public_key (
  const struct GNUNET_CRYPTO_RsaPublicKey *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_rsa_public_key,
    .data = x,
    .num_params = 1
  };

  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_rsa_signature (void *cls,
                     const void *data,
                     size_t data_len,
                     void *param_values[],
                     int param_lengths[],
                     int param_formats[],
                     unsigned int param_length,
                     void *scratch[],
                     unsigned int scratch_length)
{
  const struct GNUNET_CRYPTO_RsaSignature *sig = data;
  void *buf;
  size_t buf_size;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  buf_size = GNUNET_CRYPTO_rsa_signature_encode (sig,
                                                 &buf);
  scratch[0] = buf;
  param_values[0] = (void *) buf;
  param_lengths[0] = buf_size;
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_rsa_signature,
    .data = x,
    .num_params = 1
  };

  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_rel_time (void *cls,
                const void *data,
                size_t data_len,
                void *param_values[],
                int param_lengths[],
                int param_formats[],
                unsigned int param_length,
                void *scratch[],
                unsigned int scratch_length)
{
  const struct GNUNET_TIME_Relative *u = data;
  struct GNUNET_TIME_Relative rel;
  uint64_t *u_nbo;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  rel = *u;
  if (rel.rel_value_us > INT64_MAX)
    rel.rel_value_us = INT64_MAX;
  u_nbo = GNUNET_new (uint64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (rel.rel_value_us);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint64_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_relative_time (const struct GNUNET_TIME_Relative *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_rel_time,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_abs_time (void *cls,
                const void *data,
                size_t data_len,
                void *param_values[],
                int param_lengths[],
                int param_formats[],
                unsigned int param_length,
                void *scratch[],
                unsigned int scratch_length)
{
  const struct GNUNET_TIME_Absolute *u = data;
  struct GNUNET_TIME_Absolute abs;
  uint64_t *u_nbo;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  abs = *u;
  if (abs.abs_value_us > INT64_MAX)
    abs.abs_value_us = INT64_MAX;
  u_nbo = GNUNET_new (uint64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (abs.abs_value_us);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint64_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_abs_time,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time_nbo (
  const struct GNUNET_TIME_AbsoluteNBO *x)
{
  return GNUNET_PQ_query_param_auto_from_type (&x->abs_value_us__);
}


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_timestamp (void *cls,
                 const void *data,
                 size_t data_len,
                 void *param_values[],
                 int param_lengths[],
                 int param_formats[],
                 unsigned int param_length,
                 void *scratch[],
                 unsigned int scratch_length)
{
  const struct GNUNET_TIME_Timestamp *u = data;
  struct GNUNET_TIME_Absolute abs;
  uint64_t *u_nbo;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  abs = u->abs_time;
  if (abs.abs_value_us > INT64_MAX)
    abs.abs_value_us = INT64_MAX;
  u_nbo = GNUNET_new (uint64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (abs.abs_value_us);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint64_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_timestamp (const struct GNUNET_TIME_Timestamp *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_timestamp,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_timestamp_nbo (
  const struct GNUNET_TIME_TimestampNBO *x)
{
  return GNUNET_PQ_query_param_absolute_time_nbo (&x->abs_time_nbo);
}


/* end of pq_query_helper.c */
