/*
     This file is part of GNUnet
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
 * @file reclaim/vc_crypto.c
 * @author Tristan Schwieren
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_signatures.h"
#include <jansson.h>


/**
 * @brief Genereate the missing signature for a verifiable presentation
 * @param pres A verifiable presentation with an empty signature field
 * @param pk The private key which is used to generate the Signature
 * @param result The verifiable presentation containing a valid signature is returned
 */
char *
generate_signature_vp (json_t *pres,
                       const struct GNUNET_IDENTITY_PrivateKey *pk)
{
  // TODO: make sig multibase
  char *data;
  json_t *proof;

  struct GNUNET_IDENTITY_Signature sig;
  ssize_t sig_size;

  struct GNUNET_CRYPTO_EccSignaturePurpose *sig_purpose;
  ssize_t sig_purpose_size;

  void *sig_buf;
  ssize_t sig_buf_size;

  char *sig_str;
  ssize_t sig_str_size;

  char *sig_str_final;

  // Add empty signature key-value -> encode json -> delete empty signature key-value
  // FIXME: Needs a real Canonicalization Scheme
  proof = json_object_get (pres, "proof");
  json_object_set_new (proof, "signature", json_string (""));
  data = json_dumps (pres, JSON_COMPACT);
  json_object_del (proof, "signature");

  // Generate Signature
  sig_purpose_size = sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
    + strlen (data);
  sig_purpose = malloc (sig_purpose_size);
  sig_purpose->size = htonl (sig_purpose_size);
  sig_purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST); //FIXME: Actual purpose in GANA
  memcpy (&sig_purpose[1], (void *) data, strlen (data));

  GNUNET_IDENTITY_sign_ (pk,
                         sig_purpose,
                         &sig);

  GNUNET_free (data);
  GNUNET_free (sig_purpose);

  // Convert Signature to string
  sig_size = GNUNET_IDENTITY_signature_get_length (&sig);
  sig_buf = malloc (sig_size);
  sig_buf_size = GNUNET_IDENTITY_write_signature_to_buffer (&sig, sig_buf,
                                                            sig_size);
  sig_str_size = GNUNET_STRINGS_base64_encode (sig_buf, sig_buf_size, &sig_str);
  GNUNET_free (sig_buf);

  return sig_str;
}

/**
 * @brief Verfiy the the Proof of the verfiable presentation
 * @return Return 1 if the verfiable Presentation has been issued by the subject and not been manipulated in any way. Return 0 if not
 */
int
verify_vp (char *vp)
{
  json_t *pres;

  char *data;
  json_t *proof;
  const char *verification_method;
  char *pubk_str;
  struct GNUNET_IDENTITY_PublicKey *pubk;

  struct GNUNET_IDENTITY_Signature sig;
  ssize_t sig_size;

  struct GNUNET_CRYPTO_EccSignaturePurpose *sig_purpose;
  ssize_t sig_purpose_size;

  void *sig_buf;
  ssize_t sig_buf_size;

  const char *sig_str;
  ssize_t sig_str_size;

  int valid;

  pres = json_loads (vp, JSON_DECODE_ANY, NULL);

  if (NULL == pres)
    return 0; //GNUNET_SYSERR?
  // Add empty signature key-value -> encode json -> delete empty signature key-value
  // FIXME: Needs a real Canonicalization Scheme
  proof = json_object_get (pres, "proof");
  if (NULL == proof)
    return 0; //GNUNET_SYSERR?
  // Get signature
  sig_str = json_string_value (json_object_get (proof, "signature"));
  sig_str_size = strlen (sig_str);
  sig_buf = malloc (sig_str_size);
  sig_buf_size = GNUNET_STRINGS_base64_decode (sig_str, sig_str_size, sig_buf);
  sig_size = GNUNET_IDENTITY_read_signature_from_buffer (&sig, sig_buf,
                                                         sig_buf_size);
  GNUNET_free (sig_buf);

  json_object_del (proof, "signature");
  json_object_set (proof, "signature", json_string (""));
  data = json_dumps (pres, JSON_COMPACT);

  // Get pubkey from reclaim did
  verification_method = json_string_value (json_object_get (proof,
                                                            "verificationMethod"));
  //FIXME: conversion DID -> Pubkey in library
  pubk_str = malloc (sizeof(char) * 100); // FIXME: Get the real public key len
  if (1 != sscanf (verification_method, "did:reclaim:%s#key-1", pubk_str))
    return 0; //GNUNET_SYSERR free stuff
  GNUNET_IDENTITY_public_key_from_string (pubk_str, pubk);
  GNUNET_free (pubk_str);

  json_decref (pres);

  // Generate Purpose
  sig_purpose_size = sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose) + strlen (
    data);
  sig_purpose = malloc (sig_purpose_size);
  sig_purpose->size = htonl (sig_purpose_size);
  sig_purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
  memcpy (&sig_purpose[1], (void *) data, strlen (data));

  valid = GNUNET_IDENTITY_signature_verify_ (GNUNET_SIGNATURE_PURPOSE_TEST,
                                             sig_purpose,
                                             &sig,
                                             pubk);

  GNUNET_free (data);
  GNUNET_free (sig_purpose);

  return valid;
}
