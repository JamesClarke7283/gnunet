/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2023 GNUnet e.V.

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
 * @file util/test_crypto_rsa.c
 * @brief testcase for utility functions for RSA cryptography
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Jeffrey Burdges <burdges@gnunet.org>
 */

#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"

#define KEY_SIZE 1024


int
main (int argc,
      char *argv[])
{
#define RND_BLK_SIZE 4096
  unsigned char rnd_blk[RND_BLK_SIZE];
  struct GNUNET_CRYPTO_RsaPrivateKey *priv;
  struct GNUNET_CRYPTO_RsaPrivateKey *priv_copy;
  struct GNUNET_CRYPTO_RsaPublicKey *pub;
  struct GNUNET_CRYPTO_RsaPublicKey *pub_copy;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_CRYPTO_RsaSignature *sig_copy;
  struct GNUNET_CRYPTO_RsaSignature *bsig;
  struct GNUNET_CRYPTO_RsaBlindingKeySecret bsec;
  struct GNUNET_HashCode hash;

  GNUNET_log_setup ("test-crypto-rsa",
                    "WARNING",
                    NULL);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              rnd_blk,
                              RND_BLK_SIZE);
  GNUNET_CRYPTO_hash (rnd_blk,
                      RND_BLK_SIZE,
                      &hash);
  priv = GNUNET_CRYPTO_rsa_private_key_create (KEY_SIZE);
  priv_copy = GNUNET_CRYPTO_rsa_private_key_dup (priv);
  GNUNET_assert (NULL != priv_copy);
  GNUNET_assert (0 == GNUNET_CRYPTO_rsa_private_key_cmp (priv,
                                                         priv_copy));
  pub = GNUNET_CRYPTO_rsa_private_key_get_public (priv);

  {
    /* Encoding */
    size_t size;
    void *enc;
    enc = NULL;
    size = GNUNET_CRYPTO_rsa_private_key_encode (priv,
                                                 &enc);

    /* Decoding */
    GNUNET_CRYPTO_rsa_private_key_free (priv);
    priv = NULL;
    priv = GNUNET_CRYPTO_rsa_private_key_decode (enc,
                                                 size);
    GNUNET_assert (NULL != priv);
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                enc,
                                size);
    GNUNET_assert (NULL ==
                   GNUNET_CRYPTO_rsa_private_key_decode (enc,
                                                         size));
    (void) fprintf (stderr,
                    "The above warning is expected.\n");
    GNUNET_free (enc);

    /* try ordinary sig first */
    sig = GNUNET_CRYPTO_rsa_sign_fdh (priv,
                                      &hash,
                                      sizeof (hash));
    sig_copy = GNUNET_CRYPTO_rsa_signature_dup (sig);
    GNUNET_assert (NULL != sig);
    GNUNET_assert (0 == GNUNET_CRYPTO_rsa_signature_cmp (sig,
                                                         sig_copy));
    pub_copy = GNUNET_CRYPTO_rsa_public_key_dup (pub);
    GNUNET_assert (NULL != pub_copy);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_rsa_verify (&hash,
                                             sizeof (hash),
                                             sig,
                                             pub_copy));
  }

  {
    void *buf;
    size_t buf_size;
    struct GNUNET_CRYPTO_RsaPublicKey *pub2;
    struct GNUNET_CRYPTO_RsaSignature *sig2;

    buf_size = GNUNET_CRYPTO_rsa_public_key_encode (pub,
                                                    &buf);
    pub2 = GNUNET_CRYPTO_rsa_public_key_decode (buf,
                                                buf_size);
    GNUNET_free (buf);
    buf_size = GNUNET_CRYPTO_rsa_signature_encode (sig,
                                                   &buf);
    sig2 = GNUNET_CRYPTO_rsa_signature_decode (buf,
                                               buf_size);
    GNUNET_free (buf);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_rsa_verify (&hash,
                                             sizeof (hash),
                                             sig2,
                                             pub2));
    GNUNET_CRYPTO_rsa_public_key_free (pub2);
    GNUNET_CRYPTO_rsa_signature_free (sig2);
  }
  /* corrupt our hash and see if the signature is still valid */
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              &hash,
                              sizeof(hash));
  GNUNET_assert (GNUNET_OK !=
                 GNUNET_CRYPTO_rsa_verify (&hash,
                                           sizeof (hash),
                                           sig,
                                           pub));
  (void) fprintf (stderr,
                  "The above warning is expected.\n");
  GNUNET_CRYPTO_rsa_signature_free (sig);

  /* test blind signing */
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              &bsec,
                              sizeof(bsec));
  {
    struct GNUNET_CRYPTO_RsaBlindedMessage bm;
    GNUNET_CRYPTO_rsa_blind (&hash,
                             sizeof (hash),
                             &bsec,
                             pub,
                             &bm);
    bsig = GNUNET_CRYPTO_rsa_sign_blinded (priv,
                                           &bm);
    GNUNET_CRYPTO_rsa_blinded_message_free (&bm);
  }
  sig = GNUNET_CRYPTO_rsa_unblind (bsig,
                                   &bsec,
                                   pub);
  GNUNET_CRYPTO_rsa_signature_free (bsig);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_verify (&hash,
                                           sizeof (hash),
                                           sig,
                                           pub));
  GNUNET_CRYPTO_rsa_signature_free (sig);
  GNUNET_CRYPTO_rsa_signature_free (sig_copy);
  GNUNET_CRYPTO_rsa_private_key_free (priv);
  GNUNET_CRYPTO_rsa_private_key_free (priv_copy);
  GNUNET_CRYPTO_rsa_public_key_free (pub);
  GNUNET_CRYPTO_rsa_public_key_free (pub_copy);
  return 0;
}
