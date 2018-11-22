/*
     This file is part of GNUnet.
     Copyright (C) 2018 GNUnet e.V.

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
*/

/**
 * @file hello/hello-ng.c
 * @brief helper library for handling HELLOs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_signatures.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"

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
   * When does the address expire.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Hash of the address.
   */
  struct GNUNET_HashCode h_addr;
};


/**
 * Build address record by signing raw information with private key.
 *
 * @param address text address at @a communicator to sign
 * @param expiration how long is @a address valid
 * @param private_key signing key to use
 * @param result[out] where to write address record (allocated)
 * @param result_size[out] set to size of @a result
 */
void
GNUNET_HELLO_sign_address (const char *address,
			   struct GNUNET_TIME_Absolute expiration,
			   const struct GNUNET_CRYPTO_EddsaPrivateKey *private_key,
			   void **result,
			   size_t *result_size)
{
  struct SignedAddress sa;
  struct GNUNET_CRYPTO_EddsaSignature sig;
  char *sig_str;
  
  sa.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_ADDRESS);
  sa.purpose.size = htonl (sizeof (sa));
  sa.expiration = GNUNET_TIME_absolute_hton (expiration);
  GNUNET_CRYPTO_hash (address,
		      strlen (address),
		      &sa.h_addr);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CRYPTO_eddsa_sign (private_key,
					   &sa.purpose,
					   &sig));
  sig_str = NULL;
  (void) GNUNET_STRINGS_base64_encode (&sig,
				       sizeof (sig),
				       &sig_str);
  *result_size = 1 + GNUNET_asprintf ((char **) result,
				      "%s;%llu;%s",
				      sig_str,
				      (unsigned long long) expiration.abs_value_us,
				      address);
  GNUNET_free (sig_str);  
}

			   
/**
 * Check signature and extract address record.
 *
 * @param raw raw signed address
 * @param raw_size size of @a raw
 * @param public_key public key to use for signature verification
 * @param expiration[out] how long is the address valid
 * @return NULL on error, otherwise the address
 */
char *
GNUNET_HELLO_extract_address (const void *raw,
			      size_t raw_size,
			      const struct GNUNET_CRYPTO_EddsaPublicKey *public_key,
			      struct GNUNET_TIME_Absolute *expiration)
{
  const char *raws = raw;
  unsigned long long raw_us;
  const char *sc;
  const char *sc2;
  const char *raw_addr;
  struct GNUNET_TIME_Absolute raw_expiration;
  struct SignedAddress sa;
  struct GNUNET_CRYPTO_EddsaSignature *sig;

  if ('\0' != raws[raw_size])
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if (NULL == (sc = strchr (raws,
			    ';')))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if (NULL == (sc2 = strchr (sc + 1,
			     ';')))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if (1 != sscanf (sc + 1,
		   "%llu;",
		   &raw_us))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  raw_expiration.abs_value_us = raw_us;
  if (0 == GNUNET_TIME_absolute_get_remaining (raw_expiration).rel_value_us)
    return NULL; /* expired */
  sig = NULL;
  if (sizeof (struct GNUNET_CRYPTO_EddsaSignature) !=
      GNUNET_STRINGS_base64_decode (raws,
				    sc - raws,
				    (void **) &sig))
  {
    GNUNET_break_op (0);
    GNUNET_free_non_null (sig);
    return NULL;
  }
  raw_addr = sc2 + 1;
  
  sa.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_ADDRESS);
  sa.purpose.size = htonl (sizeof (sa));
  sa.expiration = GNUNET_TIME_absolute_hton (raw_expiration);
  GNUNET_CRYPTO_hash (raw_addr,
		      strlen (raw_addr),
		      &sa.h_addr);
  if (GNUNET_YES !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_ADDRESS,
				  &sa.purpose,
				  sig,
				  public_key))
  {
    GNUNET_break_op (0);
    GNUNET_free (sig);
    return NULL;
  }
  GNUNET_free (sig);
  return GNUNET_strdup (raw_addr);
}

			   
