/*
    Copyright (c) 2010 Nils Durner

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
 */

/**
 * @file src/util/test_crypt_hkdf.c
 * @brief Testcases for HKDF
 * @todo: test for out_len < hash_len
 * @author Nils Durner
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"


void
tc1 (void)
{
  unsigned char ikm[22] =
  { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
  unsigned char salt[13] =
  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c };
  unsigned char info[10] =
  { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
  unsigned char okm[42] =
  { 0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43,
    0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
    0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00,
    0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65 };
  unsigned char result[44];
  int l = 42;
  struct GNUNET_ShortHashCode prk;

  memset (result, 0, sizeof(result));
  GNUNET_CRYPTO_hkdf_extract (&prk, salt, sizeof(salt), ikm, sizeof(ikm));
  GNUNET_assert (GNUNET_CRYPTO_hkdf_expand
                   (result, l, &prk, info, sizeof(info),
                   NULL) == GNUNET_YES);
  GNUNET_assert (memcmp (result, okm, l) == 0);
  GNUNET_assert (memcmp (result + l, "\0", 2) == 0);
}


void
tc2 ()
{
  unsigned char ikm[80] =
  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
    0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
    0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
    0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
  unsigned char salt[80] =
  { 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
    0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
    0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };
  unsigned char info[80] =
  { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9,
    0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1,
    0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
    0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
    0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
    0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
  unsigned char okm[82] =
  { 0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7,
    0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e,
    0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04,
    0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59,
    0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77,
    0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
    0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87 };
  char result[84];
  int l = 82;
  struct GNUNET_ShortHashCode prk;

  memset (result, 0, sizeof(result));
  GNUNET_CRYPTO_hkdf_extract (&prk, salt, sizeof(salt), ikm, sizeof(ikm));
  GNUNET_assert (GNUNET_CRYPTO_hkdf_expand
                   (result, l, &prk, info, sizeof(info),
                   NULL) == GNUNET_YES);
  GNUNET_assert (memcmp (result, okm, l) == 0);
  GNUNET_assert (memcmp (result + l, "\0", 2) == 0);
}


void
tc3 ()
{
  unsigned char ikm[22] =
  { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
  unsigned char okm[42] =
  { 0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f,
    0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1,
    0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20,
    0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8 };
  unsigned char result[44];
  int l = 42;
  struct GNUNET_ShortHashCode prk;

  memset (result, 0, sizeof(result));
  GNUNET_CRYPTO_hkdf_extract (&prk, NULL, 0, ikm, sizeof(ikm));
  GNUNET_assert (GNUNET_CRYPTO_hkdf_expand
                   (result, l, &prk, NULL, 0, NULL) == GNUNET_YES);
  GNUNET_assert (memcmp (result, okm, l) == 0);
  GNUNET_assert (memcmp (result + l, "\0", 2) == 0);
}


void
tc8 ()
{
  unsigned char ikm[32] =
  { 0xbf, 0x16, 0x6e, 0x46, 0x3a, 0x6c, 0xf3, 0x93, 0xa7, 0x72,
    0x11, 0xa1, 0xdc, 0x0b, 0x07, 0xdb, 0x1a, 0x5e, 0xd9, 0xb9, 0x81, 0xbe,
    0xea, 0xe4, 0x31, 0x5f, 0x24, 0xff, 0xfe, 0x50, 0x8a, 0xde };
  unsigned char salt[4] = { 0xfc, 0x62, 0x76, 0x35 };
  unsigned char info[86] =
  { 0x8c, 0x0d, 0xcf, 0xb3, 0x25, 0x6e, 0x88, 0x0d, 0xc1, 0x0b,
    0x1d, 0x33, 0x15, 0x3e, 0x52, 0x0b, 0xb0, 0x77, 0xff, 0x7d, 0xc3, 0xc7,
    0xef, 0xe5, 0x8e, 0x3c, 0xc4, 0x4e, 0x8b, 0x41, 0x46, 0x1f, 0x02, 0x94,
    0x82, 0x35, 0xc5, 0xa6, 0x5e, 0x91, 0xd8, 0xa2, 0x90, 0xfd, 0x6f, 0xb4,
    0x07, 0xc9, 0xed, 0x6b, 0x18, 0x90, 0x31, 0xab, 0x0f, 0xb5, 0x6b, 0xec,
    0x9e, 0x45, 0xa2, 0x83, 0x65, 0x41, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61,
    0x6c, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x00 };
  unsigned char okm[16] =
  { 0xd6, 0x90, 0xec, 0x9e, 0x62, 0xdf, 0xb9, 0x41, 0xff, 0x92,
    0x4f, 0xd2, 0xf6, 0x1d, 0x67, 0xe0 };
  char result[18];
  int l = 16;

  memset (result, 0, sizeof(result));
  GNUNET_assert (GNUNET_CRYPTO_hkdf_gnunet
                   (result, l, salt, sizeof(salt),
                   ikm, sizeof(ikm), info, sizeof(info),
                   NULL) == GNUNET_YES);
  GNUNET_assert (memcmp (result, okm, l) == 0);
  GNUNET_assert (memcmp (result + l, "\0", 2) == 0);
}


int
main ()
{
  GNUNET_log_setup ("test-crypto-hkdf", "WARNING", NULL);

  /* Official test vectors */
  tc1 ();
  tc2 ();
  tc3 ();
  /*tc4 ();
  tc5 ();
  tc6 ();*/

  /* Additional tests */
  // tc7 ();
  tc8 ();

  return 0;
}
