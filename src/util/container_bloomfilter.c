/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2006, 2008, 2011, 2012, 2018 GNUnet e.V.

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
 * @file util/container_bloomfilter.c
 * @brief data structure used to reduce disk accesses.
 *
 * The idea basically: Create a signature for each element in the
 * database. Add those signatures to a bit array. When doing a lookup,
 * check if the bit array matches the signature of the requested
 * element. If yes, address the disk, otherwise return 'not found'.
 *
 * A property of the bloom filter is that sometimes we will have
 * a match even if the element is not on the disk (then we do
 * an unnecessary disk access), but what's most important is that
 * we never get a single "false negative".
 *
 * To be able to delete entries from the bloom filter, we maintain
 * a 4 bit counter in the file on the drive (we still use only one
 * bit in memory).
 *
 * @author Igor Wronsky
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind, ...) \
  GNUNET_log_from (kind, "util-container-bloomfilter", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
  GNUNET_log_from_strerror (kind, "util-container-bloomfilter", syscall)

#define LOG_STRERROR_FILE(kind, syscall, filename)             \
  GNUNET_log_from_strerror_file (kind,                         \
                                 "util-container-bloomfilter", \
                                 syscall,                      \
                                 filename)

struct GNUNET_CONTAINER_BloomFilter
{
  /**
   * The actual bloomfilter bit array
   */
  char *bitArray;

  /**
   * Filename of the filter
   */
  char *filename;

  /**
   * The bit counter file on disk
   */
  struct GNUNET_DISK_FileHandle *fh;

  /**
   * How many bits we set for each stored element
   */
  unsigned int addressesPerElement;

  /**
   * Size of bitArray in bytes
   */
  size_t bitArraySize;
};


size_t
GNUNET_CONTAINER_bloomfilter_get_element_addresses (
  const struct GNUNET_CONTAINER_BloomFilter *bf)
{
  if (bf == NULL)
    return 0;
  return bf->addressesPerElement;
}


size_t
GNUNET_CONTAINER_bloomfilter_get_size (
  const struct GNUNET_CONTAINER_BloomFilter *bf)
{
  if (bf == NULL)
    return 0;
  return bf->bitArraySize;
}


struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_copy (
  const struct GNUNET_CONTAINER_BloomFilter *bf)
{
  return GNUNET_CONTAINER_bloomfilter_init (bf->bitArray,
                                            bf->bitArraySize,
                                            bf->addressesPerElement);
}


/**
 * Sets a bit active in the bitArray. Increment bit-specific
 * usage counter on disk only if below 4bit max (==15).
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to set
 */
static void
setBit (char *bitArray,
        unsigned int bitIdx)
{
  size_t arraySlot;
  unsigned int targetBit;

  arraySlot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  bitArray[arraySlot] |= targetBit;
}


/**
 * Clears a bit from bitArray. Bit is cleared from the array
 * only if the respective usage counter on the disk hits/is zero.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to unset
 */
static void
clearBit (char *bitArray, unsigned int bitIdx)
{
  size_t slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  bitArray[slot] = bitArray[slot] & (~targetBit);
}


/**
 * Checks if a bit is active in the bitArray
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @return true if the bit is set, false if not.
 */
static bool
testBit (char *bitArray,
         unsigned int bitIdx)
{
  size_t slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  if (bitArray[slot] & targetBit)
    return true;
  return false;
}


/**
 * Sets a bit active in the bitArray and increments
 * bit-specific usage counter on disk (but only if
 * the counter was below 4 bit max (==15)).
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @param fh A file to keep the 4 bit address usage counters in
 */
static void
incrementBit (char *bitArray,
              unsigned int bitIdx,
              const struct GNUNET_DISK_FileHandle *fh)
{
  off_t fileSlot;
  unsigned char value;
  unsigned int high;
  unsigned int low;
  unsigned int targetLoc;

  setBit (bitArray,
          bitIdx);
  if (GNUNET_DISK_handle_invalid (fh))
    return;
  /* Update the counter file on disk */
  fileSlot = bitIdx / 2;
  targetLoc = bitIdx % 2;

  GNUNET_assert (fileSlot ==
                 GNUNET_DISK_file_seek (fh, fileSlot, GNUNET_DISK_SEEK_SET));
  if (1 != GNUNET_DISK_file_read (fh, &value, 1))
    value = 0;
  low = value & 0xF;
  high = (value & (~0xF)) >> 4;

  if (targetLoc == 0)
  {
    if (low < 0xF)
      low++;
  }
  else
  {
    if (high < 0xF)
      high++;
  }
  value = ((high << 4) | low);
  GNUNET_assert (fileSlot ==
                 GNUNET_DISK_file_seek (fh, fileSlot, GNUNET_DISK_SEEK_SET));
  GNUNET_assert (1 == GNUNET_DISK_file_write (fh, &value, 1));
}


/**
 * Clears a bit from bitArray if the respective usage
 * counter on the disk hits/is zero.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @param fh A file to keep the 4bit address usage counters in
 */
static void
decrementBit (char *bitArray,
              unsigned int bitIdx,
              const struct GNUNET_DISK_FileHandle *fh)
{
  off_t fileslot;
  unsigned char value;
  unsigned int high;
  unsigned int low;
  unsigned int targetLoc;

  if (GNUNET_DISK_handle_invalid (fh))
    return; /* cannot decrement! */
  /* Each char slot in the counter file holds two 4 bit counters */
  fileslot = bitIdx / 2;
  targetLoc = bitIdx % 2;
  if (GNUNET_SYSERR ==
      GNUNET_DISK_file_seek (fh, fileslot, GNUNET_DISK_SEEK_SET))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "seek");
    return;
  }
  if (1 != GNUNET_DISK_file_read (fh, &value, 1))
    value = 0;
  low = value & 0xF;
  high = (value & 0xF0) >> 4;

  /* decrement, but once we have reached the max, never go back! */
  if (targetLoc == 0)
  {
    if ((low > 0) && (low < 0xF))
      low--;
    if (low == 0)
    {
      clearBit (bitArray, bitIdx);
    }
  }
  else
  {
    if ((high > 0) && (high < 0xF))
      high--;
    if (high == 0)
    {
      clearBit (bitArray, bitIdx);
    }
  }
  value = ((high << 4) | low);
  if (GNUNET_SYSERR ==
      GNUNET_DISK_file_seek (fh, fileslot, GNUNET_DISK_SEEK_SET))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "seek");
    return;
  }
  GNUNET_assert (1 == GNUNET_DISK_file_write (fh, &value, 1));
}


#define BUFFSIZE 65536

/**
 * Creates a file filled with zeroes
 *
 * @param fh the file handle
 * @param size the size of the file
 * @return #GNUNET_OK if created ok, #GNUNET_SYSERR otherwise
 */
static enum GNUNET_GenericReturnValue
make_empty_file (const struct GNUNET_DISK_FileHandle *fh,
                 size_t size)
{
  char buffer[BUFFSIZE];
  size_t bytesleft = size;
  int res = 0;

  if (GNUNET_DISK_handle_invalid (fh))
    return GNUNET_SYSERR;
  memset (buffer, 0, sizeof(buffer));
  GNUNET_DISK_file_seek (fh, 0, GNUNET_DISK_SEEK_SET);
  while (bytesleft > 0)
  {
    if (bytesleft > sizeof(buffer))
    {
      res = GNUNET_DISK_file_write (fh, buffer, sizeof(buffer));
      if (res >= 0)
        bytesleft -= res;
    }
    else
    {
      res = GNUNET_DISK_file_write (fh, buffer, bytesleft);
      if (res >= 0)
        bytesleft -= res;
    }
    if (GNUNET_SYSERR == res)
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/* ************** GNUNET_CONTAINER_BloomFilter iterator ********* */

/**
 * Iterator (callback) method to be called by the
 * bloomfilter iterator on each bit that is to be
 * set or tested for the key.
 *
 * @param cls closure
 * @param bf the filter to manipulate
 * @param bit the current bit
 * @return #GNUNET_YES to continue, #GNUNET_NO to stop early
 */
typedef enum GNUNET_GenericReturnValue
(*BitIterator)(void *cls,
               const struct GNUNET_CONTAINER_BloomFilter *bf,
               unsigned int bit);


/**
 * Call an iterator for each bit that the bloomfilter
 * must test or set for this element.
 *
 * @param bf the filter
 * @param callback the method to call
 * @param arg extra argument to callback
 * @param key the key for which we iterate over the BF bits
 */
static void
iterateBits (const struct GNUNET_CONTAINER_BloomFilter *bf,
             BitIterator callback,
             void *arg,
             const struct GNUNET_HashCode *key)
{
  struct GNUNET_HashCode tmp = *key;
  int bitCount;
  unsigned int slot = 0;

  bitCount = bf->addressesPerElement;
  GNUNET_assert (bf->bitArraySize > 0);
  GNUNET_assert (bf->bitArraySize * 8LL > bf->bitArraySize);
  while (bitCount > 0)
  {
    while ( (0 != bitCount) &&
            (slot < (sizeof(struct GNUNET_HashCode) / sizeof(uint32_t))) )
    {
      if (GNUNET_YES !=
          callback (arg,
                    bf,
                    ntohl ((((uint32_t *) &tmp)[slot]))
                    % ((bf->bitArraySize * 8LL))))
        return;
      slot++;
      bitCount--;
    }
    if (0 == bitCount)
      break;
    GNUNET_CRYPTO_hash (&tmp,
                        sizeof(tmp),
                        &tmp);
    slot = 0;
  }
}


/**
 * Callback: increment bit
 *
 * @param cls pointer to writeable form of bf
 * @param bf the filter to manipulate
 * @param bit the bit to increment
 * @return #GNUNET_YES
 */
static enum GNUNET_GenericReturnValue
incrementBitCallback (void *cls,
                      const struct GNUNET_CONTAINER_BloomFilter *bf,
                      unsigned int bit)
{
  struct GNUNET_CONTAINER_BloomFilter *b = cls;

  incrementBit (b->bitArray,
                bit,
                bf->fh);
  return GNUNET_YES;
}


/**
 * Callback: decrement bit
 *
 * @param cls pointer to writeable form of bf
 * @param bf the filter to manipulate
 * @param bit the bit to decrement
 * @return #GNUNET_YES
 */
static enum GNUNET_GenericReturnValue
decrementBitCallback (void *cls,
                      const struct GNUNET_CONTAINER_BloomFilter *bf,
                      unsigned int bit)
{
  struct GNUNET_CONTAINER_BloomFilter *b = cls;

  decrementBit (b->bitArray,
                bit,
                bf->fh);
  return GNUNET_YES;
}


/**
 * Callback: test if all bits are set
 *
 * @param cls pointer set to false if bit is not set
 * @param bf the filter
 * @param bit the bit to test
 * @return #GNUNET_YES if the bit is set, #GNUNET_NO if not
 */
static enum GNUNET_GenericReturnValue
testBitCallback (void *cls,
                 const struct GNUNET_CONTAINER_BloomFilter *bf,
                 unsigned int bit)
{
  bool *arg = cls;

  if (! testBit (bf->bitArray, bit))
  {
    *arg = false;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/* *********************** INTERFACE **************** */

struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_load (const char *filename,
                                   size_t size,
                                   unsigned int k)
{
  struct GNUNET_CONTAINER_BloomFilter *bf;
  char *rbuff;
  off_t pos;
  int i;
  size_t ui;
  off_t fsize;
  int must_read;

  GNUNET_assert (NULL != filename);
  if ((k == 0) || (size == 0))
    return NULL;
  if (size < BUFFSIZE)
    size = BUFFSIZE;
  ui = 1;
  while ((ui < size) && (ui * 2 > ui))
    ui *= 2;
  size = ui; /* make sure it's a power of 2 */

  bf = GNUNET_new (struct GNUNET_CONTAINER_BloomFilter);
  /* Try to open a bloomfilter file */
  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    bf->fh = GNUNET_DISK_file_open (filename,
                                    GNUNET_DISK_OPEN_READWRITE,
                                    GNUNET_DISK_PERM_USER_READ
                                    | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL != bf->fh)
  {
    /* file existed, try to read it! */
    must_read = GNUNET_YES;
    if (GNUNET_OK !=
        GNUNET_DISK_file_handle_size (bf->fh,
                                      &fsize))
    {
      GNUNET_DISK_file_close (bf->fh);
      GNUNET_free (bf);
      return NULL;
    }
    if (0 == fsize)
    {
      /* found existing empty file, just overwrite */
      if (GNUNET_OK !=
          make_empty_file (bf->fh,
                           size * 4LL))
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                             "write");
        GNUNET_DISK_file_close (bf->fh);
        GNUNET_free (bf);
        return NULL;
      }
    }
    else if (fsize != ((off_t) size) * 4LL)
    {
      GNUNET_log (
        GNUNET_ERROR_TYPE_ERROR,
        _ (
          "Size of file on disk is incorrect for this Bloom filter (want %llu, have %llu)\n"),
        (unsigned long long) (size * 4LL),
        (unsigned long long) fsize);
      GNUNET_DISK_file_close (bf->fh);
      GNUNET_free (bf);
      return NULL;
    }
  }
  else
  {
    /* file did not exist, don't read, just create */
    must_read = GNUNET_NO;
    bf->fh = GNUNET_DISK_file_open (filename,
                                    GNUNET_DISK_OPEN_CREATE
                                    | GNUNET_DISK_OPEN_READWRITE,
                                    GNUNET_DISK_PERM_USER_READ
                                    | GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == bf->fh)
    {
      GNUNET_free (bf);
      return NULL;
    }
    if (GNUNET_OK != make_empty_file (bf->fh, size * 4LL))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "write");
      GNUNET_DISK_file_close (bf->fh);
      GNUNET_free (bf);
      return NULL;
    }
  }
  bf->filename = GNUNET_strdup (filename);
  /* Alloc block */
  bf->bitArray = GNUNET_malloc_large (size);
  if (NULL == bf->bitArray)
  {
    if (NULL != bf->fh)
      GNUNET_DISK_file_close (bf->fh);
    GNUNET_free (bf->filename);
    GNUNET_free (bf);
    return NULL;
  }
  bf->bitArraySize = size;
  bf->addressesPerElement = k;
  if (GNUNET_YES != must_read)
    return bf; /* already done! */
  /* Read from the file what bits we can */
  rbuff = GNUNET_malloc (BUFFSIZE);
  pos = 0;
  while (pos < ((off_t) size) * 8LL)
  {
    int res;

    res = GNUNET_DISK_file_read (bf->fh, rbuff, BUFFSIZE);
    if (res == -1)
    {
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "read", bf->filename);
      GNUNET_free (rbuff);
      GNUNET_free (bf->filename);
      GNUNET_DISK_file_close (bf->fh);
      GNUNET_free (bf);
      return NULL;
    }
    if (res == 0)
      break;   /* is ok! we just did not use that many bits yet */
    for (i = 0; i < res; i++)
    {
      if ((rbuff[i] & 0x0F) != 0)
        setBit (bf->bitArray, pos + i * 2);
      if ((rbuff[i] & 0xF0) != 0)
        setBit (bf->bitArray, pos + i * 2 + 1);
    }
    if (res < BUFFSIZE)
      break;
    pos += BUFFSIZE * 2;   /* 2 bits per byte in the buffer */
  }
  GNUNET_free (rbuff);
  return bf;
}


struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_init (const char *data,
                                   size_t size,
                                   unsigned int k)
{
  struct GNUNET_CONTAINER_BloomFilter *bf;

  if ((0 == k) || (0 == size))
    return NULL;
  bf = GNUNET_new (struct GNUNET_CONTAINER_BloomFilter);
  bf->filename = NULL;
  bf->fh = NULL;
  bf->bitArray = GNUNET_malloc_large (size);
  if (NULL == bf->bitArray)
  {
    GNUNET_free (bf);
    return NULL;
  }
  bf->bitArraySize = size;
  bf->addressesPerElement = k;
  if (NULL != data)
    GNUNET_memcpy (bf->bitArray, data, size);
  return bf;
}


enum GNUNET_GenericReturnValue
GNUNET_CONTAINER_bloomfilter_get_raw_data (
  const struct GNUNET_CONTAINER_BloomFilter *bf,
  char *data,
  size_t size)
{
  if (NULL == bf)
    return GNUNET_SYSERR;
  if (bf->bitArraySize != size)
    return GNUNET_SYSERR;
  GNUNET_memcpy (data, bf->bitArray, size);
  return GNUNET_OK;
}


void
GNUNET_CONTAINER_bloomfilter_free (struct GNUNET_CONTAINER_BloomFilter *bf)
{
  if (NULL == bf)
    return;
  if (bf->fh != NULL)
    GNUNET_DISK_file_close (bf->fh);
  GNUNET_free (bf->filename);
  GNUNET_free (bf->bitArray);
  GNUNET_free (bf);
}


void
GNUNET_CONTAINER_bloomfilter_clear (struct GNUNET_CONTAINER_BloomFilter *bf)
{
  if (NULL == bf)
    return;

  memset (bf->bitArray, 0, bf->bitArraySize);
  if (bf->filename != NULL)
    make_empty_file (bf->fh, bf->bitArraySize * 4LL);
}


bool
GNUNET_CONTAINER_bloomfilter_test (
  const struct GNUNET_CONTAINER_BloomFilter *bf,
  const struct GNUNET_HashCode *e)
{
  bool res;

  if (NULL == bf)
    return true;
  res = true;
  iterateBits (bf,
               &testBitCallback,
               &res,
               e);
  return res;
}


void
GNUNET_CONTAINER_bloomfilter_add (struct GNUNET_CONTAINER_BloomFilter *bf,
                                  const struct GNUNET_HashCode *e)
{
  if (NULL == bf)
    return;
  iterateBits (bf,
               &incrementBitCallback,
               bf,
               e);
}


enum GNUNET_GenericReturnValue
GNUNET_CONTAINER_bloomfilter_or (struct GNUNET_CONTAINER_BloomFilter *bf,
                                 const char *data,
                                 size_t size)
{
  unsigned int i;
  unsigned int n;
  unsigned long long *fc;
  const unsigned long long *dc;

  if (NULL == bf)
    return GNUNET_YES;
  if (bf->bitArraySize != size)
    return GNUNET_SYSERR;
  fc = (unsigned long long *) bf->bitArray;
  dc = (const unsigned long long *) data;
  n = size / sizeof(unsigned long long);

  for (i = 0; i < n; i++)
    fc[i] |= dc[i];
  for (i = n * sizeof(unsigned long long); i < size; i++)
    bf->bitArray[i] |= data[i];
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONTAINER_bloomfilter_or2 (
  struct GNUNET_CONTAINER_BloomFilter *bf,
  const struct GNUNET_CONTAINER_BloomFilter *to_or)
{
  unsigned int i;
  unsigned int n;
  unsigned long long *fc;
  const unsigned long long *dc;
  size_t size;

  if (NULL == bf)
    return GNUNET_OK;
  if (bf->bitArraySize != to_or->bitArraySize)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  size = bf->bitArraySize;
  fc = (unsigned long long *) bf->bitArray;
  dc = (const unsigned long long *) to_or->bitArray;
  n = size / sizeof(unsigned long long);

  for (i = 0; i < n; i++)
    fc[i] |= dc[i];
  for (i = n * sizeof(unsigned long long); i < size; i++)
    bf->bitArray[i] |= to_or->bitArray[i];
  return GNUNET_OK;
}


void
GNUNET_CONTAINER_bloomfilter_remove (struct GNUNET_CONTAINER_BloomFilter *bf,
                                     const struct GNUNET_HashCode *e)
{
  if (NULL == bf)
    return;
  if (NULL == bf->filename)
    return;
  iterateBits (bf,
               &decrementBitCallback,
               bf,
               e);
}


void
GNUNET_CONTAINER_bloomfilter_resize (struct GNUNET_CONTAINER_BloomFilter *bf,
                                     GNUNET_CONTAINER_HashCodeIterator iterator,
                                     void *iterator_cls,
                                     size_t size,
                                     unsigned int k)
{
  struct GNUNET_HashCode hc;
  unsigned int i;

  GNUNET_free (bf->bitArray);
  i = 1;
  while (i < size)
    i *= 2;
  size = i; /* make sure it's a power of 2 */
  bf->addressesPerElement = k;
  bf->bitArraySize = size;
  bf->bitArray = GNUNET_malloc (size);
  if (NULL != bf->filename)
    make_empty_file (bf->fh, bf->bitArraySize * 4LL);
  while (GNUNET_YES == iterator (iterator_cls, &hc))
    GNUNET_CONTAINER_bloomfilter_add (bf, &hc);
}


/* end of container_bloomfilter.c */
