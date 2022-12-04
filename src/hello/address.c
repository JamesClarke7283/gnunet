/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file hello/address.c
 * @brief helper functions for handling addresses
 * @author Christian Grothoff
 */
#include "platform.h"
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"


/**
 * Check if an address has a local option set
 *
 * @param address the address to check
 * @param option the respective option to check for
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
GNUNET_HELLO_address_check_option (const struct GNUNET_HELLO_Address *address,
                                   enum GNUNET_HELLO_AddressInfo option)
{
  if (option == (address->local_info & option))
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Get the size of an address struct.
 *
 * @param address address
 * @return the size
 */
size_t
GNUNET_HELLO_address_get_size (const struct GNUNET_HELLO_Address *address)
{
  return sizeof(struct GNUNET_HELLO_Address) + address->address_length
         + strlen (address->transport_name) + 1;
}


struct GNUNET_HELLO_Address *
GNUNET_HELLO_address_allocate (const struct GNUNET_PeerIdentity *peer,
                               const char *transport_name,
                               const void *address,
                               size_t address_length,
                               enum GNUNET_HELLO_AddressInfo local_info)
{
  struct GNUNET_HELLO_Address *addr;
  size_t slen;
  char *end;

  slen = strlen (transport_name) + 1;
  addr = GNUNET_malloc (sizeof(struct GNUNET_HELLO_Address)
                        + address_length + slen);
  addr->peer = *peer;
  addr->address = &addr[1];
  addr->address_length = address_length;
  addr->local_info = local_info;
  end = (char *) &addr[1];
  addr->transport_name = &end[address_length];
  GNUNET_memcpy (end,
                 address,
                 address_length);
  GNUNET_memcpy (&end[address_length],
                 transport_name,
                 slen);
  return addr;
}


/**
 * Copy an address struct.
 *
 * @param address address to copy
 * @return a copy of the address struct
 */
struct GNUNET_HELLO_Address *
GNUNET_HELLO_address_copy (const struct GNUNET_HELLO_Address *address)
{
  if (NULL == address)
    return NULL;
  return GNUNET_HELLO_address_allocate (&address->peer,
                                        address->transport_name,
                                        address->address,
                                        address->address_length,
                                        address->local_info);
}


int
GNUNET_HELLO_address_cmp (const struct GNUNET_HELLO_Address *a1,
                          const struct GNUNET_HELLO_Address *a2)
{
  int ret;

  if ((NULL == a1) &&
      (NULL == a2))
    return 0;
  if (NULL == a1)
    return 1;
  if (NULL == a2)
    return -1;
  ret = strcmp (a1->transport_name, a2->transport_name);
  if (0 != ret)
    return ret;
  if (a1->local_info != a2->local_info)
    return (((int) a1->local_info) < ((int) a2->local_info)) ? -1 : 1;
  if (a1->address_length < a2->address_length)
    return -1;
  if (a1->address_length > a2->address_length)
    return 1;
  return memcmp (a1->address,
                 a2->address,
                 a1->address_length);
}


/* end of address.c */
