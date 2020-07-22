/*
     This file is part of GNUnet
     Copyright (C) 2020 GNUnet e.V.

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
 * @author Johannes Späth
 *
 * @file
 * Plugin API for escrow methods
 *
 * @defgroup escrow-plugin  escrow plugin API for escrow methods
 * @{
 */
#ifndef GNUNET_ESCROW_PLUGIN_H
#define GNUNET_ESCROW_PLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_escrow_lib.h"
#include "gnunet_identity_service.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * State while collecting all egos
 */
#define ESCROW_PLUGIN_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ESCROW_PLUGIN_STATE_POST_INIT 1


/**
 * The ego list
 */
struct EgoEntry
{
  /**
   * DLL
   */
  struct EgoEntry *next;

  /**
   * DLL
   */
  struct EgoEntry *prev;

  /**
   * Ego Identifier
   */
  char *identifier;

  /**
   * Public key string
   */
  char *keystring;

  /**
   * The Ego
   */
  struct GNUNET_IDENTITY_Ego *ego;
};


/**
 * Handle for a plugin instance
 */
struct EscrowPluginHandle
{
  /**
   * The identity init continuation.
   */
  GNUNET_ESCROW_IdentityInitContinuation id_init_cont;

  /**
   * The ego create continuation.
   */
  GNUNET_ESCROW_EgoCreateContinuation ego_create_cont;

  /**
   * The current restore callback.
   */
  GNUNET_ESCROW_EgoContinuation curr_restore_cb;

  /**
   * The handle to the escrow component.
   */
  struct GNUNET_ESCROW_Handle *escrow_handle;

  /**
   * The state of the plugin (in the initialization phase).
   */
  int state;

  /**
   * The head of the ego list.
   */
  struct EgoEntry *ego_head;

  /**
   * The tail of the ego list
   */
  struct EgoEntry *ego_tail;
};


/**
 * Function called to start the escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param cb the function called upon completion
 */
typedef void (*GNUNET_ESCROW_StartKeyEscrowFunction) (
  struct GNUNET_ESCROW_Handle *h,
  const struct GNUNET_IDENTITY_Ego *ego,
  GNUNET_ESCROW_AnchorContinuation cb);

/**
 * Function called to renew the escrow of the key
 * 
 * @param op the escrow operation
 * @param escrowAnchor the the escrow anchor returned by the start method
 */
typedef void (*GNUNET_ESCROW_RenewKeyEscrowFunction) (
  struct GNUNET_ESCROW_Operation *op,
  struct GNUNET_ESCROW_Anchor *escrowAnchor);

/**
 * Function called to verify the escrow of the key
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego containing the private key
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param cb the function called upon completion
 */
typedef void (*GNUNET_ESCROW_VerifyKeyEscrowFunction) (
  struct GNUNET_ESCROW_Handle *h,
  const struct GNUNET_IDENTITY_Ego *ego,
  struct GNUNET_ESCROW_Anchor *escrowAnchor,
  GNUNET_ESCROW_VerifyContinuation cb);

/**
 * Function called to restore a key from an escrow
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor needed to restore the key
 * @param egoName the name of the ego to restore
 * @param cb the function called upon completion
 */
typedef void (*GNUNET_ESCROW_RestoreKeyFunction) (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_ESCROW_Anchor *escrowAnchor,
  char *egoName,
  GNUNET_ESCROW_EgoContinuation cb);


/**
 * Function called to deserialize an escrow anchor string into a
 * GNUNET_ESCROW_Anchor struct
 * 
 * @param h the handle for the escrow component
 * @param anchorString the encoded escrow anchor string
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct
 */
typedef struct GNUNET_ESCROW_Anchor *(*GNUNET_ESCROW_AnchorStringToDataFunction) (
  struct GNUNET_ESCROW_Handle *h,
  char *anchorString);


/**
 * Function called to serialize an escrow anchor struct into a string
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor struct
 * 
 * @return the encoded escrow anchor string
 */
typedef char *(*GNUNET_ESCROW_AnchorDataToStringFunction) (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_ESCROW_Anchor *escrowAnchor);


/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_ESCROW_KeyPluginFunctions
{
  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * Start key escrow
   */
  GNUNET_ESCROW_StartKeyEscrowFunction start_key_escrow;

  /**
   * Renew key escrow
   */
  GNUNET_ESCROW_RenewKeyEscrowFunction renew_key_escrow;

  /**
   * Verify key escrow
   */
  GNUNET_ESCROW_VerifyKeyEscrowFunction verify_key_escrow;

  /**
   * Restore key escrow
   */
  GNUNET_ESCROW_RestoreKeyFunction restore_key;

  /**
   * Deserialize anchor string to data
   */
  GNUNET_ESCROW_AnchorStringToDataFunction anchor_string_to_data;

  /**
   * Serialize anchor data to string
   */
  GNUNET_ESCROW_AnchorDataToStringFunction anchor_data_to_string;
};


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */ /* end of group */
