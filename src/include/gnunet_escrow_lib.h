/*
     This file is part of GNUnet.
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
 * Escrow definitions
 *
 * @defgroup escrow escrow component
 * @{
 */
#ifndef GNUNET_ESCROW_LIB_H
#define GNUNET_ESCROW_LIB_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"


/**
 * Enum for the different key escrow methods
 */
enum GNUNET_ESCROW_Key_Escrow_Method {
  GNUNET_ESCROW_KEY_PLAINTEXT,
  GNUNET_ESCROW_KEY_GNS,
  GNUNET_ESCROW_KEY_ANASTASIS
};


/**
 * Enum for the different verification results
 */
enum GNUNET_ESCROW_Verification_Result {
  GNUNET_ESCROW_VALID,
  GNUNET_ESCROW_INVALID,
  GNUNET_ESCROW_RENEW_NEEDED
};


/**
 * Struct for the escrow anchor
 */
struct GNUNET_ESCROW_Anchor {
  /**
   * The escrow method.
   */
  enum GNUNET_ESCROW_Key_Escrow_Method method;

  /**
   * The size of the anchor data.
   */
  uint32_t size;
};


/**
 * Function called after the initialization of the identity service.
 * Passed via cls to the callback of GNUNET_IDENTITY_connect
 */
typedef void (*GNUNET_ESCROW_IdentityInitContinuation) ();

/**
 * Function called after the creation of an ego in case that happened
 * because of an escrow GET operation.
 */
typedef void (*GNUNET_ESCROW_EgoCreateContinuation) (
  const struct GNUNET_IDENTITY_Ego *ego);

/**
 * Continuation for PUT and RENEW operations.
 * 
 * @param cls closure
 * @param escrowAnchor the escrow anchor needed to get the data back
 */
typedef void (*GNUNET_ESCROW_AnchorContinuation) (
  void *cls,
  struct GNUNET_ESCROW_Anchor *escrowAnchor);

/**
 * Continuation for a GET operation.
 * 
 * @param cls closure
 * @param ego a new identity ego restored from the escrow
 */
typedef void (*GNUNET_ESCROW_EgoContinuation) (
  void *cls,
  const struct GNUNET_IDENTITY_Ego *ego);

/**
 * Continuation for a VERIFY operation.
 * 
 * @param cls closure
 * @param verificationResult the result of the verification, i.e.
 *   GNUNET_ESCROW_VALID if the escrow could successfully by restored,
 *   GNUNET_ESCROW_RENEW_NEEDED if the escrow needs to be renewed,
 *   GNUNET_ESCROW_INVALID otherwise
 */
typedef void (*GNUNET_ESCROW_VerifyContinuation) (
  void *cls,
  int verificationResult);


/**
 * Handle for the escrow component.
 */
struct GNUNET_ESCROW_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Head of active operations.
   */
  struct GNUNET_ESCROW_Operation *op_head;

  /**
   * Tail of active operations.
   */
  struct GNUNET_ESCROW_Operation *op_tail;
};


/**
 * Handle for an operation with the escrow component.
 */
struct GNUNET_ESCROW_Operation
{
  /**
   * Main escrow handle.
   */
  struct GNUNET_ESCROW_Handle *h;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_ESCROW_Operation *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_ESCROW_Operation *prev;

  /**
   * Continuation for a PUT operation.
   */
  GNUNET_ESCROW_AnchorContinuation cb_put;

  /**
   * Continuation for a RENEW operation.
   */
  GNUNET_ESCROW_AnchorContinuation cb_renew;

  /**
   * Continuation for a GET operation.
   */
  GNUNET_ESCROW_EgoContinuation cb_get;

  /**
   * Continuation for a VERIFY operation.
   */
  GNUNET_ESCROW_VerifyContinuation cb_verify;

  /**
   * Closure for a callback.
   */
  void *cb_cls;
};


/**
 * Initialize the escrow component.
 * 
 * @param cfg the configuration to use
 * 
 * @return handle to use
 */
struct GNUNET_ESCROW_Handle *
GNUNET_ESCROW_init (
  const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Unload all loaded plugins on destruction.
 * 
 * @param h the escrow handle
 */
void
GNUNET_ESCROW_fini (
  struct GNUNET_ESCROW_Handle *h);


/**
 * Put some data in escrow using the specified escrow method
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego to put in escrow
 * @param method the escrow method to use
 * @param cb function to call with the escrow anchor on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_put (
  struct GNUNET_ESCROW_Handle *h,
  const struct GNUNET_IDENTITY_Ego *ego,
  enum GNUNET_ESCROW_Key_Escrow_Method method,
  GNUNET_ESCROW_AnchorContinuation cb,
  void *cb_cls);


/**
 * Renew the escrow of the data related to the given escrow anchor
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * @param cb function to call with the escrow anchor on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_renew (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_ESCROW_Anchor *escrowAnchor,
  enum GNUNET_ESCROW_Key_Escrow_Method method,
  GNUNET_ESCROW_AnchorContinuation cb,
  void *cb_cls);


/**
 * Get the escrowed data back
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param egoName the name of the ego to get back
 * @param method the escrow method to use
 * @param cb function to call with the restored ego on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_get (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_ESCROW_Anchor *escrowAnchor,
  char *egoName,
  enum GNUNET_ESCROW_Key_Escrow_Method method,
  GNUNET_ESCROW_EgoContinuation cb,
  void *cb_cls);


/**
 * Verify the escrowed data
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego that was put into escrow
 * @param escrowAnchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * @param cb function to call with the verification result on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_verify (
  struct GNUNET_ESCROW_Handle *h,
  const struct GNUNET_IDENTITY_Ego *ego,
  struct GNUNET_ESCROW_Anchor *escrowAnchor,
  enum GNUNET_ESCROW_Key_Escrow_Method method,
  GNUNET_ESCROW_VerifyContinuation cb,
  void *cb_cls);


/**
 * Deserialize an escrow anchor string (e.g. from command line) into a
 * GNUNET_ESCROW_Anchor struct
 * 
 * @param h the handle for the escrow component
 * @param anchorString the encoded escrow anchor string
 * @param method the escrow method to use
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct
 */
struct GNUNET_ESCROW_Anchor *
GNUNET_ESCROW_anchor_string_to_data (
  struct GNUNET_ESCROW_Handle *h,
  char *anchorString,
  enum GNUNET_ESCROW_Key_Escrow_Method method);


/**
 * Serialize an escrow anchor (struct GNUNET_ESCROW_Anchor) into a string
 * 
 * @param h the handle for the escrow component
 * @param escrowAnchor the escrow anchor struct
 * @param method the escrow method to use
 * 
 * @return the encoded escrow anchor string
 */
char *
GNUNET_ESCROW_anchor_data_to_string (struct GNUNET_ESCROW_Handle *h,
                                     struct GNUNET_ESCROW_Anchor *escrowAnchor,
                                     enum GNUNET_ESCROW_Key_Escrow_Method method);


/**
 * Cancel an escrow operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation.
 *
 * @param op operation to cancel
 * @param method the escrow method to use
 */
void
GNUNET_ESCROW_cancel (struct GNUNET_ESCROW_Operation *op,
                      enum GNUNET_ESCROW_Key_Escrow_Method method);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_ESCROW_LIB_H */
#endif

/** @} */ /* end of group escrow */

/* end of gnunet_escrow_lib.h */
