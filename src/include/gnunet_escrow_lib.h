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
enum GNUNET_ESCROW_Key_Escrow_Method
{
  GNUNET_ESCROW_KEY_NONE, // error value
  GNUNET_ESCROW_KEY_PLAINTEXT,
  GNUNET_ESCROW_KEY_GNS,
  GNUNET_ESCROW_KEY_ANASTASIS
};


/**
 * Enum for the different verification results
 */
enum GNUNET_ESCROW_Verification_Result
{
  GNUNET_ESCROW_VALID,
  GNUNET_ESCROW_INVALID,
  GNUNET_ESCROW_SHARES_MISSING
};


/**
 * Struct for the escrow anchor
 */
struct GNUNET_ESCROW_Anchor
{
  /**
   * The escrow method.
   */
  enum GNUNET_ESCROW_Key_Escrow_Method method;

  /**
   * The name of the ego that was put in escrow.
   */
  const char *egoName;

  /**
   * The size of the anchor data.
   */
  uint32_t size;
};


/**
 * Struct for the escrow status
 */
struct GNUNET_ESCROW_Status
{
  /**
   * The time of the last successful escrow.
   */
  struct GNUNET_TIME_Absolute last_escrow_time;

  /**
   * The time of the next recommended escrow.
   */
  struct GNUNET_TIME_Absolute next_recommended_escrow_time;

  /**
   * The used escrow method.
   */
  enum GNUNET_ESCROW_Key_Escrow_Method last_method;
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
 * Continuation for PUT operations.
 * 
 * @param cls closure
 * @param anchor the escrow anchor needed to get the data back
 * @param emsg error message, NULL on success
 */
typedef void (*GNUNET_ESCROW_AnchorContinuation) (
  void *cls,
  struct GNUNET_ESCROW_Anchor *anchor,
  const char *emsg);

/**
 * Continuation for a GET operation.
 * 
 * @param cls closure
 * @param ego a new identity ego restored from the escrow
 * @param emsg error message, NULL on success
 */
typedef void (*GNUNET_ESCROW_EgoContinuation) (
  void *cls,
  const struct GNUNET_IDENTITY_Ego *ego,
  const char *emsg);

/**
 * Continuation for a VERIFY operation.
 * 
 * @param cls closure
 * @param verificationResult the result of the verification, i.e.
 *   GNUNET_ESCROW_VALID if the escrow could successfully by restored,
 *   GNUNET_ESCROW_SHARES_MISSING if it could be restored, but some of
 *                                the shares are missing
 *   GNUNET_ESCROW_INVALID otherwise
 * @param emsg error message, NULL on success
 */
typedef void (*GNUNET_ESCROW_VerifyContinuation) (
  void *cls,
  int verificationResult,
  const char *emsg);


/**
 * Handle for the escrow component.
 */
struct GNUNET_ESCROW_Handle
{
  /**
   * Configuration to use.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Head of active operations.
   */
  struct GNUNET_ESCROW_Operation *op_head;

  /**
   * Tail of active operations.
   */
  struct GNUNET_ESCROW_Operation *op_tail;

  /**
   * The last operation id used for an ESCROW operation.
   */
  uint32_t last_op_id_used;
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
   * ID of the operation.
   */
  uint32_t id;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_ESCROW_Operation *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_ESCROW_Operation *prev;

  /**
   * The used escrow method.
   */
  enum GNUNET_ESCROW_Key_Escrow_Method method;

  /**
   * The respective plugin operation
   */
  struct ESCROW_PluginOperationWrapper *plugin_op_wrap;

  /**
   * The escrow anchor.
   */
  struct GNUNET_ESCROW_Anchor *escrow_anchor;

  /**
   * The ego.
   */
  const struct GNUNET_IDENTITY_Ego *ego;

  /**
   * The verification result.
   */
  enum GNUNET_ESCROW_Verification_Result verification_result;

  /**
   * Continuation for a PUT operation.
   */
  GNUNET_ESCROW_AnchorContinuation cb_put;

  /**
   * Continuation for a GET operation.
   */
  GNUNET_ESCROW_EgoContinuation cb_get;

  /**
   * Continuation for a VERIFY operation.
   */
  GNUNET_ESCROW_VerifyContinuation cb_verify;

  /**
   * Closure for the callback
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
 * @param userSecret the user secret (e.g. for derivation of escrow identities)
 *                   for GNS escrow, this has to be UNIQUE in the whole network!
 * @param method the escrow method to use
 * @param cb function to call with the escrow anchor on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_put (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_IDENTITY_Ego *ego,
  const char *userSecret,
  enum GNUNET_ESCROW_Key_Escrow_Method method,
  GNUNET_ESCROW_AnchorContinuation cb,
  void *cb_cls);


/**
 * Get the escrowed data back
 * 
 * @param h the handle for the escrow component
 * @param anchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * @param cb function to call with the restored ego on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_get (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_ESCROW_Anchor *anchor,
  enum GNUNET_ESCROW_Key_Escrow_Method method,
  GNUNET_ESCROW_EgoContinuation cb,
  void *cb_cls);


/**
 * Verify the escrowed data
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego that was put into escrow
 * @param anchor the escrow anchor returned by the GNUNET_ESCROW_put method
 * @param method the escrow method to use
 * @param cb function to call with the verification result on completion
 * @param cb_cls closure for @a cb
 * 
 * @return handle to abort the operation
 */
struct GNUNET_ESCROW_Operation *
GNUNET_ESCROW_verify (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_IDENTITY_Ego *ego,
  struct GNUNET_ESCROW_Anchor *anchor,
  enum GNUNET_ESCROW_Key_Escrow_Method method,
  GNUNET_ESCROW_VerifyContinuation cb,
  void *cb_cls);


/**
 * Get the status of an escrow, i.e.
 *   -> when the last escrow was
 *   -> when the next escrow is recommended
 * 
 * @param h the handle for the escrow component
 * @param ego the identity ego of which the escrow status has to be determined
 * @param method the escrow method to use
 * 
 * @return the status of the escrow packed into a GNUNET_ESCROW_Status struct
 */
struct GNUNET_ESCROW_Status *
GNUNET_ESCROW_get_status (
  struct GNUNET_ESCROW_Handle *h,
  struct GNUNET_IDENTITY_Ego *ego,
  enum GNUNET_ESCROW_Key_Escrow_Method method);


/**
 * Deserialize an escrow anchor string (e.g. from command line) into a
 * GNUNET_ESCROW_Anchor struct
 * The anchor string is expected to have the following form:
 *    <method>:<egoName>:<anchorData>
 * with <method>, <egoName> and <anchorData> being URL-encoded
 * 
 * @param anchorString the encoded escrow anchor string
 * 
 * @return the deserialized data packed into a GNUNET_ESCROW_Anchor struct,
 *         NULL if we failed to parse the string
 */
struct GNUNET_ESCROW_Anchor *
GNUNET_ESCROW_anchor_string_to_data (
  const char *anchorString);


/**
 * Serialize an escrow anchor (struct GNUNET_ESCROW_Anchor) into a string
 * 
 * @param anchor the escrow anchor struct
 * 
 * @return the encoded escrow anchor string
 */
char *
GNUNET_ESCROW_anchor_data_to_string (
  const struct GNUNET_ESCROW_Anchor *anchor);


/**
 * Convert a method name string to the respective enum number
 * 
 * @param methodString the method name string
 * 
 * @return the enum number
 */
enum GNUNET_ESCROW_Key_Escrow_Method
GNUNET_ESCROW_method_string_to_number (const char *methodString);


/**
 * Convert a method enum number to the respective method string
 * 
 * @param method the method enum number
 * 
 * @return the method string
 */
const char *
GNUNET_ESCROW_method_number_to_string (enum GNUNET_ESCROW_Key_Escrow_Method method);


/**
 * Cancel an escrow operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation.
 *
 * @param op operation to cancel
 */
void
GNUNET_ESCROW_cancel (struct GNUNET_ESCROW_Operation *op);


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
