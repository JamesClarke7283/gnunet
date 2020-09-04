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
 * @file escrow/escrow.h
 * 
 * @brief Common type definitions for the escrow component
 */

#ifndef ESCROW_H
#define ESCROW_H

#include "gnunet_escrow_lib.h"


/**
 * State while collecting all egos
 */
#define ESCROW_PLUGIN_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ESCROW_PLUGIN_STATE_POST_INIT 1

/**
 * State while cleaning up
 */
#define ESCROW_PLUGIN_STATE_CLEANUP 2


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
struct ESCROW_PluginHandle
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

  /**
   * The head of the plugin operation list
   */
  struct ESCROW_PluginOperationWrapper *plugin_op_head;

  /**
   * The tail of the plugin operation list
   */
  struct ESCROW_PluginOperationWrapper *plugin_op_tail;
};

/**
 * Wrapper for an escrow plugin operation
 */
struct ESCROW_PluginOperationWrapper
{
  /**
   * Plugin operations are kept in a DLL.
   */
  struct ESCROW_PluginOperationWrapper *prev;

  /**
   * Plugin operations are kept in a DLL.
   */
  struct ESCROW_PluginOperationWrapper *next;

  /**
   * The actual plugin operation
   */
  void *plugin_op;
};


/**
 * Continuation for a plugin operation (e.g. used for restore, as this
 * callback has to be called from the IDENTITY service after finishing)
 */
typedef void (*ESCROW_Plugin_Continuation) (void *cls);


/**
 * Wrapper for the Plugin_AnchorContinuation.
 * 
 * As this type of function is called from the scheduler, which only takes
 * one argument as closure, this struct is used to pass more arguments.
 */
struct ESCROW_Plugin_AnchorContinuationWrapper
{
  /**
   * Handle for the escrow component
   */
  struct GNUNET_ESCROW_Handle *h;

  /**
   * The escrow anchor
   */
  struct GNUNET_ESCROW_Anchor *anchor;

  /**
   * The unique ID of the respective ESCROW_Operation
   */
  uint32_t op_id;

  /**
   * The error message, NULL on success
   */
  const char *emsg;
};

/**
 * Wrapper for the Plugin_EgoContinuation.
 * 
 * As this type of function is called from the scheduler, which only takes
 * one argument as closure, this struct is used to pass more arguments.
 */
struct ESCROW_Plugin_EgoContinuationWrapper
{
  /**
   * Handle for the escrow component
   */
  struct GNUNET_ESCROW_Handle *h;

  /**
   * The restored ego
   */
  const struct GNUNET_IDENTITY_Ego *ego;

  /**
   * The unique ID of the respective ESCROW_Operation
   */
  uint32_t op_id;

  /**
   * The error message, NULL on success
   */
  const char *emsg;
};

/**
 * Wrapper for the Plugin_VerifyContinuation.
 * 
 * As this type of function is called from the scheduler, which only takes
 * one argument as closure, this struct is used to pass more arguments.
 */
struct ESCROW_Plugin_VerifyContinuationWrapper
{
  /**
   * Handle for the escrow component
   */
  struct GNUNET_ESCROW_Handle *h;

  /**
   * The result of the verification
   */
  int verificationResult;

  /**
   * The unique ID of the respective ESCROW_Operation
   */
  uint32_t op_id;

  /**
   * The error message, NULL on success
   */
  const char *emsg;
};


#endif
