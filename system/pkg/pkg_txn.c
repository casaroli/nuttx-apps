/****************************************************************************
 * apps/system/pkg/pkg_txn.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include "pkg.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

const char *pkg_txn_state_str(enum pkg_txn_state_e state)
{
  switch (state)
    {
      case PKG_TXN_IDLE:
        return "IDLE";

      case PKG_TXN_FETCHING:
        return "FETCHING";

      case PKG_TXN_VERIFIED:
        return "VERIFIED";

      case PKG_TXN_STAGED:
        return "STAGED";

      case PKG_TXN_COMPAT_OK:
        return "COMPAT_OK";

      case PKG_TXN_ACTIVATED:
        return "ACTIVATED";

      case PKG_TXN_CLEANUP:
        return "CLEANUP";

      case PKG_TXN_FAILED:
        return "FAILED";

      case PKG_TXN_RESTORE:
        return "RESTORE";

      default:
        return "UNKNOWN";
    }
}
