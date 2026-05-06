/****************************************************************************
 * apps/system/pkg/pkg.h
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

#ifndef __APPS_SYSTEM_PKG_PKG_H
#define __APPS_SYSTEM_PKG_PKG_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define PKG_REPO_DIR          "/data/repo"
#define PKG_REPO_INDEX        "/data/repo/index.json"
#define PKG_REPO_INSTALLED    "/data/repo/installed.json"
#define PKG_STORE_DIR         "/data/pkgs"
#define PKG_TMP_DIR           "/data/tmp"
#define PKG_TMP_PKG_DIR       "/data/tmp/pkg"

#define PKG_NAME_MAX          63
#define PKG_VERSION_MAX       31
#define PKG_ARCH_MAX          31
#define PKG_COMPAT_MAX        63
#define PKG_HASH_HEX_LEN      64

/****************************************************************************
 * Public Types
 ****************************************************************************/

enum pkg_payload_type_e
{
  PKG_PAYLOAD_ELF = 0,
  PKG_PAYLOAD_SHARED_LIB
};

enum pkg_txn_state_e
{
  PKG_TXN_IDLE = 0,
  PKG_TXN_FETCHING,
  PKG_TXN_VERIFIED,
  PKG_TXN_STAGED,
  PKG_TXN_COMPAT_OK,
  PKG_TXN_ACTIVATED,
  PKG_TXN_CLEANUP,
  PKG_TXN_FAILED,
  PKG_TXN_RESTORE
};

struct pkg_manifest_s
{
  char name[PKG_NAME_MAX + 1];
  char version[PKG_VERSION_MAX + 1];
  char arch[PKG_ARCH_MAX + 1];
  char compat[PKG_COMPAT_MAX + 1];
  char artifact[PATH_MAX];
  char sha256[PKG_HASH_HEX_LEN + 1];
  enum pkg_payload_type_e type;
};

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

const char *pkg_manifest_type_str(enum pkg_payload_type_e type);
int pkg_manifest_validate(FAR const struct pkg_manifest_s *manifest);

int pkg_store_prepare_layout(void);
int pkg_store_format_index_path(FAR char *buffer, size_t size);
int pkg_store_format_installed_path(FAR char *buffer, size_t size);
int pkg_store_format_package_root(FAR char *buffer, size_t size,
                                  FAR const char *name);
int pkg_store_format_version_path(FAR char *buffer, size_t size,
                                  FAR const char *name,
                                  FAR const char *version);
int pkg_store_format_current_path(FAR char *buffer, size_t size,
                                  FAR const char *name);
int pkg_store_format_previous_path(FAR char *buffer, size_t size,
                                   FAR const char *name);
int pkg_store_format_txn_path(FAR char *buffer, size_t size,
                              FAR const char *name);
int pkg_store_format_lock_path(FAR char *buffer, size_t size,
                               FAR const char *name);
int pkg_store_format_download_path(FAR char *buffer, size_t size,
                                   FAR const char *name,
                                   FAR const char *version);

const char *pkg_txn_state_str(enum pkg_txn_state_e state);

void pkg_error(FAR const char *fmt, ...);
void pkg_info(FAR const char *fmt, ...);

#endif /* __APPS_SYSTEM_PKG_PKG_H */
