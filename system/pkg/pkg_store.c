/****************************************************************************
 * apps/system/pkg/pkg_store.c
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "pkg.h"

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int pkg_store_format(FAR char *buffer, size_t size,
                            FAR const char *fmt,
                            FAR const char *name,
                            FAR const char *version)
{
  int ret;

  ret = snprintf(buffer, size, fmt, name, version);
  if (ret < 0)
    {
      return ret;
    }

  if ((size_t)ret >= size)
    {
      return -ENAMETOOLONG;
    }

  return 0;
}

static int pkg_store_mkdir(FAR const char *path)
{
  struct stat st;
  int ret;

  ret = stat(path, &st);
  if (ret == 0)
    {
      return S_ISDIR(st.st_mode) ? 0 : -ENOTDIR;
    }

  if (errno != ENOENT)
    {
      return -errno;
    }

  ret = mkdir(path, 0755);
  if (ret < 0 && errno != EEXIST)
    {
      return -errno;
    }

  return 0;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int pkg_store_prepare_layout(void)
{
  int ret;

  ret = pkg_store_mkdir("/data");
  if (ret < 0)
    {
      return ret;
    }

  ret = pkg_store_mkdir(PKG_REPO_DIR);
  if (ret < 0)
    {
      return ret;
    }

  ret = pkg_store_mkdir(PKG_STORE_DIR);
  if (ret < 0)
    {
      return ret;
    }

  ret = pkg_store_mkdir(PKG_TMP_DIR);
  if (ret < 0)
    {
      return ret;
    }

  return pkg_store_mkdir(PKG_TMP_PKG_DIR);
}

int pkg_store_format_index_path(FAR char *buffer, size_t size)
{
  return pkg_store_format(buffer, size, "%s", PKG_REPO_INDEX, "");
}

int pkg_store_format_installed_path(FAR char *buffer, size_t size)
{
  return pkg_store_format(buffer, size, "%s", PKG_REPO_INSTALLED, "");
}

int pkg_store_format_package_root(FAR char *buffer, size_t size,
                                  FAR const char *name)
{
  return pkg_store_format(buffer, size, PKG_STORE_DIR "/%s", name, "");
}

int pkg_store_format_version_path(FAR char *buffer, size_t size,
                                  FAR const char *name,
                                  FAR const char *version)
{
  return pkg_store_format(buffer, size, PKG_STORE_DIR "/%s/%s", name, version);
}

int pkg_store_format_current_path(FAR char *buffer, size_t size,
                                  FAR const char *name)
{
  return pkg_store_format(buffer, size, PKG_STORE_DIR "/%s/current", name, "");
}

int pkg_store_format_previous_path(FAR char *buffer, size_t size,
                                   FAR const char *name)
{
  return pkg_store_format(buffer, size, PKG_STORE_DIR "/%s/previous", name,
                          "");
}

int pkg_store_format_txn_path(FAR char *buffer, size_t size,
                              FAR const char *name)
{
  return pkg_store_format(buffer, size, PKG_STORE_DIR "/%s/.txn", name, "");
}

int pkg_store_format_lock_path(FAR char *buffer, size_t size,
                               FAR const char *name)
{
  return pkg_store_format(buffer, size, PKG_STORE_DIR "/%s/.lock", name, "");
}

int pkg_store_format_download_path(FAR char *buffer, size_t size,
                                   FAR const char *name,
                                   FAR const char *version)
{
  return pkg_store_format(buffer, size, PKG_TMP_PKG_DIR "/%s-%s.npkg", name,
                          version);
}
