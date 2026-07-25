/****************************************************************************
 * apps/system/nxpkg/pkg_lifecycle.c
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pkg.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: pkg_recover
 *
 * Description:
 *   Heal a package left in a torn state by an operation that was interrupted
 *   (power loss / reset) mid-transaction.  A leftover .txn or .lock file
 *   marks an incomplete transaction.
 *
 *   The installed database (installed.json) is the authoritative committed
 *   state and is written atomically as the final activation step; the
 *   on-disk current/previous activation pointers are a derived mirror.
 *   Recovery therefore re-derives the pointers from the installed database,
 *   which rolls an uncommitted transaction back and rolls a committed-but-
 *   not-yet-cleaned-up one forward, then drops the stale .lock and .txn.
 *
 *   Single-user assumption: any .lock present at the start of an op is from
 *   a crashed run, not a live concurrent one.
 *
 ****************************************************************************/

int pkg_recover(FAR const char *name)
{
  FAR struct pkg_installed_db_s *db;
  FAR struct pkg_installed_entry_s *entry;
  char txn_path[PATH_MAX];
  char lock_path[PATH_MAX];
  struct stat st;
  int ret;

  ret = pkg_store_format_txn_path(txn_path, sizeof(txn_path), name);
  if (ret < 0)
    {
      return ret;
    }

  ret = pkg_store_format_lock_path(lock_path, sizeof(lock_path), name);
  if (ret < 0)
    {
      return ret;
    }

  if (stat(txn_path, &st) != 0 && stat(lock_path, &st) != 0)
    {
      return 0;  /* No leftover markers: nothing to recover. */
    }

  pkg_info("recovering interrupted transaction for '%s'", name);

  /* Re-derive the activation pointers from the authoritative installed db.
   * If the package has no entry (a first install that never committed),
   * there is nothing to activate; the orphaned version dir is harmless.
   */

  db = malloc(sizeof(*db));
  if (db == NULL)
    {
      pkg_error("unable to allocate installed metadata buffer");
      return -ENOMEM;
    }

  ret = pkg_metadata_load_installed(db);
  if (ret >= 0)
    {
      entry = pkg_metadata_find_installed(db, name);
      if (entry != NULL)
        {
          pkg_store_write_pointers(name, entry->current, entry->previous);
        }
    }

  free(db);

  /* Drop the stale lock and transaction marker. */

  pkg_store_remove_file(lock_path);
  pkg_txn_clear_state(name);

  pkg_info("recovered '%s'", name);
  return 0;
}

/****************************************************************************
 * Name: pkg_recover_all
 *
 * Description:
 *   Run recovery for every package present in the installed database.  Used
 *   by "nxpkg recover" with no package name (e.g. at boot).
 *
 ****************************************************************************/

int pkg_recover_all(void)
{
  FAR struct pkg_installed_db_s *db;
  size_t i;
  int ret;

  db = malloc(sizeof(*db));
  if (db == NULL)
    {
      pkg_error("unable to allocate installed metadata buffer");
      return EXIT_FAILURE;
    }

  ret = pkg_store_prepare_layout();
  if (ret < 0)
    {
      free(db);
      pkg_error("unable to prepare package layout: %d", ret);
      return EXIT_FAILURE;
    }

  ret = pkg_metadata_load_installed(db);
  if (ret < 0)
    {
      free(db);
      pkg_error("unable to load installed metadata: %d", ret);
      return EXIT_FAILURE;
    }

  for (i = 0; i < db->count; i++)
    {
      pkg_recover(db->entries[i].name);
    }

  free(db);
  return EXIT_SUCCESS;
}

/****************************************************************************
 * Name: pkg_update
 *
 * Description:
 *   Update an already-installed package to the latest compatible version in
 *   the local index.  The heavy lifting (fetch -> verify -> stage ->
 *   compatibility gate -> activate) is the same transactional pipeline used
 *   by install, which atomically switches the "current" pointer while
 *   preserving the prior version as "previous" (enabling rollback).  This
 *   entry point only adds the update-specific guards: the package must
 *   already be installed, and there must be a newer version to move to.
 *
 ****************************************************************************/

int pkg_update(FAR const char *name)
{
  FAR struct pkg_index_s *index;
  FAR struct pkg_installed_db_s *installed;
  FAR const struct pkg_manifest_s *manifest;
  FAR struct pkg_installed_entry_s *entry;
  char current[PKG_VERSION_MAX + 1];
  int ret;

  index = malloc(sizeof(*index));
  installed = malloc(sizeof(*installed));
  if (index == NULL || installed == NULL)
    {
      free(index);
      free(installed);
      pkg_error("unable to allocate package metadata buffers");
      return EXIT_FAILURE;
    }

  ret = pkg_store_prepare_layout();
  if (ret < 0)
    {
      pkg_error("unable to prepare package layout: %d", ret);
      goto errout;
    }

  pkg_recover(name);

  ret = pkg_metadata_load_index(index);
  if (ret < 0)
    {
      pkg_error("unable to load local index metadata: %d", ret);
      goto errout;
    }

  ret = pkg_metadata_load_installed(installed);
  if (ret < 0)
    {
      pkg_error("unable to load installed metadata: %d", ret);
      goto errout;
    }

  entry = pkg_metadata_find_installed(installed, name);
  if (entry == NULL)
    {
      pkg_error("'%s' is not installed; use install first", name);
      goto errout;
    }

  ret = snprintf(current, sizeof(current), "%s", entry->current);
  if (ret < 0 || (size_t)ret >= sizeof(current))
    {
      pkg_error("installed version string for '%s' is invalid", name);
      goto errout;
    }

  manifest = pkg_metadata_find_latest(index, name);
  if (manifest == NULL)
    {
      pkg_error("package '%s' not found in local index", name);
      goto errout;
    }

  if (strcmp(manifest->version, current) == 0)
    {
      pkg_info("'%s' is already up to date at version %s", name, current);
      free(index);
      free(installed);
      return EXIT_SUCCESS;
    }

  pkg_info("updating '%s' from %s to %s", name, current, manifest->version);

  /* Reuse the install pipeline: it stages the new version and atomically
   * promotes the running version to "previous" while switching "current".
   */

  free(index);
  free(installed);
  return pkg_install(name);

errout:
  free(index);
  free(installed);
  return EXIT_FAILURE;
}

/****************************************************************************
 * Name: pkg_rollback
 *
 * Description:
 *   Roll a package back to its previously-active version.  Because every
 *   installed version is staged in an immutable directory and activation is
 *   just a pointer, rollback is a pointer swap: "current" and "previous" are
 *   exchanged in the installed database and in the on-disk activation
 *   pointers.  The swap is bracketed by a transaction-state file so an
 *   interrupted rollback is recoverable rather than leaving a torn state.
 *
 ****************************************************************************/

int pkg_rollback(FAR const char *name)
{
  FAR struct pkg_installed_db_s *installed;
  FAR struct pkg_installed_entry_s *entry;
  struct stat st;
  char version_dir[PATH_MAX];
  char swap[PKG_VERSION_MAX + 1];
  int ret;

  installed = malloc(sizeof(*installed));
  if (installed == NULL)
    {
      pkg_error("unable to allocate installed metadata buffer");
      return EXIT_FAILURE;
    }

  ret = pkg_store_prepare_layout();
  if (ret < 0)
    {
      free(installed);
      pkg_error("unable to prepare package layout: %d", ret);
      return EXIT_FAILURE;
    }

  /* Heal any interrupted transaction before touching the pointers. */

  pkg_recover(name);

  ret = pkg_metadata_load_installed(installed);
  if (ret < 0)
    {
      free(installed);
      pkg_error("unable to load installed metadata: %d", ret);
      return EXIT_FAILURE;
    }

  entry = pkg_metadata_find_installed(installed, name);
  if (entry == NULL)
    {
      free(installed);
      pkg_error("'%s' is not installed", name);
      return EXIT_FAILURE;
    }

  if (entry->previous[0] == '\0')
    {
      free(installed);
      pkg_error("'%s' has no previous version to roll back to", name);
      return EXIT_FAILURE;
    }

  /* The previous version's immutable directory must still be staged. */

  ret = pkg_store_format_version_path(version_dir, sizeof(version_dir), name,
                                      entry->previous);
  if (ret < 0)
    {
      free(installed);
      pkg_error("unable to resolve version path for '%s': %d", name, ret);
      return EXIT_FAILURE;
    }

  if (stat(version_dir, &st) < 0 || !S_ISDIR(st.st_mode))
    {
      free(installed);
      pkg_error("previous version %s of '%s' is no longer staged",
                entry->previous, name);
      return EXIT_FAILURE;
    }

  pkg_info("rolling back '%s' from %s to %s", name, entry->current,
           entry->previous);

  ret = pkg_txn_write_state(name, PKG_TXN_RESTORE);
  if (ret < 0)
    {
      goto txnout;
    }

  /* Swap current <-> previous in the installed database. */

  strlcpy(swap, entry->current, sizeof(swap));
  strlcpy(entry->current, entry->previous, sizeof(entry->current));
  strlcpy(entry->previous, swap, sizeof(entry->previous));

  ret = pkg_store_write_pointers(name, entry->current, entry->previous);
  if (ret < 0)
    {
      goto txnout;
    }

  ret = pkg_metadata_save_installed(installed);
  if (ret < 0)
    {
      goto txnout;
    }

  pkg_txn_write_state(name, PKG_TXN_ACTIVATED);
  pkg_txn_clear_state(name);

  pkg_info("rolled back '%s' to version %s", name, entry->current);
  free(installed);
  return EXIT_SUCCESS;

txnout:
  pkg_txn_write_state(name, PKG_TXN_FAILED);
  pkg_txn_clear_state(name);
  free(installed);
  pkg_error("rollback failed for '%s': %d", name, ret);
  return EXIT_FAILURE;
}
