/****************************************************************************
 * apps/system/nxpkg/pkg_main.c
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkg.h"

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void pkg_show_usage(FAR FILE *stream, FAR const char *progname)
{
  fprintf(stream,
          "Usage: %s <install|update|list|rollback|recover|help> [args]\n",
          progname);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  FAR const char *cmd;

  if (argc < 2)
    {
      pkg_show_usage(stderr, argv[0]);
      return EXIT_FAILURE;
    }

  cmd = argv[1];

  if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 ||
      strcmp(cmd, "-h") == 0)
    {
      pkg_show_usage(stdout, argv[0]);
      return EXIT_SUCCESS;
    }

  if (strcmp(cmd, "install") == 0)
    {
      if (argc != 3)
        {
          pkg_error("install expects exactly one package name");
          pkg_show_usage(stderr, argv[0]);
          return EXIT_FAILURE;
        }

      return pkg_install(argv[2]);
    }

  if (strcmp(cmd, "update") == 0)
    {
      if (argc != 3)
        {
          pkg_error("update expects exactly one package name");
          pkg_show_usage(stderr, argv[0]);
          return EXIT_FAILURE;
        }

      return pkg_update(argv[2]);
    }

  if (strcmp(cmd, "list") == 0)
    {
      if (argc != 2)
        {
          pkg_error("list does not take additional arguments");
          pkg_show_usage(stderr, argv[0]);
          return EXIT_FAILURE;
        }

      return pkg_list(stdout);
    }

  if (strcmp(cmd, "rollback") == 0)
    {
      if (argc != 3)
        {
          pkg_error("rollback expects exactly one package name");
          pkg_show_usage(stderr, argv[0]);
          return EXIT_FAILURE;
        }

      return pkg_rollback(argv[2]);
    }

  if (strcmp(cmd, "recover") == 0)
    {
      if (argc == 2)
        {
          return pkg_recover_all();
        }

      if (argc == 3)
        {
          return pkg_recover(argv[2]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        }

      pkg_error("recover takes an optional package name");
      pkg_show_usage(stderr, argv[0]);
      return EXIT_FAILURE;
    }

  fprintf(stderr, "ERROR: Unknown subcommand '%s'\n", cmd);
  pkg_show_usage(stderr, argv[0]);
  return EXIT_FAILURE;
}
