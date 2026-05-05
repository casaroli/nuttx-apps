/****************************************************************************
 * apps/system/pkg/pkg_main.c
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

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void pkg_show_usage(FAR FILE *stream, FAR const char *progname)
{
  fprintf(stream,
          "Usage: %s <install|update|list|rollback|help> [args]\n",
          progname);
}

static int pkg_not_implemented(FAR const char *cmd)
{
  fprintf(stderr,
          "ERROR: 'pkg %s' is not implemented yet in the current unit.\n",
          cmd);
  return EXIT_FAILURE;
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
      return pkg_not_implemented("install");
    }

  if (strcmp(cmd, "update") == 0)
    {
      return pkg_not_implemented("update");
    }

  if (strcmp(cmd, "list") == 0)
    {
      return pkg_not_implemented("list");
    }

  if (strcmp(cmd, "rollback") == 0)
    {
      return pkg_not_implemented("rollback");
    }

  fprintf(stderr, "ERROR: Unknown subcommand '%s'\n", cmd);
  pkg_show_usage(stderr, argv[0]);
  return EXIT_FAILURE;
}
