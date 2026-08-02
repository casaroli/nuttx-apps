/****************************************************************************
 * apps/system/termreset/termreset.c
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

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: main
 *
 * Description:
 *   Put the terminal back the way a shell expects to find it.
 *
 *   A full-screen program turns echo and canonical input off and restores
 *   them when it exits.  One that is killed instead -- Ctrl-C out of an
 *   editor, say -- never gets to, and leaves a terminal that still runs
 *   commands but shows nothing as they are typed.  That is what this is
 *   for, and it is why the traditional name is `reset`.
 *
 *   Only the local modes are touched.  Baud, parity and flow control belong
 *   to whoever configured the port and are not this program's business to
 *   guess at.
 *
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  struct termios term;

  if (tcgetattr(STDIN_FILENO, &term) < 0)
    {
      /* Not a terminal, or a driver with no termios at all.  Nothing to
       * restore, and saying so is more use than failing silently.
       */

      fprintf(stderr, "reset: not a terminal\n");
      return EXIT_FAILURE;
    }

  term.c_lflag |= ECHO | ICANON | ISIG;

  if (tcsetattr(STDIN_FILENO, TCSANOW, &term) < 0)
    {
      fprintf(stderr, "reset: could not restore the terminal\n");
      return EXIT_FAILURE;
    }

  /* Start on a fresh line: whatever was interrupted probably left the
   * cursor somewhere in the middle of one.
   */

  putchar('\n');
  return EXIT_SUCCESS;
}
