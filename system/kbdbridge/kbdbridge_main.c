/****************************************************************************
 * apps/system/kbdbridge/kbdbridge_main.c
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

/* Feed a keyboard upper-half device into the NX server.
 *
 * NX has no keyboard driver of its own: something has to read the hardware
 * and call nx_kbdin(), and NX then routes the characters to whichever window
 * has focus.  Windows that want them -- an NxTerm, for instance -- receive
 * them through their kbdin callback.
 *
 * This is that something, for any keyboard registered through the
 * INPUT_KEYBOARD upper half.  It is a separate client rather than a thread
 * inside the graphics application because NX is a server: a bridge that
 * connects on its own can serve whatever window happens to have focus,
 * without every application having to grow its own input plumbing.
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <debug.h>

#include <nuttx/nx/nx.h>
#include <nuttx/input/keyboard.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define KBDBRIDGE_BATCH  8    /* Events read per pass */

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: kbdbridge_usage
 ****************************************************************************/

static void kbdbridge_usage(void)
{
  printf("Usage: kbdbridge [<keyboard device>]\n"
         "  Default: %s\n", CONFIG_SYSTEM_KBDBRIDGE_DEVPATH);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  struct keyboard_event_s events[KBDBRIDGE_BATCH];
  FAR const char *devpath = CONFIG_SYSTEM_KBDBRIDGE_DEVPATH;
  NXHANDLE handle;
  ssize_t nread;
  int fd;

  if (argc > 2)
    {
      kbdbridge_usage();
      return EXIT_FAILURE;
    }

  if (argc == 2)
    {
      devpath = argv[1];
    }

  /* Connect to the running NX server.  This does not start one: the
   * graphics application owns the server's lifetime, and a bridge that
   * outlived it would inject into nothing.
   */

  handle = nx_connect();
  if (handle == NULL)
    {
      fprintf(stderr, "kbdbridge: nx_connect failed: %d\n", errno);
      fprintf(stderr, "kbdbridge: is a graphics application running?\n");
      return EXIT_FAILURE;
    }

  fd = open(devpath, O_RDONLY);
  if (fd < 0)
    {
      fprintf(stderr, "kbdbridge: open %s failed: %d\n", devpath, errno);
      nx_disconnect(handle);
      return EXIT_FAILURE;
    }

  printf("kbdbridge: %s -> NX\n", devpath);

  for (; ; )
    {
      nread = read(fd, events, sizeof(events));
      if (nread < 0)
        {
          if (errno == EINTR)
            {
              continue;
            }

          fprintf(stderr, "kbdbridge: read failed: %d\n", errno);
          break;
        }

      if (nread == 0)
        {
          continue;
        }

      /* Forward the presses one character at a time.
       *
       * Releases are dropped: NX carries characters, not key states, so a
       * release would arrive at the shell as a second copy of the same
       * keystroke.  Codes outside 7-bit ASCII are dropped for the same
       * reason -- the arrow keys report 0x80-0x83, which is a keyboard
       * convention rather than anything a terminal can render.
       */

      for (size_t i = 0; i < (size_t)nread / sizeof(struct keyboard_event_s);
           i++)
        {
          uint8_t ch;

          if (events[i].type != KEYBOARD_PRESS)
            {
              continue;
            }

          if (events[i].code == 0 || events[i].code > 0x7f)
            {
              continue;
            }

          ch = (uint8_t)events[i].code;
          nx_kbdin(handle, 1, &ch);
        }
    }

  close(fd);
  nx_disconnect(handle);
  return EXIT_SUCCESS;
}
