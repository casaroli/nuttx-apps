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

#include <nuttx/ascii.h>
#include <nuttx/nx/nx.h>
#include <nuttx/input/kbd_codec.h>
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
  int ret;

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

      /* Forward the presses.
       *
       * Releases are dropped: NX carries characters, not key states, so a
       * release would arrive at the shell as a second copy of the same
       * keystroke.
       *
       * An arrow key produces no character, so a keyboard reports it as a
       * special key carrying a keycode rather than as a press carrying a
       * character.  A terminal has no idea what a keycode means, so they
       * are translated here into the ANSI sequences one does:
       * ESC [ A/B/C/D.  This is the right layer for it -- the keyboard
       * device stays generic, and the thing feeding a terminal speaks
       * terminal.
       *
       * Without this, readline never sees an arrow key at all and a line
       * cannot be edited anywhere but at its end.
       *
       * Any other special key is dropped rather than guessed at.  There is
       * no character it could stand for, and emitting the keycode would put
       * an unrelated character on the display.
       */

      for (size_t i = 0; i < (size_t)nread / sizeof(struct keyboard_event_s);
           i++)
        {
          uint8_t seq[3];
          uint8_t nch;

          if (events[i].type == KEYBOARD_SPECPRESS)
            {
              char final;

              switch (events[i].code)
                {
                  case KEYCODE_UP:
                    final = 'A';
                    break;

                  case KEYCODE_DOWN:
                    final = 'B';
                    break;

                  case KEYCODE_LEFT:
                    final = 'D';
                    break;

                  case KEYCODE_RIGHT:
                    final = 'C';
                    break;

                  default:
                    continue;
                }

              seq[0] = ASCII_ESC;
              seq[1] = '[';
              seq[2] = final;
              nch    = 3;
            }
          else if (events[i].type == KEYBOARD_PRESS)
            {
              if (events[i].code == 0 || events[i].code > 0x7f)
                {
                  continue;
                }

              seq[0] = (uint8_t)events[i].code;
              nch    = 1;
            }
          else
            {
              continue;
            }

          ret = nx_kbdin(handle, nch, seq);
          if (ret < 0)
            {
              fprintf(stderr, "kbdbridge: nx_kbdin failed: %d\n", ret);
            }
        }
    }

  close(fd);
  nx_disconnect(handle);
  return EXIT_SUCCESS;
}
