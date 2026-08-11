/****************************************************************************
 * apps/system/usbsh/usbsh_main.c
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

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include <nuttx/usb/cdcacm.h>

#include "nshlib/nshlib.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define USBSH_DEVICE   CONFIG_SYSTEM_USBSH_DEVNAME

/* How long to wait for the device node to appear after registering it */

#define USBSH_WAIT_MS  2000
#define USBSH_POLL_MS  50

/* How long to wait before offering the prompt again after a session ends */

#define USBSH_RETRY_MS 500

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: main
 *
 * Description:
 *   A second shell, on the USB serial port.
 *
 *   This board's console is the debug probe's RTT link, and reading that
 *   halts the CPU:  every keystroke and every line of output stops the
 *   scheduler for a moment.  That is tolerable for looking around and
 *   useless for anything being timed -- it stalls the thread refilling the
 *   audio and manufactures the dropouts one is trying to measure.
 *
 *   So this is a separate session rather than a replacement console.  The
 *   RTT shell stays exactly as it was, which also means there is still a
 *   way in if USB does not enumerate.  Both see the same filesystem, so
 *   what one does the other observes; only the terminals differ.
 *
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  struct stat buf;
  int waited;
  int ret;
  int fd;

  /* Register the CDC/ACM device.
   *
   * cdcacm_initialize() returns a negated errno rather than setting errno,
   * so the return value is the only thing worth reading.  Being told it is
   * already there is not a failure:  board bringup may have done it, or
   * this may be a second run.
   */

  ret = cdcacm_initialize(CONFIG_SYSTEM_USBSH_MINOR, NULL);
  if (ret < 0 && ret != -EEXIST)
    {
      syslog(LOG_ERR, "usbsh: cannot register %s: %d\n", USBSH_DEVICE, ret);
      return EXIT_FAILURE;
    }

  for (waited = 0; waited < USBSH_WAIT_MS; waited += USBSH_POLL_MS)
    {
      if (stat(USBSH_DEVICE, &buf) == 0)
        {
          break;
        }

      usleep(USBSH_POLL_MS * 1000);
    }

  if (waited >= USBSH_WAIT_MS)
    {
      syslog(LOG_ERR, "usbsh: %s never appeared\n", USBSH_DEVICE);
      return EXIT_FAILURE;
    }

  /* Run the session again every time it ends.
   *
   * nsh_consolemain() returns as soon as its input goes away, and on a USB
   * port that happens whenever the host closes the terminal -- including at
   * boot, when nobody has opened it yet.  Exiting then would mean the shell
   * only ever exists if a host happened to be attached at the right moment,
   * which is the opposite of useful.  So the session is re-established
   * instead, and unplugging the cable costs nothing but the session.
   */

  for (; ; )
    {
      fd = open(USBSH_DEVICE, O_RDWR);
      if (fd < 0)
        {
          usleep(USBSH_RETRY_MS * 1000);
          continue;
        }

      dup2(fd, 0);
      dup2(fd, 1);
      dup2(fd, 2);

      if (fd > 2)
        {
          close(fd);
        }

      nsh_consolemain(0, NULL);

      /* Give the port a moment before offering a prompt to nobody */

      usleep(USBSH_RETRY_MS * 1000);
    }

  return EXIT_SUCCESS;
}
