/****************************************************************************
 * apps/testing/ostest/vfork.c
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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ostest.h"

#if defined(CONFIG_ARCH_HAVE_VFORK) && defined(CONFIG_SCHED_WAITPID)

/****************************************************************************
 * Private Data
 ****************************************************************************/

static volatile bool g_vforkchild;

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int vfork_test(void)
{
  pid_t pid;

  g_vforkchild = false;
  pid = vfork();
  if (pid == 0)
    {
      /* The child borrows the parent's memory, so setting g_vforkchild here
       * is what the parent will observe below.  That sharing is the whole
       * point of vfork() and is what this test verifies.
       *
       * POSIX allows the child almost nothing else: it must not modify any
       * other data, must not return from this function, and must not call
       * any function other than _exit() or one of the exec family.  In
       * particular it must leave through _exit() rather than exit() -- the
       * child is running in the parent's address space, so running atexit
       * handlers and flushing the parent's stdio buffers here is precisely
       * the misuse the restriction exists to prevent.
       */

      g_vforkchild = true;
      _exit(0);
    }
  else if (pid < 0)
    {
      printf("vfork_test: ERROR vfork() failed: %d\n", errno);
      ASSERT(false);
      return -1;
    }
  else
    {
      /* vfork() does not return in the parent until the child has called
       * _exit() or exec(), so the child's write is already visible.  The
       * sleep only makes a failure easier to tell apart from a race.
       */

      sleep(1);
      if (g_vforkchild)
        {
          printf("vfork_test: Child %d ran successfully\n", pid);
        }
      else
        {
          printf("vfork_test: ERROR Child %d did not run, or did not share "
                 "the parent's memory\n", pid);
          ASSERT(false);
          return -1;
        }
    }

  return 0;
}

#endif /* CONFIG_ARCH_HAVE_FORK && CONFIG_SCHED_WAITPID */
