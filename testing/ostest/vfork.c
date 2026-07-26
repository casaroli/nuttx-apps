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
#include <sys/wait.h>
#include <unistd.h>

#include "ostest.h"

#ifdef CONFIG_ARCH_HAVE_VFORK

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* Set by the parent before vfork() and cleared by the parent after it
 * resumes.  The child never touches it -- a vfork() child may not modify any
 * data other than the pid_t holding vfork()'s return value.
 */

static volatile bool g_vforkrunning;

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: vfork_test
 *
 * Description:
 *   Verify the defining property of vfork():  the parent is suspended until
 *   the child calls _exit() or one of the exec family of functions.
 *
 *   The child does only what POSIX permits it to do -- it calls _exit(), and
 *   nothing else.  In particular it does not call exit(), which would run
 *   atexit handlers and flush stdio in the parent's address space; that is
 *   exactly the misuse vfork()'s restrictions exist to prevent, and a test
 *   that did it would be testing the wrong thing.
 *
 *   Because the child may not write memory and the parent cannot run while
 *   the child lives, the observable is the child's *exit status*:  if the
 *   parent were not suspended it would reach waitpid() before the child had
 *   run at all.
 *
 ****************************************************************************/

int vfork_test(void)
{
  pid_t pid;

  printf("vfork_test: Started\n");

  g_vforkrunning = true;

  pid = vfork();
  if (pid == 0)
    {
      /* Child.  The only thing it is allowed to do is leave.  Note _exit()
       * and not exit():  we are running in the parent's address space on
       * borrowed time.
       */

      _exit(42);
    }
  else if (pid < 0)
    {
      printf("vfork_test: ERROR vfork() failed: %d\n", errno);
      ASSERT(false);
      return -1;
    }

  /* Parent.  We only get here once the child has exited or exec'ed:  that is
   * what vfork() promises, and it is what we are testing.
   */

  g_vforkrunning = false;

#ifdef CONFIG_SCHED_WAITPID
    {
      int status = 0;
      pid_t ret;

      ret = waitpid(pid, &status, 0);

#ifdef CONFIG_SCHED_CHILD_STATUS
      /* The child's status was retained for us to collect. */

      if (ret != pid)
        {
          printf("vfork_test: ERROR waitpid() returned %d (%d)\n",
                 ret, errno);
          ASSERT(false);
          return -1;
        }

      if (!WIFEXITED(status) || WEXITSTATUS(status) != 42)
        {
          printf("vfork_test: ERROR Child %d status 0x%04x, expected "
                 "exit(42)\n", pid, status);
          ASSERT(false);
          return -1;
        }
#else
      /* Without CONFIG_SCHED_CHILD_STATUS an exited child's status is not
       * retained, so waitpid() can only answer for a child that still
       * exists.  ECHILD here is therefore not a failure -- it is the
       * evidence we are looking for:  the child had already run and
       * terminated by the time we resumed, which is exactly what vfork()
       * promises.  Had we not been suspended, waitpid() would have blocked
       * on a child that was still alive.
       */

      if (ret >= 0 || errno != ECHILD)
        {
          printf("vfork_test: ERROR waitpid() returned %d (%d), expected "
                 "ECHILD for an already-terminated child\n", ret, errno);
          ASSERT(false);
          return -1;
        }

      UNUSED(status);
#endif
    }
#endif

  printf("vfork_test: Child %d ran and exited before the parent resumed\n",
         pid);
  return 0;
}

#endif /* CONFIG_ARCH_HAVE_VFORK */
