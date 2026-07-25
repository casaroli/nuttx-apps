/****************************************************************************
 * apps/examples/forktest/forktest_main.c
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
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: deep
 *
 * Description:
 *   Recurse before forking so that several register windows are live and
 *   have been spilled onto the stack.  The child inherits a copy of that
 *   stack, and its first returns unwind through the copied frames -- which
 *   is the part of fork() the Xtensa windowed ABI makes interesting.  The
 *   sum is carried back out so the compiler cannot discard the frames.
 *
 ****************************************************************************/

static int deep(int depth, pid_t *pid)
{
  volatile int marker = depth * 7;

  if (depth > 0)
    {
      return marker + deep(depth - 1, pid);
    }

  *pid = fork();
  return marker;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  char      onstack[64];
  pid_t     pid = -1;
  int       sum;
  int       status;

  /* Something on the parent's stack with a known value.  The child must see
   * its own copy: same contents, but writing to it must not be visible to
   * the parent.
   */

  strlcpy(onstack, "parent", sizeof(onstack));

  printf("forktest: parent pid=%d, forking from 6 frames deep\n", getpid());
  fflush(stdout);

  sum = deep(5, &pid);

  if (pid < 0)
    {
      printf("forktest: FAIL fork() returned %d\n", (int)pid);
      return 1;
    }

  if (pid == 0)
    {
      /* Child.  Check what it inherited, then change it. */

      printf("forktest: child  pid=%d, fork() returned 0, sum=%d, "
             "inherited \"%s\"\n", getpid(), sum, onstack);
      strlcpy(onstack, "child", sizeof(onstack));
      printf("forktest: child  wrote \"%s\" to its own stack copy\n",
             onstack);
      fflush(stdout);
      exit(42);
    }

  /* Parent */

  printf("forktest: parent fork() returned child pid=%d, sum=%d\n",
         (int)pid, sum);
  fflush(stdout);

  if (waitpid(pid, &status, 0) != pid)
    {
      printf("forktest: FAIL waitpid() did not reap %d\n", (int)pid);
      return 1;
    }

  printf("forktest: parent reaped child, exit status %d (expected 42)\n",
         WEXITSTATUS(status));
  printf("forktest: parent stack still says \"%s\" (expected \"parent\")\n",
         onstack);

  if (WEXITSTATUS(status) != 42)
    {
      printf("forktest: FAIL wrong exit status\n");
      return 1;
    }

  if (strcmp(onstack, "parent") != 0)
    {
      printf("forktest: FAIL the child wrote through to the parent stack\n");
      return 1;
    }

  printf("forktest: PASS\n");
  return 0;
}
