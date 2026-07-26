/****************************************************************************
 * apps/testing/ostest/fork.c
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
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ostest.h"

#ifdef CONFIG_ARCH_HAVE_FORK

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define FORK_HEAPSIZE   256
#define FORK_PARENTMARK 0x5a
#define FORK_CHILDMARK  0xa5

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* .data and .bss, which a fork() child must get its own copy of */

static volatile int  g_forkdata = 1;
static volatile int  g_forkbss;
static FAR unsigned char *g_forkheap;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: fork_child
 *
 * Description:
 *   Everything the child does here is forbidden to a vfork() child and
 *   permitted to a fork() child:  it modifies data, it calls arbitrary
 *   functions, and -- by being a separate function that returns -- it
 *   returns from the function in which fork() was called.
 *
 *   Returns the exit status the child should use.
 *
 ****************************************************************************/

static int fork_child(void)
{
  FAR char *scratch;

  /* Write our own values over the parent's.  The parent must not see any of
   * this.
   */

  g_forkdata = 2;
  g_forkbss  = 2;
  memset(g_forkheap, FORK_CHILDMARK, FORK_HEAPSIZE);

  /* Call malloc() and printf().  A vfork() child may not do this; a fork()
   * child may, because the heap it is allocating from is its own.
   */

  scratch = malloc(64);
  if (scratch == NULL)
    {
      printf("fork_test: ERROR Child could not malloc()\n");
      return 1;
    }

  strlcpy(scratch, "child", 64);
  printf("fork_test: Child running independently (%s)\n", scratch);
  free(scratch);

  /* Give the parent time to make its own writes, so that if the two shared
   * memory we would see the parent's values below rather than our own.
   */

  usleep(200 * 1000);

  if (g_forkdata != 2 || g_forkbss != 2)
    {
      printf("fork_test: ERROR Child saw the parent's writes: "
             "data=%d bss=%d\n", g_forkdata, g_forkbss);
      return 1;
    }

  if (g_forkheap[0] != FORK_CHILDMARK ||
      g_forkheap[FORK_HEAPSIZE - 1] != FORK_CHILDMARK)
    {
      printf("fork_test: ERROR Child saw the parent's heap writes\n");
      return 1;
    }

  return 0;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: fork_test
 *
 * Description:
 *   Verify the defining property of POSIX fork():  the child gets its own
 *   copy of the parent's memory.  Writes by the child are invisible to the
 *   parent and writes by the parent are invisible to the child -- the exact
 *   opposite of what task_fork_test() checks, which is why the two cannot be
 *   the same function.
 *
 *   Also verifies that none of vfork()'s restrictions apply:  the child
 *   modifies data, returns from the function that called fork(), calls
 *   malloc() and printf(), and runs concurrently with the parent.
 *
 ****************************************************************************/

int fork_test(void)
{
  pid_t pid;
  int status = 0;
  int ret = 0;

  printf("fork_test: Started\n");

  g_forkdata = 1;
  g_forkbss  = 1;

  g_forkheap = malloc(FORK_HEAPSIZE);
  if (g_forkheap == NULL)
    {
      printf("fork_test: ERROR Failed to allocate the heap probe\n");
      ASSERT(false);
      return -1;
    }

  memset(g_forkheap, FORK_PARENTMARK, FORK_HEAPSIZE);

  pid = fork();
  if (pid == 0)
    {
      /* Child.  Note that it returns from fork_child() and then from the
       * branch of fork_test() it was forked in -- both illegal for vfork().
       */

      _exit(fork_child());
    }
  else if (pid < 0)
    {
      printf("fork_test: ERROR fork() failed: %d\n", errno);
      free(g_forkheap);
      ASSERT(false);
      return -1;
    }

  /* Parent.  It runs concurrently with the child, so make our own writes now
   * and check afterwards that the child never saw them and that we never saw
   * the child's.
   */

  g_forkdata = 3;
  g_forkbss  = 3;
  memset(g_forkheap, FORK_PARENTMARK, FORK_HEAPSIZE);

#ifdef CONFIG_SCHED_WAITPID
  if (waitpid(pid, &status, 0) != pid)
    {
      printf("fork_test: ERROR waitpid() failed: %d\n", errno);
      free(g_forkheap);
      ASSERT(false);
      return -1;
    }
#else
  sleep(1);
#endif

  if (g_forkdata != 3 || g_forkbss != 3)
    {
      printf("fork_test: ERROR Parent saw the child's writes: "
             "data=%d bss=%d (expected 3, 3)\n", g_forkdata, g_forkbss);
      ret = -1;
    }

  if (g_forkheap[0] != FORK_PARENTMARK ||
      g_forkheap[FORK_HEAPSIZE - 1] != FORK_PARENTMARK)
    {
      printf("fork_test: ERROR Parent saw the child's heap writes\n");
      ret = -1;
    }

#ifdef CONFIG_SCHED_WAITPID
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
      printf("fork_test: ERROR Child reported failure, status 0x%04x\n",
             status);
      ret = -1;
    }
#endif

  free(g_forkheap);
  g_forkheap = NULL;

  if (ret < 0)
    {
      ASSERT(false);
      return ret;
    }

  printf("fork_test: Parent and child had independent memory\n");
  return 0;
}

#endif /* CONFIG_ARCH_HAVE_FORK */
