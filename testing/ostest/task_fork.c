/****************************************************************************
 * apps/testing/ostest/task_fork.c
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
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ostest.h"

/****************************************************************************
 * Private Data
 ****************************************************************************/

static volatile bool g_taskforkchild;

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: task_fork_test
 *
 * Description:
 *   Verify the defining property of task_fork():  the child shares the
 *   parent's memory, so the parent observes the child's write.  This is the
 *   test that used to be called the "vfork" test.  A real fork() child's
 *   write would be invisible here; see fork_test().
 *
 ****************************************************************************/

int task_fork_test(void)
{
  pid_t pid;

  printf("task_fork_test: Started\n");

  g_taskforkchild = false;
  pid = task_fork();
  if (pid == 0)
    {
      /* Shared memory, so the parent sees this.  Runs concurrently. */

      g_taskforkchild = true;
      exit(0);
    }
  else if (pid < 0)
    {
      printf("task_fork_test: ERROR task_fork() failed: %d\n", errno);
      ASSERT(false);
      return -1;
    }

  sleep(1);

  if (!g_taskforkchild)
    {
      printf("task_fork_test: ERROR Child %d did not run, or its write to "
             "shared memory was not visible\n", pid);
      ASSERT(false);
      return -1;
    }

  printf("task_fork_test: Child %d ran successfully\n", pid);
  return 0;
}
