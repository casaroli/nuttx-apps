/****************************************************************************
 * apps/examples/misbehave/misbehave_main.c
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

/* What this asks
 * ==============
 *
 * examples/sandbox asks whether a task can reach memory it does not own.
 * This asks the complementary question:  whatever an application does wrong,
 * does the *system* survive it?
 *
 * The two are not the same.  A boundary can be enforced perfectly and the
 * kernel still panic on the fault that enforced it -- which is the whole
 * point of the user-fault recovery work -- and a fault need not involve a
 * boundary at all.  A divide by zero, an unaligned load or a corrupt opcode
 * are things a *correctly confined* application does to itself, and none of
 * them may stop the machine.
 *
 * What is a pass
 * ==============
 *
 * The invariant is only this:  the offender may die, but nothing else may.
 * So for each misbehaviour the checks are
 *
 *   - this task is still running afterwards, and
 *   - an unrelated task is still making progress.
 *
 * Whether the offending operation faults at all is deliberately NOT a
 * criterion, because it is architecture-specific:  ARMv7-A and later permit
 * unaligned loads, RISC-V returns -1 for an integer divide by zero rather
 * than trapping, and Xtensa traps both.  A misbehaviour that simply completes
 * is reported as such and is not a failure -- the operation was legal on this
 * hardware.  What would be a failure is the console going silent, which no
 * check inside this program can report; that result is the absence of the
 * summary at the end.
 *
 * Usage
 * =====
 *
 *   misbehave                 run every misbehaviour in turn
 *   misbehave <name>          run just one
 *   misbehave do <name>       misbehave in *this* task, for use under a
 *                             debugger; in a contained build this does not
 *                             return
 *   misbehave -l              list them
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/wait.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CONFIG_BUILD_KERNEL
#include <spawn.h>
#endif

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define CANARY_PRIORITY    (CONFIG_EXAMPLES_MISBEHAVE_PRIORITY - 1)
#define CANARY_STACKSIZE   2048
#define OFFENDER_STACKSIZE CONFIG_EXAMPLES_MISBEHAVE_STACKSIZE

/* Exit status the offender reports when its misbehaviour simply completed.
 * Distinguishes "this hardware does not trap that" from "it was contained".
 */

#define MISBEHAVE_SURVIVED 42

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct misbehaviour_s
{
  FAR const char *name;
  FAR const char *what;
  CODE void (*fn)(void);
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

static volatile unsigned long g_canary;
static volatile bool          g_canary_stop;

/* Written through by the misbehaviours so the compiler cannot fold them
 * away, and read back so it cannot discard the write either.
 */

static volatile uint32_t g_sink;
static volatile int      g_zero;
static volatile int      g_one = 1;

#ifdef CONFIG_BUILD_KERNEL
static FAR const char *g_progpath = "misbehave";
#endif

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/* The misbehaviours themselves.  Each one is written so that the compiler
 * cannot prove it undefined and delete it:  the addresses and operands all
 * come through volatile objects it must reload.
 */

static void mb_null(void)
{
  FAR volatile uint32_t *p = (FAR volatile uint32_t *)(uintptr_t)g_zero;

  *p = 0x5a5a5a5a;
  g_sink = *p;
}

static void mb_wild(void)
{
  FAR volatile uint32_t *p =
    (FAR volatile uint32_t *)(uintptr_t)(0xdeadbee0u + (unsigned)g_zero);

  g_sink = *p;
}

static void mb_align(void)
{
  static uint8_t buf[16];
  FAR volatile uint32_t *p;

  /* One byte into a buffer: a 32-bit load from an address that is not
   * 4-byte aligned.
   */

  p = (FAR volatile uint32_t *)(FAR void *)(&buf[1] + g_zero);
  g_sink = *p;
}

static void mb_div0(void)
{
  g_sink = (uint32_t)(g_one / g_zero);
}

static void mb_illegal(void)
{
  /* Call into data.  Either the fetch is refused because the region is not
   * executable, or it is fetched and decodes as garbage.  Both are faults
   * the system must survive; which one happens is not this test's business.
   */

  static volatile uint8_t garbage[16] =
  {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
  };

  CODE void (*fn)(void) =
    (CODE void (*)(void))(FAR void *)(&garbage[0] + g_zero);

  fn();
}

static int recurse(int depth)
{
  volatile char pad[256];

  /* Touch the frame so it cannot be optimised away, and recurse without a
   * tail call so the stack really grows.
   */

  pad[0] = (char)depth;
  pad[sizeof(pad) - 1] = (char)depth;

  return pad[0] + recurse(depth + 1) + pad[sizeof(pad) - 1];
}

static void mb_stack(void)
{
  g_sink = (uint32_t)recurse(g_zero);
}

static void mb_abort(void)
{
  abort();
}

static const struct misbehaviour_s g_misbehaviours[] =
{
  {"null",    "write through a NULL pointer",         mb_null},
  {"wild",    "read a wild address (0xdeadbee0)",     mb_wild},
  {"align",   "32-bit load from an unaligned address", mb_align},
  {"div0",    "integer divide by zero",               mb_div0},
  {"illegal", "call into a buffer of garbage",        mb_illegal},
  {"stack",   "overflow the stack by recursion",      mb_stack},
  {"abort",   "call abort()",                         mb_abort},
};

#define NMISBEHAVIOURS \
  ((int)(sizeof(g_misbehaviours) / sizeof(g_misbehaviours[0])))

/****************************************************************************
 * Name: find
 ****************************************************************************/

static FAR const struct misbehaviour_s *find(FAR const char *name)
{
  int i;

  for (i = 0; i < NMISBEHAVIOURS; i++)
    {
      if (strcmp(g_misbehaviours[i].name, name) == 0)
        {
          return &g_misbehaviours[i];
        }
    }

  return NULL;
}

/****************************************************************************
 * Name: canary_loop
 *
 * Description:
 *   An unrelated task that just counts.  If it stops counting while the
 *   offender is being dealt with, the fault took more than the offender --
 *   which is the failure this example exists to catch.
 *
 ****************************************************************************/

static void canary_loop(void)
{
  while (!g_canary_stop)
    {
      g_canary++;
      usleep(10000);
    }
}

#ifdef CONFIG_BUILD_KERNEL
static FAR void *canary_thread(FAR void *arg)
{
  canary_loop();
  return NULL;
}
#else
static int canary_task(int argc, FAR char *argv[])
{
  canary_loop();
  return 0;
}
#endif

/****************************************************************************
 * Name: offend
 *
 * Description:
 *   Run one misbehaviour in the calling task.  Returns only if the operation
 *   was legal on this hardware.
 *
 ****************************************************************************/

static int offend(FAR const struct misbehaviour_s *mb)
{
  printf("misbehave:   %s -- %s\n", mb->name, mb->what);
  fflush(stdout);

  mb->fn();

  printf("misbehave:   completed without faulting\n");
  fflush(stdout);
  return MISBEHAVE_SURVIVED;
}

#ifndef CONFIG_BUILD_KERNEL
static int offender_task(int argc, FAR char *argv[])
{
  FAR const struct misbehaviour_s *mb;

  if (argc < 2 || (mb = find(argv[1])) == NULL)
    {
      return EXIT_FAILURE;
    }

  return offend(mb);
}
#endif

/****************************************************************************
 * Name: run_one
 *
 * Description:
 *   Spawn a task to commit one misbehaviour, wait for it, then check that
 *   this task and the canary both came through.
 *
 * Returned Value:
 *   The number of failed checks (0 is a pass).
 *
 ****************************************************************************/

static int run_one(FAR const struct misbehaviour_s *mb)
{
  unsigned long before;
  unsigned long after;
  pid_t         pid;
  int           status = 0;
  int           ret;
  int           fails = 0;
  bool          completed = false;
#ifdef CONFIG_BUILD_KERNEL
  pthread_t         canary;
  posix_spawnattr_t attr;
  struct sched_param param;
  FAR const char   *spawn_argv[4];
#else
  FAR char *argv[3];
  pid_t     canary;
#endif

  printf("\nmisbehave: === %s ===\n", mb->name);

  g_canary      = 0;
  g_canary_stop = false;

#ifdef CONFIG_BUILD_KERNEL
  /* A kernel build gives every process its own address environment, so the
   * canary has to be a thread to share g_canary with this task.
   */

  if (pthread_create(&canary, NULL, canary_thread, NULL) != 0)
    {
      printf("misbehave: FAIL - could not start the canary thread\n");
      return 1;
    }
#else
  canary = task_create("mb_canary", CANARY_PRIORITY, CANARY_STACKSIZE,
                       canary_task, NULL);
  if (canary < 0)
    {
      printf("misbehave: FAIL - could not start the canary task\n");
      return 1;
    }
#endif

  usleep(100000);
  before = g_canary;

  fflush(stdout);

#ifdef CONFIG_BUILD_KERNEL
  /* The offender must be a separate process, so that its death is the only
   * thing the fault takes with it.  Re-run this program with "do".
   */

  spawn_argv[0] = g_progpath;
  spawn_argv[1] = "do";
  spawn_argv[2] = mb->name;
  spawn_argv[3] = NULL;

  posix_spawnattr_init(&attr);
  param.sched_priority = CONFIG_EXAMPLES_MISBEHAVE_PRIORITY;
  posix_spawnattr_setschedparam(&attr, &param);
  posix_spawnattr_setstacksize(&attr, OFFENDER_STACKSIZE);

  ret = posix_spawn(&pid, g_progpath, NULL, &attr,
                    (FAR char * const *)spawn_argv, NULL);
  if (ret != 0)
    {
      printf("misbehave: FAIL - could not spawn the offender (%d)\n", ret);
      g_canary_stop = true;
      return 1;
    }
#else
  argv[0] = (FAR char *)mb->name;
  argv[1] = NULL;

  pid = task_create("mb_offender", CONFIG_EXAMPLES_MISBEHAVE_PRIORITY,
                    OFFENDER_STACKSIZE, offender_task, argv);
  if (pid < 0)
    {
      printf("misbehave: FAIL - could not start the offending task\n");
      g_canary_stop = true;
      return 1;
    }
#endif

  /* Wait for the offender to be reaped.  If the system contains the fault,
   * this returns.  If it panics or resets, nothing below ever prints -- and
   * that missing output is the result.
   */

#ifdef CONFIG_SCHED_WAITPID
  ret = waitpid(pid, &status, 0);
  if (ret < 0)
    {
      printf("misbehave:   waitpid() returned %d (already reaped)\n", ret);
    }
  else if (WIFEXITED(status) && WEXITSTATUS(status) == MISBEHAVE_SURVIVED)
    {
      completed = true;
    }
#else
  for (ret = 0; ret < 100; ret++)
    {
      if (kill(pid, 0) < 0)
        {
          break;
        }

      usleep(50000);
    }
#endif

  usleep(200000);
  after = g_canary;
  g_canary_stop = true;

  /* The two checks that matter. */

  if (kill(pid, 0) == 0)
    {
      printf("misbehave:   FAIL - the offender is still alive\n");
      fails++;
    }

  printf("misbehave:   PASS - this task survived\n");

  if (after > before)
    {
      printf("misbehave:   PASS - unrelated task kept running (%lu -> %lu)\n",
             before, after);
    }
  else
    {
      printf("misbehave:   FAIL - unrelated task stopped (%lu -> %lu)\n",
             before, after);
      fails++;
    }

  if (completed)
    {
      printf("misbehave:   NOTE - the operation was legal here; it did not "
             "fault\n");
    }
  else
    {
      printf("misbehave:   contained (status %d)\n", status);
    }

  usleep(100000);
  return fails;
}

/****************************************************************************
 * Name: usage
 ****************************************************************************/

static void usage(void)
{
  int i;

  printf("Usage: misbehave [-l] [do] [name]\n"
         "  (no args)   run every misbehaviour in turn\n"
         "  <name>      run just one\n"
         "  do <name>   misbehave in *this* task, for a debugger\n"
         "  -l          list them\n\n");

  for (i = 0; i < NMISBEHAVIOURS; i++)
    {
      printf("  %-8s %s\n", g_misbehaviours[i].name,
             g_misbehaviours[i].what);
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  FAR const struct misbehaviour_s *mb;
  int fails = 0;
  int i;

#ifdef CONFIG_BUILD_KERNEL
  if (argc > 0 && argv[0] != NULL)
    {
      g_progpath = argv[0];
    }
#endif

  if (argc > 1 && strcmp(argv[1], "-h") == 0)
    {
      usage();
      return EXIT_SUCCESS;
    }

  if (argc > 1 && strcmp(argv[1], "-l") == 0)
    {
      usage();
      return EXIT_SUCCESS;
    }

  /* One-shot form:  misbehave in this very task, deliberately. */

  if (argc > 2 && strcmp(argv[1], "do") == 0)
    {
      mb = find(argv[2]);
      if (mb == NULL)
        {
          printf("misbehave: no such misbehaviour '%s'\n", argv[2]);
          return EXIT_FAILURE;
        }

      return offend(mb);
    }

  if (argc > 1)
    {
      mb = find(argv[1]);
      if (mb == NULL)
        {
          printf("misbehave: no such misbehaviour '%s'\n", argv[1]);
          usage();
          return EXIT_FAILURE;
        }

      fails = run_one(mb);
    }
  else
    {
      for (i = 0; i < NMISBEHAVIOURS; i++)
        {
          fails += run_one(&g_misbehaviours[i]);
        }
    }

  printf("\n");
  if (fails == 0)
    {
      printf("misbehave: SURVIVED - the system contained every "
             "misbehaviour\n");
      return EXIT_SUCCESS;
    }

  printf("misbehave: NOT CONTAINED - %d check(s) failed\n", fails);
  return EXIT_FAILURE;
}
