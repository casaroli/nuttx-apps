/****************************************************************************
 * apps/examples/sandbox/sandbox_main.c
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

#include <sys/types.h>
#include <sys/wait.h>

#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CONFIG_BUILD_KERNEL
#  include <pthread.h>
#  include <spawn.h>
#endif

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Where to poke.
 *
 * The point of this test is to be architecture-neutral, so the address is
 * derived rather than hard-coded.  In every BUILD_PROTECTED configuration in
 * the tree the kernel blob is placed *below* the user blob, and the boundary
 * between them is exactly CONFIG_NUTTX_USERSPACE:
 *
 *   qemu-armv7a:pnsh       0x00200000     mps2-an521:knsh     0x10200000
 *   qemu-armv8a:pnsh       0x41000000     pimoroni-pico-2-plus:pnsh
 *   rv-virt:pnsh[64]       0x80040000                         0x10100000
 *
 * so the word just below it belongs to the kernel in all of them.  Whether
 * that address holds kernel code, kernel data, or nothing mapped at all does
 * not matter:  either way an unprivileged task must not be able to read it.
 *
 * A BUILD_KERNEL configuration has no such boundary and no
 * CONFIG_NUTTX_USERSPACE:  every process gets its own address environment
 * and the kernel is simply never mapped into it.  CONFIG_RAM_START, where
 * the kernel image itself is loaded, serves the same purpose there.
 *
 * A BUILD_FLAT configuration has neither, and the test reports that there
 * is nothing to contain rather than pretending to pass.
 */

#if defined(CONFIG_BUILD_KERNEL) && defined(CONFIG_RAM_START)
#  define SANDBOX_HAVE_TARGET   1
#  define SANDBOX_TARGET        ((uintptr_t)CONFIG_RAM_START)
#  define SANDBOX_ORIGIN_NAME   "CONFIG_RAM_START"
#  define SANDBOX_ORIGIN_VALUE  ((uintptr_t)CONFIG_RAM_START)
#elif defined(CONFIG_NUTTX_USERSPACE)
#  define SANDBOX_HAVE_TARGET   1
#  define SANDBOX_TARGET        ((uintptr_t)CONFIG_NUTTX_USERSPACE - 16)
#  define SANDBOX_ORIGIN_NAME   "CONFIG_NUTTX_USERSPACE"
#  define SANDBOX_ORIGIN_VALUE  ((uintptr_t)CONFIG_NUTTX_USERSPACE)
#else
#  define SANDBOX_HAVE_TARGET   0
#  define SANDBOX_TARGET        ((uintptr_t)0)
#endif

#define CANARY_PRIORITY         (CONFIG_EXAMPLES_SANDBOX_PRIORITY - 1)
#define CANARY_STACKSIZE        2048
#define ESCAPE_STACKSIZE        CONFIG_EXAMPLES_SANDBOX_STACKSIZE

/* How to touch it.  A read and a write are both data accesses and are
 * refused by the same fault; an instruction fetch is refused by a different
 * one (a prefetch abort on ARM, an instruction access fault on risc-v).
 * That is a different exception vector and, historically, a separately
 * broken one, so both are worth asking about.
 */

#define SANDBOX_READ            0
#define SANDBOX_WRITE           1
#define SANDBOX_EXEC            2

/* Exit status the offender uses to say "I survived the access".  It has to
 * be the *survival* that is marked, not the death:  a task killed by the
 * fault exits with whatever its architecture's recovery leaves behind, and
 * that is not uniform.  Where the recovery redirects to _exit(SIGSEGV) the
 * status is 2816; where it raises SIGSEGV and lets the default action run,
 * sig_default.c calls _exit(EXIT_FAILURE) and it is 256.  Only the offender
 * itself can say it got through, and if it is killed it says nothing.
 */

#define SANDBOX_ESCAPED         42

/* Exit status for "the access was refused, but silently".  Some hardware does
 * not trap a denied access at all:  the ESP32-S3 TRM v1.8 p.699 says an
 * access without permission is "responded with 0 (for internal memory) or
 * 0xdeadbeaf (for external memory)".  There the load completes, escape()
 * returns, and a single read cannot tell a refusal from memory that happens
 * to hold that value.  Reading two addresses whose real contents differ
 * settles it:  if both come back identical, what came back is the bus's
 * substitute and not the memory.
 */

#define SANDBOX_REFUSED         43

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* Bumped continuously by the canary task.  It is the evidence that the rest
 * of the system kept running while the offender was being killed:  a system
 * that panicked or reset stops printing entirely, and one that merely wedged
 * leaves this stuck.
 */

static volatile unsigned long g_canary;
static volatile bool          g_canary_stop;

#ifdef CONFIG_BUILD_KERNEL
/* Path this program was invoked with, so the offender can be spawned from
 * the same file.
 */

static FAR const char *g_progpath = "sandbox";
#endif

/****************************************************************************
 * Private Functions
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
 * Name: escape
 *
 * Description:
 *   Make the access that must not be allowed.  This runs in whatever task
 *   calls it, and in a correctly isolated build it does not return.
 *
 ****************************************************************************/

static FAR const char *modename(int mode)
{
  switch (mode)
    {
      case SANDBOX_WRITE:
        return "WRITE";

      case SANDBOX_EXEC:
        return "call";

      default:
        return "read";
    }
}

static int escape(uintptr_t addr, int mode, uintptr_t addr2)
{
  FAR volatile uint32_t *p = (FAR volatile uint32_t *)addr;

  printf("sandbox:   attempting %s of %p\n", modename(mode),
         (FAR void *)addr);
  fflush(stdout);

  if (mode == SANDBOX_WRITE)
    {
      /* A write is the more dangerous direction and is not the default:  if
       * the hardware does *not* contain it, this corrupts whatever it lands
       * on.  It is offered because a read-only mapping would let a read
       * through while still refusing the write.
       */

      *p = 0xdeadbeef;
    }
  else if (mode == SANDBOX_EXEC)
    {
      /* Branching into kernel memory is refused by the instruction fetch
       * rather than by a data access, so it arrives at a different exception
       * vector.  Whether the target holds anything that would decode as an
       * instruction is beside the point:  an unprivileged task must not get
       * that far.
       */

      void (*fn)(void) = (CODE void (*)(void))addr;

      fn();
    }
  else
    {
      uint32_t v = *p;

      /* Getting here means the load did not trap.  On hardware that denies
       * silently that is not evidence either way, so if a second address was
       * given, compare.  Identical values from two addresses whose real
       * contents differ means neither read reached memory.
       */

      if (addr2 != 0)
        {
          FAR volatile uint32_t *q = (FAR volatile uint32_t *)addr2;
          uint32_t w = *q;

          if (v == w)
            {
              printf("sandbox:   REFUSED -- %p and %p both read %08lx,\n"
                     "sandbox:   so that is the bus substitute, not memory\n",
                     (FAR void *)addr, (FAR void *)addr2,
                     (unsigned long)v);
              fflush(stdout);
              return SANDBOX_REFUSED;
            }

          printf("sandbox:   NOT CONTAINED -- read %08lx and %08lx\n",
                 (unsigned long)v, (unsigned long)w);
          fflush(stdout);
          return SANDBOX_ESCAPED;
        }

      printf("sandbox:   NOT CONTAINED -- read %08lx\n", (unsigned long)v);
      fflush(stdout);
      return SANDBOX_ESCAPED;
    }

  printf("sandbox:   NOT CONTAINED -- the access completed\n");
  fflush(stdout);
  return SANDBOX_ESCAPED;
}

static int mode_of(FAR const char *arg)
{
  switch (arg[0])
    {
      case 'w':
        return SANDBOX_WRITE;

      case 'x':
        return SANDBOX_EXEC;

      default:
        return SANDBOX_READ;
    }
}

#ifndef CONFIG_BUILD_KERNEL
static int escape_task(int argc, FAR char *argv[])
{
  int       mode  = (argc > 1) ? mode_of(argv[1]) : SANDBOX_READ;
  uintptr_t addr  = SANDBOX_TARGET;
  uintptr_t addr2 = 0;

  if (argc > 2)
    {
      addr = (uintptr_t)strtoul(argv[2], NULL, 0);
    }

  if (argc > 3)
    {
      addr2 = (uintptr_t)strtoul(argv[3], NULL, 0);
    }

  /* Reaching the return means the access was not contained; escape() says
   * whether it was allowed outright or refused without trapping.
   */

  return escape(addr, mode, addr2);
}
#endif

/****************************************************************************
 * Name: selfcheck
 *
 * Description:
 *   Spawn the offender as a separate task and watch what happens to it, and
 *   to everything else.  Three things have to be true for a pass:  the
 *   offending task must die, this task must still be running afterwards, and
 *   the canary must still be advancing.
 *
 ****************************************************************************/

static int selfcheck(int mode, uintptr_t addr, uintptr_t addr2)
{
  char      addrbuf[24];
  char      addr2buf[24];
  char      modebuf[2];
  unsigned long before;
  unsigned long after;
  pid_t     pid;
  int       status = 0;
  int       ret;
  int       fails = 0;
#ifdef CONFIG_BUILD_KERNEL
  pthread_t canary;
  posix_spawnattr_t attr;
  struct sched_param param;
  FAR const char *spawn_argv[6];
#else
  FAR char *argv[4];
  pid_t     canary;
#endif

  printf("sandbox: target %p (%s)\n", (FAR void *)addr, modename(mode));
#if SANDBOX_HAVE_TARGET
  printf("sandbox: derived from %s = %p\n", SANDBOX_ORIGIN_NAME,
         (FAR void *)SANDBOX_ORIGIN_VALUE);
#endif

  /* Start the canary before anything else, so it is already running when the
   * offender faults.
   */

  g_canary      = 0;
  g_canary_stop = false;

#ifdef CONFIG_BUILD_KERNEL
  /* A kernel build gives every process its own address environment, so the
   * canary has to be a thread to share g_canary with this task.
   */

  if (pthread_create(&canary, NULL, canary_thread, NULL) != 0)
    {
      printf("sandbox: FAIL - could not start the canary thread\n");
      return 1;
    }
#else
  canary = task_create("sandbox_canary", CANARY_PRIORITY, CANARY_STACKSIZE,
                       canary_task, NULL);
  if (canary < 0)
    {
      printf("sandbox: FAIL - could not start the canary task\n");
      return 1;
    }
#endif

  usleep(100000);
  before = g_canary;

  snprintf(addrbuf, sizeof(addrbuf), "0x%lx", (unsigned long)addr);
  snprintf(addr2buf, sizeof(addr2buf), "0x%lx", (unsigned long)addr2);
  modebuf[0] = mode == SANDBOX_WRITE ? 'w' :
               mode == SANDBOX_EXEC  ? 'x' : 'r';
  modebuf[1] = '\0';
#ifndef CONFIG_BUILD_KERNEL
  argv[0] = modebuf;
  argv[1] = addrbuf;
  argv[2] = addr2 != 0 ? addr2buf : NULL;
  argv[3] = NULL;
#endif

  printf("sandbox: starting the offending task\n");
  fflush(stdout);

#ifdef CONFIG_BUILD_KERNEL
  /* The offender must be a separate process, so that its death is the only
   * thing the fault takes with it.  Re-run this program with "escape".
   */

  spawn_argv[0] = g_progpath;
  spawn_argv[1] = "escape";
  spawn_argv[2] = modebuf;
  spawn_argv[3] = addrbuf;
  spawn_argv[4] = addr2 != 0 ? addr2buf : NULL;
  spawn_argv[5] = NULL;

  posix_spawnattr_init(&attr);
  param.sched_priority = CONFIG_EXAMPLES_SANDBOX_PRIORITY;
  posix_spawnattr_setschedparam(&attr, &param);
  posix_spawnattr_setstacksize(&attr, ESCAPE_STACKSIZE);

  ret = posix_spawn(&pid, g_progpath, NULL, &attr,
                    (FAR char * const *)spawn_argv, NULL);
  if (ret != 0)
    {
      printf("sandbox: FAIL - could not spawn the offender (%d)\n", ret);
      g_canary_stop = true;
      return 1;
    }
#else
  pid = task_create("sandbox_escape", CONFIG_EXAMPLES_SANDBOX_PRIORITY,
                    ESCAPE_STACKSIZE, escape_task, argv);
  if (pid < 0)
    {
      printf("sandbox: FAIL - could not start the offending task\n");
      g_canary_stop = true;
      return 1;
    }
#endif

  /* Wait for the offender to be reaped.  If the system contains the fault by
   * killing just that task, this returns.  If it panics or resets, nothing
   * below ever prints -- which is itself the result, visible on the console.
   */

#ifdef CONFIG_SCHED_WAITPID
  ret = waitpid(pid, &status, 0);
  if (ret < 0)
    {
      /* ECHILD here means the task was already reaped, which is still
       * containment -- it died and the system moved on.
       */

      printf("sandbox: waitpid() returned %d (task already reaped)\n", ret);
    }
  else
    {
      printf("sandbox: offender reaped, status %d\n", status);
    }
#else
  /* No waitpid:  poll until the pid is gone. */

  for (ret = 0; ret < 100; ret++)
    {
      if (kill(pid, 0) < 0)
        {
          break;
        }

      usleep(50000);
    }

  printf("sandbox: offender gone after %d polls\n", ret);
#endif

  usleep(200000);
  after = g_canary;
  g_canary_stop = true;

  /* Now the things that make this a pass. */

  printf("\n");
  printf("sandbox: --- results ---\n");

#ifdef CONFIG_SCHED_WAITPID
  /* Dying is not enough:  the offender has to have died *of the fault*.
   * Every architecture's recovery redirects it to _exit(SIGSEGV), so that
   * status is the signature.  Any other one means escape() returned and
   * the access was allowed -- a containment failure however tidily the
   * system carried on afterwards.
   */

  if (ret >= 0 && WIFEXITED(status) &&
      WEXITSTATUS(status) == SANDBOX_ESCAPED)
    {
      printf("sandbox: FAIL - the access was allowed; the offender ran to\n"
             "sandbox:        completion and reported it (status %d)\n",
             status);
      fails++;
    }
  else if (ret >= 0 && WIFEXITED(status) &&
           WEXITSTATUS(status) == SANDBOX_REFUSED)
    {
      /* Refused, but without trapping.  The offender proved it by reading
       * two addresses and getting one answer.  Containment holds; there was
       * simply no fault for the kernel to recover from.
       */

      printf("sandbox: PASS - the access was refused (silently; no trap)\n");
    }
#endif

  if (kill(pid, 0) == 0)
    {
      printf("sandbox: FAIL - the offending task is still alive\n");
      fails++;
    }
  else
    {
      printf("sandbox: PASS - the offending task was terminated\n");
    }

  printf("sandbox: PASS - this task survived and is still running\n");

  if (after > before)
    {
      printf("sandbox: PASS - unrelated task kept running (%lu -> %lu)\n",
             before, after);
    }
  else
    {
      printf("sandbox: FAIL - unrelated task stopped (%lu -> %lu)\n",
             before, after);
      fails++;
    }

  usleep(100000);

  printf("\n");
  if (fails == 0)
    {
      printf("sandbox: CONTAINED - the sandbox held\n");
    }
  else
    {
      printf("sandbox: NOT CONTAINED - %d check(s) failed\n", fails);
    }

#ifdef CONFIG_BUILD_KERNEL
  pthread_join(canary, NULL);
#endif

  return fails;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

static void usage(void)
{
  printf("Usage: sandbox [escape] [r|w|x] [addr] [addr2]\n"
         "  (no args)           spawn an offending task and check it is\n"
         "                      contained while everything else survives\n"
         "  escape [r|w|x] [a]  make the bad access in *this* task; in a\n"
         "                      contained build this task does not return\n"
         "  r read (default), w write, x call the address\n"
         "  addr2  a second kernel address, for read only, whose real\n"
         "         contents differ from addr's.  Needed on hardware that\n"
         "         refuses an access without trapping: two reads that come\n"
         "         back identical did not reach memory.\n");
}

int main(int argc, FAR char *argv[])
{
  int       mode = SANDBOX_READ;
  uintptr_t addr  = SANDBOX_TARGET;
  uintptr_t addr2 = 0;
  int       argbase = 1;

#ifdef CONFIG_BUILD_KERNEL
  if (argc > 0 && argv[0] != NULL)
    {
      g_progpath = argv[0];
    }
#endif

  if (argc > 1 && strcmp(argv[1], "-h") == 0)
    {
      usage();
      return 0;
    }

#if !SANDBOX_HAVE_TARGET
#  ifdef CONFIG_BUILD_KERNEL
  printf("sandbox: this kernel build does not set CONFIG_RAM_START, so\n"
         "sandbox: no target can be derived.  Pass an address in kernel\n"
         "sandbox: memory on the command line instead.\n");
#  else
  printf("sandbox: this is a flat build -- there is no kernel/user\n"
         "sandbox: boundary to escape from, so there is nothing to\n"
         "sandbox: contain.  Build a protected or kernel configuration\n"
         "sandbox: to run this test.\n");
#  endif
  if (argc <= 1)
    {
      return 0;
    }
#endif

  if (argc > 1 && strcmp(argv[1], "escape") == 0)
    {
      argbase = 2;
    }

  if (argc > argbase && argv[argbase][1] == '\0' &&
      (argv[argbase][0] == 'r' || argv[argbase][0] == 'w' ||
       argv[argbase][0] == 'x'))
    {
      mode = mode_of(argv[argbase]);
      argbase++;
    }

  if (argc > argbase)
    {
      addr = (uintptr_t)strtoul(argv[argbase], NULL, 0);
      argbase++;
    }

  if (argc > argbase)
    {
      addr2 = (uintptr_t)strtoul(argv[argbase], NULL, 0);
    }

  if (argc > 1 && strcmp(argv[1], "escape") == 0)
    {
      /* One-shot mode:  fault in this task, deliberately. */

      printf("sandbox: escaping from this task -- expect it to die\n");
      return escape(addr, mode, addr2);
    }

  return selfcheck(mode, addr, addr2);
}
