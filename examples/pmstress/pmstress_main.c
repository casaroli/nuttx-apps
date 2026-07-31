/****************************************************************************
 * apps/examples/pmstress/pmstress_main.c
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
 *
 * Walks the power management states in a fixed, self-timed sequence so that
 * a supply with current logging can be left to record the whole run with no
 * debugger, no console and no host attached.
 *
 * The output is a staircase.  Each step is one power state held for a known
 * number of seconds, and the steps are separated by a short burst of
 * full-speed execution that shows up as an unmistakable spike.  The spikes
 * make the trace self-describing: the operator does not have to know when
 * the run started to work out which plateau is which.
 *
 * The last step is the deepest state and is never left, because in that
 * state nothing on the board can generate the event needed to leave it.
 * The run therefore ends by staying put, and the final plateau is the
 * measurement of interest.
 *
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/boardctl.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <nuttx/power/pm.h>
#include <nuttx/leds/userled.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define MARKER_MS      1000    /* Length of the spike between steps */
#define PM_DOMAIN      0       /* PM_IDLE_DOMAIN */

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct pmstress_step_s
{
  FAR const char *name;
  int             state;    /* State to pin the domain at, -1 to release */
  int             seconds;  /* How long to hold it, 0 to hold forever */
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* The staircase.  Deepest state last, and held indefinitely: once the chip
 * is dormant there is nothing left on the board to wake it.
 */

static const struct pmstress_step_s g_steps[] =
{
  {
    "active  (full speed, busy)", PM_NORMAL,
    CONFIG_EXAMPLES_PMSTRESS_STEP_SECS
  },
  {
    "idle    (full speed, wfi)", PM_NORMAL,
    CONFIG_EXAMPLES_PMSTRESS_STEP_SECS
  },
  {
    "standby (clocks gated)", PM_STANDBY,
    CONFIG_EXAMPLES_PMSTRESS_STEP_SECS
  },
  {
    "sleep   (dormant, terminal)", -1, 0
  },
};

/* Which state, if any, this program is currently holding the domain at. */

static int g_held = -1;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: pmstress_control
 *
 * Description:
 *   Issue one power management control action against the idle domain.
 *
 ****************************************************************************/

static int pmstress_control(int action, int state)
{
  struct boardioc_pm_ctrl_s ctrl;

  memset(&ctrl, 0, sizeof(ctrl));
  ctrl.action = action;
  ctrl.domain = PM_DOMAIN;
  ctrl.state  = state;

  return boardctl(BOARDIOC_PM_CONTROL, (uintptr_t)&ctrl);
}

/****************************************************************************
 * Name: pmstress_hold
 *
 * Description:
 *   Pin the idle domain at a state, releasing any previous hold.  The greedy
 *   governor selects the shallowest state that carries a wakelock, so a
 *   single hold is enough to stop it descending past that point.  Passing -1
 *   releases the hold and lets it go all the way down.
 *
 ****************************************************************************/

static void pmstress_hold(int state)
{
  if (g_held >= 0)
    {
      pmstress_control(BOARDIOC_PM_RELAX, g_held);
      g_held = -1;
    }

  if (state >= 0)
    {
      if (pmstress_control(BOARDIOC_PM_STAY, state) == OK)
        {
          g_held = state;
        }
      else
        {
          printf("pmstress: failed to hold state %d: %d\n", state, errno);
        }
    }
}

/****************************************************************************
 * Name: pmstress_marker
 *
 * Description:
 *   Burn a fixed amount of time at full speed.  This is what separates the
 *   steps in the current trace, so it deliberately keeps the CPU out of any
 *   idle state: it reports activity, holds the domain at PM_NORMAL and then
 *   spins rather than sleeping.
 *
 ****************************************************************************/

static void pmstress_marker(void)
{
  struct timespec start;
  struct timespec now;
  volatile uint32_t sink = 0;
  long elapsed;

  pmstress_hold(PM_NORMAL);

  clock_gettime(CLOCK_MONOTONIC, &start);

  do
    {
      /* Keep the core busy.  The compiler is not allowed to discard this
       * because the accumulator is volatile.
       */

      for (int i = 0; i < 10000; i++)
        {
          sink = sink + i;
        }

      pmstress_control(BOARDIOC_PM_ACTIVITY, 0);

      clock_gettime(CLOCK_MONOTONIC, &now);
      elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                (now.tv_nsec - start.tv_nsec) / 1000000;
    }
  while (elapsed < MARKER_MS);
}

/****************************************************************************
 * Name: pmstress_leds_off
 *
 * Description:
 *   Drive every user LED low.  An indicator LED draws milliamps, which
 *   swamps a sleep current measured in microamps, and leaving the pin as a
 *   floating input is not an alternative: an undriven pad settles at an
 *   indeterminate level and can light the LED part way or leak.
 *
 ****************************************************************************/

static void pmstress_leds_off(bool verbose)
{
#ifdef CONFIG_USERLED_LOWER
  userled_set_t ledset = 0;
  int fd;

  fd = open(CONFIG_EXAMPLES_PMSTRESS_LEDPATH, O_WRONLY);
  if (fd < 0)
    {
      if (verbose)
        {
          printf("pmstress: no %s, LEDs left as they are: %d\n",
                 CONFIG_EXAMPLES_PMSTRESS_LEDPATH, errno);
        }

      return;
    }

  if (ioctl(fd, ULEDIOC_SETALL, (unsigned long)ledset) < 0)
    {
      if (verbose)
        {
          printf("pmstress: could not clear the LEDs: %d\n", errno);
        }
    }
  else if (verbose)
    {
      printf("pmstress: LEDs driven off\n");
    }

  close(fd);
#else
  if (verbose)
    {
      printf("pmstress: no user LED driver, check the LED is not lit\n");
    }
#endif
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/* Bring-up hook for the POWMAN suspend-to-RAM path.  Declared locally
 * rather than pulled in from an arch header, because this is a test
 * vehicle and applications have no business including those.
 */

extern int rp23xx_pm_suspend(uint32_t wake_ms);
extern uint32_t rp23xx_pm_wake_source(void);

/****************************************************************************
 * Name: pmstress_suspend
 *
 * Description:
 *   Drop into the deepest state the chip has and come back on the timed
 *   wake.  Kept separate from the staircase so it can be iterated on
 *   quickly, and always armed with a timer so a failure to wake on
 *   anything else still returns the board.
 *
 ****************************************************************************/

static int pmstress_suspend(int seconds)
{
  int ret;

  pmstress_leds_off(true);

  printf("pmstress: suspending to RAM for %d s\n", seconds);
  printf("pmstress: peripherals come back reset; expect the console to be\n"
         "          unreliable until the system is reinitialised\n\n");
  fflush(stdout);

  /* Let the console drain: the UART loses its registers on the way down
   * and anything still queued would be lost mid-character.
   */

  sleep(2);

  ret = rp23xx_pm_suspend((uint32_t)seconds * 1000);

  printf("\npmstress: back, rp23xx_pm_suspend() returned %d, "
         "wake source 0x%08lx\n", ret,
         (unsigned long)rp23xx_pm_wake_source());
  fflush(stdout);

  return ret;
}

int main(int argc, FAR char *argv[])
{
  int total;
  int i;

  if (argc > 1 && strcmp(argv[1], "suspend") == 0)
    {
      int seconds = argc > 2 ? atoi(argv[2]) : 10;
      return pmstress_suspend(seconds);
    }

  printf("\npmstress: power management current staircase\n\n");

  pmstress_leds_off(true);

  /* Describe the whole run before starting, because by the time it matters
   * the console will be unplugged.
   */

  total = 0;
  printf("pmstress: schedule, %d ms full-speed spike between each step\n",
         MARKER_MS);

  for (i = 0; i < (int)(sizeof(g_steps) / sizeof(g_steps[0])); i++)
    {
      if (g_steps[i].seconds > 0)
        {
          total += g_steps[i].seconds + (MARKER_MS / 1000);
          printf("  t+%4ds  %s, %ds\n", total - g_steps[i].seconds,
                 g_steps[i].name, g_steps[i].seconds);
        }
      else
        {
          total += MARKER_MS / 1000;
          printf("  t+%4ds  %s, until power off\n", total,
                 g_steps[i].name);
        }
    }

  printf("\npmstress: starting in %d seconds, disconnect now\n\n",
         CONFIG_EXAMPLES_PMSTRESS_DISCONNECT_SECS);
  fflush(stdout);

  /* Hold the domain awake across the wait.  Releasing it here would let the
   * governor take the chip into its deepest state, and that state stops the
   * system clock, so this sleep would never expire and the run would never
   * begin.
   */

  pmstress_hold(PM_NORMAL);
  sleep(CONFIG_EXAMPLES_PMSTRESS_DISCONNECT_SECS);

  for (i = 0; i < (int)(sizeof(g_steps) / sizeof(g_steps[0])); i++)
    {
      pmstress_marker();

      pmstress_hold(g_steps[i].state);

      /* The board LED callback relights the LED whenever the domain passes
       * back through PM_NORMAL, which the marker above forces it to do.
       * Clear it again now that the state for this step has been selected,
       * so the plateau being measured is not carrying a few milliamps of
       * indicator current.
       */

      pmstress_leds_off(false);

      if (g_steps[i].seconds > 0)
        {
          if (i == 0)
            {
              /* The first step is the active reference: stay busy rather
               * than sleeping, so it records the running current.
               */

              struct timespec start;
              struct timespec now;
              volatile uint32_t sink = 0;

              clock_gettime(CLOCK_MONOTONIC, &start);
              do
                {
                  for (int j = 0; j < 10000; j++)
                    {
                      sink = sink + j;
                    }

                  pmstress_control(BOARDIOC_PM_ACTIVITY, 0);
                  clock_gettime(CLOCK_MONOTONIC, &now);
                }
              while (now.tv_sec - start.tv_sec < g_steps[i].seconds);
            }
          else
            {
              sleep(g_steps[i].seconds);
            }
        }
      else
        {
          /* Terminal step.  Sleeping forever keeps this task off the run
           * queue so the idle loop can take the chip all the way down.  The
           * system clock stops in the deepest state, so this never returns
           * and that is the intent.
           */

          for (; ; )
            {
              sleep(3600);
            }
        }
    }

  return 0;
}
