/****************************************************************************
 * apps/examples/battery/batt_main.c
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
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <nuttx/debug.h>

#include <nuttx/power/battery_ioctl.h>
#include <nuttx/power/battery_charger.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Configuration ************************************************************/

#ifndef CONFIG_EXAMPLES_BATTERY_DEVNAME
#  define CONFIG_EXAMPLES_BATTERT_DEVNAME "/dev/batt0"
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * status_report
 ****************************************************************************/

void status_report(int status)
{
  switch (status)
    {
      case BATTERY_UNKNOWN:
        {
          printf("Battery state is not known!\n");
        }
        break;

      case BATTERY_FAULT:
        {
          printf("Charger fault, look at the health info!\n");
        }
        break;

      case BATTERY_IDLE:
        {
          printf("Battery is idle, not full, not charging, "
                 "not discharging!\n");
        }
        break;

      case BATTERY_FULL:
        {
          printf("Battery fully charged, not discharging!\n");
        }
        break;

      case BATTERY_CHARGING:
        {
          printf("Battery is charging, not full yet!\n");
        }
        break;

      case BATTERY_DISCHARGING:
        {
          printf("Battery discharging!\n");
        }
        break;

      default:
        printf("ERROR: the value %d is not a defined status!\n", status);
        break;
    }
}

/****************************************************************************
 * health_report
 ****************************************************************************/

void health_report(int health)
{
  switch (health)
    {
      case BATTERY_HEALTH_UNKNOWN:
        {
          printf("Battery health is not known!\n");
        }
        break;

      case BATTERY_HEALTH_GOOD:
        {
          printf("Battery is in good condition!\n");
        }
        break;

      case BATTERY_HEALTH_DEAD:
        {
          printf("Battery is dead, nothing we can do!\n");
        }
        break;

      case BATTERY_HEALTH_OVERHEAT:
        {
          printf("Battery is over recommended temperature!\n");
        }
        break;

      case BATTERY_HEALTH_OVERVOLTAGE:
        {
          printf("Battery voltage is over recommended level!\n");
        }
        break;

      case BATTERY_HEALTH_UNSPEC_FAIL:
        {
          printf("Battery charger reported an unspected failure!\n");
        }
        break;

      case BATTERY_HEALTH_COLD:
        {
          printf("Battery is under recommended temperature!\n");
        }
        break;

      case BATTERY_HEALTH_WD_TMR_EXP:
        {
          printf("Battery WatchDog Timer Expired!\n");
        }
        break;

      case BATTERY_HEALTH_SAFE_TMR_EXP:
        {
          printf("Battery Safety Timer Expired!\n");
        }
        break;

      case BATTERY_HEALTH_DISCONNECTED:
        {
          printf("Battery is not connected!\n");
        }
        break;

      default:
        printf("ERROR: the value %d is not a defined health!\n", health);
        break;
    }
}

/****************************************************************************
 * batt_main
 ****************************************************************************/

/****************************************************************************
 * Name: batt_optional
 *
 * Description:
 *   Perform an ioctl that not every battery driver implements.
 *
 *   The two battery classes answer different subsets: a charger has health
 *   and an input current limit, a gauge has capacity and a chip id, and the
 *   upper half returns ENOTTY for whatever its lower half left out.  Treating
 *   that as fatal would mean this example only ever worked against one of
 *   them, so an unimplemented request is reported and stepped over while a
 *   real failure still stops the run.
 *
 * Returned Value:
 *   1 if the value was read, 0 if the driver does not implement it, and a
 *   negative value on a real error.
 *
 ****************************************************************************/

static int batt_optional(int fd, int cmd, FAR void *arg, FAR const char *name)
{
  if (ioctl(fd, cmd, (unsigned long)((uintptr_t)arg)) >= 0)
    {
      return 1;
    }

  if (errno == ENOTTY || errno == ENOSYS)
    {
      printf("%s: not supported by this driver\n", name);
      return 0;
    }

  if (errno == ENODEV)
    {
      /* A gauge that can reach its hardware but has no cell in it.  Distinct
       * from "not supported", and the distinction is the point: it is the
       * difference between a board with no battery and a battery at zero.
       */

      printf("%s: no battery\n", name);
      return 0;
    }

  fprintf(stderr, "ERROR: %s failed: %d\n", name, errno);
  return -errno;
}

/****************************************************************************
 * batt_main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  unsigned int chipid;
  int capacity;
  int voltage;
  int current;
  int i;
  int fd;
  int ret;
  int status;
  int health;

  /* Open the battery charger device */

  fd = open(CONFIG_EXAMPLES_BATTERY_DEVNAME, O_RDONLY);
  if (fd < 0)
    {
      fprintf(stderr, "ERROR: Failed to open %s: %d\n",
              CONFIG_EXAMPLES_BATTERY_DEVNAME, errno);
      return EXIT_FAILURE;
    }

  printf("Going to read battery info, updated each two seconds.\n");
  printf("Try to remove the board power supply, etc, "
         "to change its status.\n");

  /* Wait the user read the information message above */

  sleep(5);

  if (batt_optional(fd, BATIOC_CHIPID, &chipid, "CHIPID") > 0)
    {
      printf("CHIPID: %u\n", chipid);
    }

  for (i = 0; i < 10; i++)
    {
      printf("\n----------------------------"
             "-------------------------------\n");

      /* Read battery status */

      ret = ioctl(fd, BATIOC_STATE, (unsigned long)((uintptr_t) &status));
      if (ret < 0)
        {
          fprintf(stderr, "ERROR: ioctl(BATIOC_STATE) failed: %d\n", errno);
          goto errout_with_fd;
        }

      /* Show status */

      printf("STATUS: ");

      status_report(status);

      /* The rest are optional: which of them answer depends on whether this
       * is a charger or a gauge, and on what its lower half implements.
       */

      ret = batt_optional(fd, BATIOC_HEALTH, &health, "HEALTH");
      if (ret < 0)
        {
          goto errout_with_fd;
        }
      else if (ret > 0)
        {
          printf("HEALTH: ");
          health_report(health);
        }

      ret = batt_optional(fd, BATIOC_CAPACITY, &capacity, "CAPACITY");
      if (ret < 0)
        {
          goto errout_with_fd;
        }
      else if (ret > 0)
        {
          printf("CAPACITY: %d%%\n", capacity);
        }

      ret = batt_optional(fd, BATIOC_VOLTAGE, &voltage, "VOLTAGE");
      if (ret < 0)
        {
          goto errout_with_fd;
        }
      else if (ret > 0)
        {
          printf("VOLTAGE: %d mV\n", voltage);
        }

      ret = batt_optional(fd, BATIOC_CURRENT, &current, "CURRENT");
      if (ret < 0)
        {
          goto errout_with_fd;
        }
      else if (ret > 0)
        {
          printf("CURRENT: %d mA\n", current);
        }

      /* Wait one second before reading again */

      sleep(2);
    }

  ret = OK;

errout_with_fd:
  close(fd);
  return ret;
}
