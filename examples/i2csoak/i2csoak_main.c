/****************************************************************************
 * apps/examples/i2csoak/i2csoak_main.c
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

/* Hammer a known-answer register on an I2C slave and count how often the
 * answer comes back wrong.
 *
 * This exists to measure a slave implementation, not a master: it reads a
 * register whose value never changes, so every mismatch is a transport
 * fault.  Two framings are exercised because they stress different things --
 * a STOP between the register select and the read, which is what the
 * PicoCalc's legacy protocol specifies, and a repeated START, which is what
 * a faster protocol wants and which many slave implementations get wrong.
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>

#include <nuttx/i2c/i2c_master.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define DEFAULT_DEVPATH  "/dev/i2c1"
#define DEFAULT_ADDR     0x1f
#define DEFAULT_REG      0x01    /* REG_ID_VER, a constant                  */
#define DEFAULT_EXP0     0x00
#define DEFAULT_EXP1     0x16    /* BIOS v1.6                               */
#define DEFAULT_COUNT    1000000
#define DEFAULT_FREQ     400000

/* Report progress this often so a long soak is visibly alive. */

#define PROGRESS_EVERY   50000

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct soak_cfg_s
{
  FAR const char *devpath;
  uint8_t  addr;
  uint8_t  reg;
  uint8_t  exp[2];
  uint32_t frequency;
  unsigned long count;
  bool     restart;             /* repeated START instead of STOP + START   */
};

struct soak_result_s
{
  unsigned long attempted;
  unsigned long xfer_errors;    /* I2C_TRANSFER returned an error           */
  unsigned long mismatches;     /* transfer succeeded, bytes were wrong     */
  unsigned long elapsed_ms;
  uint8_t       first_bad[2];
  unsigned long first_bad_at;
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: soak_now_ms
 ****************************************************************************/

static unsigned long soak_now_ms(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (unsigned long)ts.tv_sec * 1000UL + ts.tv_nsec / 1000000UL;
}

/****************************************************************************
 * Name: soak_once
 *
 * Description:
 *   One register select plus one two byte read, in whichever framing the
 *   configuration asks for.
 *
 ****************************************************************************/

static int soak_once(int fd, FAR const struct soak_cfg_s *cfg,
                     FAR uint8_t *reply)
{
  struct i2c_msg_s msg[2];
  struct i2c_transfer_s xfer;
  uint8_t reg = cfg->reg;
  int ret;

  msg[0].frequency = cfg->frequency;
  msg[0].addr      = cfg->addr;
  msg[0].flags     = 0;
  msg[0].buffer    = &reg;
  msg[0].length    = 1;

  msg[1].frequency = cfg->frequency;
  msg[1].addr      = cfg->addr;
  msg[1].flags     = I2C_M_READ;
  msg[1].buffer    = reply;
  msg[1].length    = 2;

  if (cfg->restart)
    {
      /* Both messages in one transfer: the driver emits a repeated START
       * between them and a single STOP at the end.
       */

      xfer.msgv = msg;
      xfer.msgc = 2;
      return ioctl(fd, I2CIOC_TRANSFER, (unsigned long)(uintptr_t)&xfer);
    }

  /* Two separate transfers, so each one ends with a STOP.  This is what the
   * legacy protocol requires: the slave assembles its reply inside the
   * receive callback, so the select must complete before the read starts.
   */

  xfer.msgv = &msg[0];
  xfer.msgc = 1;
  ret = ioctl(fd, I2CIOC_TRANSFER, (unsigned long)(uintptr_t)&xfer);
  if (ret < 0)
    {
      return ret;
    }

  xfer.msgv = &msg[1];
  xfer.msgc = 1;
  return ioctl(fd, I2CIOC_TRANSFER, (unsigned long)(uintptr_t)&xfer);
}

/****************************************************************************
 * Name: soak_run
 ****************************************************************************/

static int soak_run(FAR const struct soak_cfg_s *cfg,
                    FAR struct soak_result_s *res)
{
  unsigned long i;
  uint8_t reply[2];
  unsigned long start;
  int fd;

  fd = open(cfg->devpath, O_RDONLY);
  if (fd < 0)
    {
      fprintf(stderr, "i2csoak: open %s failed: %d\n", cfg->devpath, errno);
      return -errno;
    }

  memset(res, 0, sizeof(*res));
  start = soak_now_ms();

  for (i = 0; i < cfg->count; i++)
    {
      reply[0] = 0xff;
      reply[1] = 0xff;

      res->attempted++;

      if (soak_once(fd, cfg, reply) < 0)
        {
          res->xfer_errors++;
        }
      else if (reply[0] != cfg->exp[0] || reply[1] != cfg->exp[1])
        {
          if (res->mismatches == 0)
            {
              res->first_bad[0] = reply[0];
              res->first_bad[1] = reply[1];
              res->first_bad_at = i;
            }

          res->mismatches++;
        }

      if (PROGRESS_EVERY != 0 && (i % PROGRESS_EVERY) == (PROGRESS_EVERY - 1))
        {
          printf("  %lu/%lu  err=%lu bad=%lu\n",
                 i + 1, cfg->count, res->xfer_errors, res->mismatches);
          fflush(stdout);
        }
    }

  res->elapsed_ms = soak_now_ms() - start;
  close(fd);
  return OK;
}

/****************************************************************************
 * Name: soak_report
 ****************************************************************************/

static void soak_report(FAR const struct soak_cfg_s *cfg,
                        FAR const struct soak_result_s *res)
{
  unsigned long bad = res->xfer_errors + res->mismatches;

  printf("\n--- i2csoak %s, %lu Hz, %s ---\n",
         cfg->restart ? "repeated-START" : "STOP+START",
         (unsigned long)cfg->frequency,
         bad == 0 ? "PASS" : "FAIL");
  printf("  attempted    : %lu\n", res->attempted);
  printf("  xfer errors  : %lu\n", res->xfer_errors);
  printf("  bad replies  : %lu\n", res->mismatches);

  if (res->mismatches > 0)
    {
      printf("  first bad    : [%02x %02x] at %lu, expected [%02x %02x]\n",
             res->first_bad[0], res->first_bad[1], res->first_bad_at,
             cfg->exp[0], cfg->exp[1]);
    }

  printf("  elapsed      : %lu ms\n", res->elapsed_ms);

  if (res->elapsed_ms > 0)
    {
      printf("  rate         : %lu transactions/s\n",
             res->attempted * 1000UL / res->elapsed_ms);
    }
}

/****************************************************************************
 * Name: soak_usage
 ****************************************************************************/

static void soak_usage(void)
{
  printf("Usage: i2csoak [options]\n"
         "  -d <path>  I2C device      (default %s)\n"
         "  -a <addr>  slave address   (default 0x%02x)\n"
         "  -r <reg>   register to read(default 0x%02x)\n"
         "  -e <hi,lo> expected bytes  (default %02x,%02x)\n"
         "  -f <hz>    bus frequency   (default %u)\n"
         "  -n <count> transactions    (default %u)\n"
         "  -s         use repeated START instead of STOP + START\n",
         DEFAULT_DEVPATH, DEFAULT_ADDR, DEFAULT_REG,
         DEFAULT_EXP0, DEFAULT_EXP1, DEFAULT_FREQ, DEFAULT_COUNT);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  struct soak_cfg_s cfg;
  struct soak_result_s res;
  int i;

  cfg.devpath   = DEFAULT_DEVPATH;
  cfg.addr      = DEFAULT_ADDR;
  cfg.reg       = DEFAULT_REG;
  cfg.exp[0]    = DEFAULT_EXP0;
  cfg.exp[1]    = DEFAULT_EXP1;
  cfg.frequency = DEFAULT_FREQ;
  cfg.count     = DEFAULT_COUNT;
  cfg.restart   = false;

  /* Hand rolled rather than getopt(): NSH splits the command line for us and
   * an option parser here keeps the argument count inside
   * CONFIG_NSH_MAXARGUMENTS, which is 7 on this board.
   */

  for (i = 1; i < argc; i++)
    {
      if (strcmp(argv[i], "-s") == 0)
        {
          cfg.restart = true;
          continue;
        }

      if (i + 1 >= argc)
        {
          soak_usage();
          return EXIT_FAILURE;
        }

      if (strcmp(argv[i], "-d") == 0)
        {
          cfg.devpath = argv[++i];
        }
      else if (strcmp(argv[i], "-a") == 0)
        {
          cfg.addr = (uint8_t)strtoul(argv[++i], NULL, 0);
        }
      else if (strcmp(argv[i], "-r") == 0)
        {
          cfg.reg = (uint8_t)strtoul(argv[++i], NULL, 0);
        }
      else if (strcmp(argv[i], "-e") == 0)
        {
          FAR char *p = argv[++i];

          cfg.exp[0] = (uint8_t)strtoul(p, &p, 0);
          if (*p == ',')
            {
              p++;
            }

          cfg.exp[1] = (uint8_t)strtoul(p, NULL, 0);
        }
      else if (strcmp(argv[i], "-f") == 0)
        {
          cfg.frequency = (uint32_t)strtoul(argv[++i], NULL, 0);
        }
      else if (strcmp(argv[i], "-n") == 0)
        {
          cfg.count = strtoul(argv[++i], NULL, 0);
        }
      else
        {
          soak_usage();
          return EXIT_FAILURE;
        }
    }

  printf("i2csoak: %s addr 0x%02x reg 0x%02x expect [%02x %02x]\n",
         cfg.devpath, cfg.addr, cfg.reg, cfg.exp[0], cfg.exp[1]);
  printf("i2csoak: %lu transactions at %lu Hz, %s\n",
         cfg.count, (unsigned long)cfg.frequency,
         cfg.restart ? "repeated-START" : "STOP+START");

  if (soak_run(&cfg, &res) < 0)
    {
      return EXIT_FAILURE;
    }

  soak_report(&cfg, &res);
  return (res.xfer_errors + res.mismatches) == 0 ? EXIT_SUCCESS
                                                 : EXIT_FAILURE;
}
