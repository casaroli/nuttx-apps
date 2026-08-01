/****************************************************************************
 * apps/examples/pmu/pmu_main.c
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

/* Read and drive the PicoCalc co-processor's PMU registers.
 *
 * The co-processor caches the AXP2101's state at 0x20 and offers an
 * asynchronous mailbox at 0x22/0x23 for the registers it does not model.
 * i2ctool cannot reach the mailbox at all: a submission is four to seven
 * bytes and `i2c set` writes only 8 or 16 bits, so the shortest legal
 * request is one byte longer than the tool can send.
 *
 * This is also the only convenient way to see the summary as anything other
 * than twelve bytes of hex, and the decode is where the interesting
 * distinction lives -- "no battery" and "zero percent" are different facts,
 * and the summary is careful to say which.
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <nuttx/i2c/i2c_master.h>
#include <nuttx/lcd/lcd_dev.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define DEVPATH        "/dev/i2c1"
#define ADDR           0x1e
#define FREQUENCY      400000

/* Register byte OR'd with this makes the transaction a write. */

#define WRITE_MASK     0x80

#define REG_CAPS       0x02
#define REG_IRQ_FLAGS  0x04
#define REG_SUMMARY    0x20
#define REG_CTL        0x21
#define REG_XFER       0x22
#define REG_XFER_RES   0x23
#define REG_UNLOCK     0x7f
#define REG_BL_KEY     0x11
#define REG_POWER_CTL  0x30

/* power_op::BOOTLOADER */

#define POWER_BOOTLOADER  0x08

#define LCD_DEVPATH    "/dev/lcd0"

#define SUMMARY_LEN    12
#define XFER_RES_LEN   6
#define XFER_MAX_DATA  4

/* pmu::flags */

#define F_BATT         (1 << 0)
#define F_CHARGING     (1 << 1)
#define F_VBUS         (1 << 2)
#define F_VBUS_GOOD    (1 << 3)
#define F_LOW          (1 << 4)
#define F_CHG_DONE     (1 << 5)
#define F_BATFET       (1 << 6)
#define F_ONLINE       (1 << 7)

/* pmu::status */

#define ST_IDLE        0
#define ST_BUSY        1
#define ST_OK          2
#define ST_DENIED      3
#define ST_NAK         4
#define ST_BAD         5

/* pmu::xfer_op */

#define XFER_READ      0x01
#define XFER_WRITE     0x02

/* How long to wait for the mailbox.  The PMU task services requests on a
 * 50ms tick, so anything past a few ticks means it is not running.
 */

#define POLL_TRIES     20
#define POLL_DELAY_US  25000

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const char *g_chg_state[] =
{
  "trickle", "pre", "constant-current", "constant-voltage", "done", "stopped"
};

static const char *g_status[] =
{
  "idle", "busy", "ok", "DENIED", "nak", "bad request"
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: pmu_read
 *
 * Description:
 *   Register select and read in one transfer, so the driver emits a repeated
 *   START between them.  The new protocol requires it: a bare read with no
 *   selection is the keyboard hot block, not the register that was asked
 *   for.
 *
 ****************************************************************************/

static int pmu_read(int fd, uint8_t reg, FAR uint8_t *buf, size_t len)
{
  struct i2c_msg_s msg[2];
  struct i2c_transfer_s xfer;

  msg[0].frequency = FREQUENCY;
  msg[0].addr      = ADDR;
  msg[0].flags     = 0;
  msg[0].buffer    = &reg;
  msg[0].length    = 1;

  msg[1].frequency = FREQUENCY;
  msg[1].addr      = ADDR;
  msg[1].flags     = I2C_M_READ;
  msg[1].buffer    = buf;
  msg[1].length    = len;

  xfer.msgv = msg;
  xfer.msgc = 2;

  return ioctl(fd, I2CIOC_TRANSFER, (unsigned long)(uintptr_t)&xfer);
}

/****************************************************************************
 * Name: pmu_write
 ****************************************************************************/

static int pmu_write(int fd, uint8_t reg, FAR const uint8_t *data,
                     size_t len)
{
  struct i2c_msg_s msg;
  struct i2c_transfer_s xfer;
  uint8_t buf[1 + 8];

  if (len > sizeof(buf) - 1)
    {
      return -E2BIG;
    }

  buf[0] = reg | WRITE_MASK;
  memcpy(&buf[1], data, len);

  msg.frequency = FREQUENCY;
  msg.addr      = ADDR;
  msg.flags     = 0;
  msg.buffer    = buf;
  msg.length    = len + 1;

  xfer.msgv = &msg;
  xfer.msgc = 1;

  return ioctl(fd, I2CIOC_TRANSFER, (unsigned long)(uintptr_t)&xfer);
}

/****************************************************************************
 * Name: pmu_status_name
 ****************************************************************************/

static const char *pmu_status_name(uint8_t s)
{
  return s < sizeof(g_status) / sizeof(g_status[0]) ? g_status[s]
                                                    : "unknown";
}

/****************************************************************************
 * Name: pmu_show_summary
 ****************************************************************************/

static int pmu_show_summary(int fd)
{
  uint8_t b[SUMMARY_LEN];
  uint8_t flags;
  int i;

  if (pmu_read(fd, REG_SUMMARY, b, sizeof(b)) < 0)
    {
      fprintf(stderr, "pmu: read summary failed: %d\n", errno);
      return ERROR;
    }

  printf("raw     ");
  for (i = 0; i < SUMMARY_LEN; i++)
    {
      printf("%02x ", b[i]);
    }

  printf("\n");

  flags = b[0];

  if ((flags & F_ONLINE) == 0)
    {
      /* Everything else in the block is meaningless without this bit, so say
       * so rather than printing a decode of it.
       */

      printf("PMU     OFFLINE -- %u consecutive failures\n", b[10]);
      return OK;
    }

  printf("PMU     online, refresh #%u", b[3]);
  if (b[10] != 0)
    {
      printf(", %u recent failures", b[10]);
    }

  printf("\n");

  printf("battery %s", (flags & F_BATT) ? "present" : "ABSENT");

  if (flags & F_BATT)
    {
      if (b[2] > 100)
        {
          printf(", charge unknown");
        }
      else
        {
          printf(", %u%%%s", b[2], (flags & F_LOW) ? " (LOW)" : "");
        }

      printf(", %u mV", (unsigned)(b[4] | (b[5] << 8)));
    }

  printf("\n");

  printf("charge  %s",
         b[1] < sizeof(g_chg_state) / sizeof(g_chg_state[0])
           ? g_chg_state[b[1]] : "unknown");

  if (flags & F_CHARGING)
    {
      printf(", charging");
    }

  if (flags & F_CHG_DONE)
    {
      printf(", done");
    }

  printf("\n");

  printf("vbus    %s%s, %u mV\n",
         (flags & F_VBUS) ? "present" : "absent",
         (flags & F_VBUS_GOOD) ? ", good" : "",
         (unsigned)(b[6] | (b[7] << 8)));

  printf("vsys    %u mV%s\n",
         (unsigned)(b[8] | (b[9] << 8)),
         (flags & F_BATFET) ? ", batfet on" : "");

  return OK;
}

/****************************************************************************
 * Name: pmu_await
 *
 * Description:
 *   Poll the mailbox result until it stops saying busy.  The mailbox is
 *   asynchronous by design -- the co-processor cannot run an AXP2101
 *   transaction inside the I2C interrupt without stretching SCL through the
 *   whole of it -- so a submission and its answer are two transactions.
 *
 ****************************************************************************/

static int pmu_await(int fd, FAR uint8_t *res)
{
  int i;

  for (i = 0; i < POLL_TRIES; i++)
    {
      if (pmu_read(fd, REG_XFER_RES, res, XFER_RES_LEN) < 0)
        {
          fprintf(stderr, "pmu: read result failed: %d\n", errno);
          return ERROR;
        }

      if (res[0] != ST_BUSY)
        {
          return OK;
        }

      usleep(POLL_DELAY_US);
    }

  fprintf(stderr, "pmu: mailbox still busy after %d tries\n", POLL_TRIES);
  return ERROR;
}

/****************************************************************************
 * Name: pmu_mailbox
 ****************************************************************************/

static int pmu_mailbox(int fd, uint8_t op, uint8_t reg, uint8_t len,
                       FAR const uint8_t *data)
{
  uint8_t body[3 + XFER_MAX_DATA];
  uint8_t res[XFER_RES_LEN];
  size_t n = 3;
  int i;

  body[0] = op;
  body[1] = reg;
  body[2] = len;

  if (op == XFER_WRITE)
    {
      memcpy(&body[3], data, len);
      n += len;
    }

  if (pmu_write(fd, REG_XFER, body, n) < 0)
    {
      fprintf(stderr, "pmu: submit failed: %d\n", errno);
      return ERROR;
    }

  if (pmu_await(fd, res) != OK)
    {
      return ERROR;
    }

  printf("status  %u (%s)\n", res[0], pmu_status_name(res[0]));

  if (res[0] == ST_OK && op == XFER_READ)
    {
      printf("data    ");
      for (i = 0; i < res[1] && i < XFER_MAX_DATA; i++)
        {
          printf("%02x ", res[2 + i]);
        }

      printf("\n");
    }

  /* A denial is the guard doing its job, not a failure of this program, so
   * it is reported and exits zero.  Only a transport fault is an error.
   */

  return OK;
}

/****************************************************************************
 * Name: pmu_backlight
 *
 * Description:
 *   Set the panel backlight through /dev/lcd0, and read it back.
 *
 *   Deliberately not a register write.  The co-processor register is two
 *   lines away, but going through LCDDEVIO_SETPOWER is what exercises the
 *   path a real caller uses -- NX, the framebuffer, the PM framework -- and
 *   therefore the only way to find out whether that path is wired up.
 *
 ****************************************************************************/

static int pmu_backlight(int level)
{
  int power;
  int fd;

  fd = open(LCD_DEVPATH, O_RDWR);
  if (fd < 0)
    {
      fprintf(stderr, "pmu: open %s failed: %d\n", LCD_DEVPATH, errno);
      return ERROR;
    }

  if (level >= 0 &&
      ioctl(fd, LCDDEVIO_SETPOWER, (unsigned long)level) < 0)
    {
      fprintf(stderr, "pmu: LCDDEVIO_SETPOWER failed: %d\n", errno);
      close(fd);
      return ERROR;
    }

  if (ioctl(fd, LCDDEVIO_GETPOWER, (unsigned long)((uintptr_t)&power)) < 0)
    {
      fprintf(stderr, "pmu: LCDDEVIO_GETPOWER failed: %d\n", errno);
      close(fd);
      return ERROR;
    }

  printf("lcd power %d of %d\n", power, CONFIG_LCD_MAXPOWER);
  close(fd);
  return OK;
}

/****************************************************************************
 * Name: pmu_usage
 ****************************************************************************/

static void pmu_usage(void)
{
  fprintf(stderr,
    "Usage: pmu [status]              decode the cached PMU summary\n"
    "       pmu caps                  capability bitmap and IRQ flags\n"
    "       pmu ctl <op> <arg>        submit a PMU_CTL opcode\n"
    "       pmu read <reg> [len]      mailbox read of an AXP2101 register\n"
    "       pmu write [-u] <reg> <b>...  mailbox write, up to 4 bytes\n"
    "       pmu unlock                arm privileged writes for one second\n"
    "       pmu bootloader            reset the co-processor into its ROM\n"
    "                                 bootloader, ready for stm32flash\n"
    "       pmu bl [level]            panel backlight, /dev/lcd0, decimal\n"
    "       pmu kbl <level>           keyboard backlight, 00-ff\n"
    "\n"
    "-u arms the guard in the same process as the write, since arming\n"
    "lapses after a second and two shell commands never fit inside that.\n"
    "\n"
    "All numbers are hex.  A mailbox write to a denied register reports\n"
    "status 3; see the denylist in picocalc-proto's pmu module for what is\n"
    "on it and why.\n");
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  static const uint8_t magic[] =
    {
      0x50, 0x4b, 0x55, 0x4c
    };

  uint8_t data[XFER_MAX_DATA];
  uint8_t buf[4];
  int status = EXIT_FAILURE;
  int fd;

  fd = open(DEVPATH, O_RDONLY);
  if (fd < 0)
    {
      fprintf(stderr, "pmu: open %s failed: %d\n", DEVPATH, errno);
      return EXIT_FAILURE;
    }

  if (argc < 2 || strcmp(argv[1], "status") == 0)
    {
      status = pmu_show_summary(fd) == OK ? EXIT_SUCCESS : EXIT_FAILURE;
    }
  else if (strcmp(argv[1], "caps") == 0)
    {
      if (pmu_read(fd, REG_CAPS, buf, 4) < 0)
        {
          fprintf(stderr, "pmu: read caps failed: %d\n", errno);
        }
      else
        {
          printf("caps    %08lx\n",
                 (unsigned long)(buf[0] | (buf[1] << 8) |
                                 (buf[2] << 16) | ((uint32_t)buf[3] << 24)));

          if (pmu_read(fd, REG_IRQ_FLAGS, buf, 2) == 0)
            {
              printf("irq     %04x\n",
                     (unsigned)(buf[0] | (buf[1] << 8)));
              status = EXIT_SUCCESS;
            }
        }
    }
  else if (strcmp(argv[1], "bootloader") == 0)
    {
      /* Arm and fire in one process: the guard lapses after a second, and
       * this is the one command where being unable to complete the sequence
       * would leave the co-processor exactly as it was -- which is the safe
       * outcome, but not the one that was asked for.
       *
       * The co-processor stops answering immediately after.  That is the
       * success case: it is in the ROM bootloader, which serves neither I2C
       * address, and stm32flash on the serial port is what talks to it next.
       */

      uint8_t op[2];

      op[0] = POWER_BOOTLOADER;
      op[1] = 0;

      if (pmu_write(fd, REG_UNLOCK, magic, sizeof(magic)) < 0 ||
          pmu_write(fd, REG_POWER_CTL, op, sizeof(op)) < 0)
        {
          fprintf(stderr, "pmu: bootloader request failed: %d\n", errno);
        }
      else
        {
          printf("requested; the co-processor should stop answering now\n");
          status = EXIT_SUCCESS;
        }
    }
  else if (strcmp(argv[1], "bl") == 0)
    {
      /* Decimal here, unlike everything else: this one is an
       * LCD power level in the units CONFIG_LCD_MAXPOWER is expressed in,
       * not a register value.
       */

      int level = argc > 2 ? atoi(argv[2]) : -1;

      status = pmu_backlight(level) == OK ? EXIT_SUCCESS : EXIT_FAILURE;
    }
  else if (strcmp(argv[1], "kbl") == 0 && argc >= 3)
    {
      /* The keyboard backlight has no NuttX device of its own -- nothing in
       * the OS models a light that is not attached to a display -- so this
       * one really is a register write.
       */

      uint8_t level = (uint8_t)strtoul(argv[2], NULL, 16);

      if (pmu_write(fd, REG_BL_KEY, &level, 1) < 0)
        {
          fprintf(stderr, "pmu: keyboard backlight failed: %d\n", errno);
        }
      else
        {
          status = EXIT_SUCCESS;
        }
    }
  else if (strcmp(argv[1], "unlock") == 0)
    {
      if (pmu_write(fd, REG_UNLOCK, magic, sizeof(magic)) < 0)
        {
          fprintf(stderr, "pmu: unlock failed: %d\n", errno);
        }
      else
        {
          printf("armed for one second\n");
          status = EXIT_SUCCESS;
        }
    }
  else if (strcmp(argv[1], "ctl") == 0 && argc >= 3)
    {
      uint8_t ctl[2];

      ctl[0] = (uint8_t)strtoul(argv[2], NULL, 16);
      ctl[1] = argc > 3 ? (uint8_t)strtoul(argv[3], NULL, 16) : 0;

      if (pmu_write(fd, REG_CTL, ctl, 2) < 0)
        {
          fprintf(stderr, "pmu: ctl failed: %d\n", errno);
        }
      else
        {
          usleep(POLL_DELAY_US * 4);

          if (pmu_read(fd, REG_CTL, buf, 2) == 0)
            {
              printf("op %02x  status %u (%s)\n",
                     buf[0], buf[1], pmu_status_name(buf[1]));
              status = EXIT_SUCCESS;
            }
        }
    }
  else if (strcmp(argv[1], "read") == 0 && argc >= 3)
    {
      uint8_t reg = (uint8_t)strtoul(argv[2], NULL, 16);
      uint8_t len = argc > 3 ? (uint8_t)strtoul(argv[3], NULL, 16) : 1;

      status = pmu_mailbox(fd, XFER_READ, reg, len, NULL) == OK
                 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
  else if (strcmp(argv[1], "write") == 0 && argc >= 4)
    {
      /* "-u" arms the guard and writes in the same process.  The arming
       * lapses after a second, which no operator typing two shell commands
       * will ever beat, so the two have to be one command or the privileged
       * path is untestable by hand.
       */

      bool priv = strcmp(argv[2], "-u") == 0;
      int base = priv ? 3 : 2;
      uint8_t reg;
      int n;
      int i;

      if (argc < base + 2)
        {
          pmu_usage();
          close(fd);
          return EXIT_FAILURE;
        }

      if (priv && pmu_write(fd, REG_UNLOCK, magic, sizeof(magic)) < 0)
        {
          fprintf(stderr, "pmu: unlock failed: %d\n", errno);
          close(fd);
          return EXIT_FAILURE;
        }

      reg = (uint8_t)strtoul(argv[base], NULL, 16);
      n = argc - base - 1;

      if (n > XFER_MAX_DATA)
        {
          n = XFER_MAX_DATA;
        }

      for (i = 0; i < n; i++)
        {
          data[i] = (uint8_t)strtoul(argv[base + 1 + i], NULL, 16);
        }

      status = pmu_mailbox(fd, XFER_WRITE, reg, n, data) == OK
                 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
  else
    {
      pmu_usage();
    }

  close(fd);
  return status;
}
