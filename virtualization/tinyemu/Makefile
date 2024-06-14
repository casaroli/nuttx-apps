############################################################################
# apps/virtualization/tinyemu/Makefile
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#
############################################################################

include $(APPDIR)/Make.defs

TINYEMU_UNPACKDIR = tinyemu-2019-12-21

TINYEMU_TGZ = $(TINYEMU_UNPACKDIR).tar.gz

TINYEMU_URL ?= https://bellard.org/tinyemu/$(TINYEMU_TGZ)

UNPACK ?= tar zxvf

# CSRCS = $(wildcard $(MBEDTLS_UNPACKLIBDIR)$(DELIM)*.c)

$(TINYEMU_TGZ):
	@echo "Downloading: $(TINYEMU_TGZ)"
	$(Q) curl -O -L $(TINYEMU_URL)

$(TINYEMU_UNPACKDIR): $(TINYEMU_TGZ)
	@echo "Unpacking: $(TINYEMU_TGZ) -> $(TINYEMU_UNPACKDIR)"
	$(Q) $(UNPACK) $(TINYEMU_TGZ)
	cp $(TINYEMU_UNPACKDIR)/riscv_cpu.c $(TINYEMU_UNPACKDIR)/riscv_cpu32.c
	cp $(TINYEMU_UNPACKDIR)/riscv_cpu.c $(TINYEMU_UNPACKDIR)/riscv_cpu64.c
	cp $(TINYEMU_UNPACKDIR)/riscv_cpu.c $(TINYEMU_UNPACKDIR)/riscv_cpu128.c

context:: $(TINYEMU_UNPACKDIR)

distclean::
	$(call DELDIR, $(TINYEMU_UNPACKDIR))
	$(call DELFILE, $(TINYEMU_TGZ))

CFLAGS += -DCONFIG_RISCV_MAX_XLEN=64
CFLAGS += -DCONFIG_X86EMU

CFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
CFLAGS += -D_GNU_SOURCE
#-DCONFIG_VERSION=\"$(shell cat VERSION)\"

CSRCS += $(TINYEMU_UNPACKDIR)/virtio.c
CSRCS += $(TINYEMU_UNPACKDIR)/pci.c
CSRCS += $(TINYEMU_UNPACKDIR)/fs.c
CSRCS += $(TINYEMU_UNPACKDIR)/cutils.c
CSRCS += $(TINYEMU_UNPACKDIR)/iomem.c
CSRCS += $(TINYEMU_UNPACKDIR)/simplefb.c
CSRCS += $(TINYEMU_UNPACKDIR)/json.c
CSRCS += $(TINYEMU_UNPACKDIR)/machine.c

# ifeq ($(CONFIG_MBEDTLS_APP_BENCHMARK),y)
PROGNAME  += $(CONFIG_VIRTUALIZATION_TINYEMU_PROGNAME)
PRIORITY  += $(CONFIG_VIRTUALIZATION_TINYEMU_PRIORITY)
STACKSIZE += $(CONFIG_VIRTUALIZATION_TINYEMU_STACKSIZE)
MAINSRC += $(TINYEMU_UNPACKDIR)/temu.c
$(TINYEMU_UNPACKDIR)/temu.c_CFLAGS = -DCONFIG_VERSION=\"v1.2.3\"
# endif



# slirp
#CFLAGS+=-DCONFIG_SLIRP
#EMU_OBJS+=$(addprefix slirp/, bootp.c ip_icmp.c mbuf.c slirp.c tcp_output.c cksum.c ip_input.c misc.c socket.c tcp_subr.c udp.c if.c ip_output.c sbuf.c tcp_input.c tcp_timer.c)

# fs
#EMU_OBJS+=fs_disk.c
#EMU_LIBS=-lrt

# fs_net
#CFLAGS+=-DCONFIG_FS_NET
#CSRCS += $(TINYEMU_UNPACKDIR)/fs_net.c
# CSRCS += $(TINYEMU_UNPACKDIR)/fs_wget.c
#CSRCS += $(TINYEMU_UNPACKDIR)/fs_utils.c
# CSRCS += $(TINYEMU_UNPACKDIR)/block_net.c

# sdl
#CSRCS += sdl.c
#CFLAGS+=-DCONFIG_SDL

CSRCS += $(TINYEMU_UNPACKDIR)/riscv_machine.c
CSRCS += $(TINYEMU_UNPACKDIR)/softfp.c
CSRCS += $(TINYEMU_UNPACKDIR)/riscv_cpu32.c
CSRCS += $(TINYEMU_UNPACKDIR)/riscv_cpu64.c

$(TINYEMU_UNPACKDIR)/riscv_cpu32.c_CFLAGS = -DMAX_XLEN=32
$(TINYEMU_UNPACKDIR)/riscv_cpu64.c_CFLAGS += -DMAX_XLEN=64
$(TINYEMU_UNPACKDIR)/riscv_cpu128.c_CFLAGS += -DMAX_XLEN=128

CSRCS += $(TINYEMU_UNPACKDIR)/x86_cpu.c
CSRCS += $(TINYEMU_UNPACKDIR)/x86_machine.c
CSRCS += $(TINYEMU_UNPACKDIR)/ide.c
CSRCS += $(TINYEMU_UNPACKDIR)/ps2.c
CSRCS += $(TINYEMU_UNPACKDIR)/vmmouse.c
CSRCS += $(TINYEMU_UNPACKDIR)/pckbd.c
CSRCS += $(TINYEMU_UNPACKDIR)/vga.c



# # Configuration Applications

# ifneq ($(CONFIG_MBEDTLS_APPS),)

# MODULE = $(CONFIG_MBEDTLS_APPS)

# ifeq ($(CONFIG_MBEDTLS_APP_BENCHMARK),y)

# PROGNAME  += $(CONFIG_MBEDTLS_APP_BENCHMARK_PROGNAME)
# PRIORITY  += $(CONFIG_MBEDTLS_APP_BENCHMARK_PRIORITY)
# STACKSIZE += $(CONFIG_MBEDTLS_APP_BENCHMARK_STACKSIZE)

# MAINSRC += $(MBEDTLS_UNPACKPROGDIR)/test/benchmark.c
# endif

# ifeq ($(CONFIG_MBEDTLS_APP_SELFTEST),y)

# PROGNAME  += $(CONFIG_MBEDTLS_APP_SELFTEST_PROGNAME)
# PRIORITY  += $(CONFIG_MBEDTLS_APP_SELFTEST_PRIORITY)
# STACKSIZE += $(CONFIG_MBEDTLS_APP_SELFTEST_STACKSIZE)

# MAINSRC += $(MBEDTLS_UNPACKPROGDIR)/test/selftest.c
# endif

# endif

# # Configuration alternative implementation

# ifeq ($(CONFIG_MBEDTLS_ENTROPY_HARDWARE_ALT),y)
# CSRCS += $(APPDIR)/crypto/mbedtls/source/entropy_alt.c
# endif

# ifeq ($(CONFIG_MBEDTLS_ALT),y)

# CSRCS += $(APPDIR)/crypto/mbedtls/source/dev_alt.c

# ifeq ($(CONFIG_MBEDTLS_AES_ALT),y)
# CSRCS += $(APPDIR)/crypto/mbedtls/source/aes_alt.c
# endif

# ifeq ($(CONFIG_MBEDTLS_MD5_ALT),y)
# CSRCS += $(APPDIR)/crypto/mbedtls/source/md5_alt.c
# endif

# ifeq ($(CONFIG_MBEDTLS_SHA1_ALT),y)
# CSRCS += $(APPDIR)/crypto/mbedtls/source/sha1_alt.c
# endif

# ifeq ($(CONFIG_MBEDTLS_SHA256_ALT),y)
# CSRCS += $(APPDIR)/crypto/mbedtls/source/sha256_alt.c
# endif

# ifeq ($(CONFIG_MBEDTLS_SHA512_ALT),y)
# CSRCS += $(APPDIR)/crypto/mbedtls/source/sha512_alt.c
# endif

# endif

include $(APPDIR)/Application.mk
