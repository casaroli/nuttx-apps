############################################################################
# apps/crypto/mbedtls/Makefile
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

# Mbed TLS crypto library

MBEDTLS_VERSION = $(patsubst "%",%,$(strip $(CONFIG_MBEDTLS_VERSION)))
MBEDTLS_UNPACKNAME = mbedtls

MBEDTLS_UNPACKLIBDIR = $(MBEDTLS_UNPACKNAME)$(DELIM)library
MBEDTLS_UNPACKPROGDIR = $(MBEDTLS_UNPACKNAME)$(DELIM)programs

# This lets Mbed TLS better use some of the POSIX features we have
CFLAGS += ${DEFINE_PREFIX}__unix__ -Wno-error=undef

# CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/include


# mbedtls/library/bignum.c_CFLAGS += -fno-lto
# 
# # Build break on Assemble compiler if -fno-omit-frame-pointer and -O3 enabled at same time
# # {standard input}: Assembler messages:
# # {standard input}:2560: Error: branch out of range
# # make[2]: *** [apps/Application.mk:170: mbedtls/library/sha256.o] Error 1
# 
# ifeq ($(CONFIG_FRAME_POINTER),y)
#   ifeq ($(CONFIG_DEBUG_OPTLEVEL),"-O3")
#     mbedtls/library/sha256.c_CFLAGS += -O2
#   endif
# endif
# 
# ifeq ($(CONFIG_ARCH_SIM),y)
#   CFLAGS += -O0
# endif

# CSRCS = $(wildcard $(MBEDTLS_UNPACKLIBDIR)$(DELIM)*.c)

# $(MBEDTLS_ZIP):
# 	@echo "Downloading: $(MBEDTLS_URL)/$(MBEDTLS_ZIP)"
# 	$(Q) curl -O -L $(MBEDTLS_URL)/$(MBEDTLS_ZIP)

$(MBEDTLS_UNPACKNAME):
	# git clone --depth 1 --recursive --branch v$(MBEDTLS_VERSION) https://github.com/Mbed-TLS/mbedtls.git
	git clone --depth 1 --recursive --branch nuttx-static-locals https://github.com/casaroli/mbedtls.git
	patch -p1 -d $(MBEDTLS_UNPACKNAME) < 0001-mbedtls-entropy_poll-use-getrandom-to-get-the-system.patch

context:: $(MBEDTLS_UNPACKNAME)
	(cd $(MBEDTLS_UNPACKNAME)/tests && make src/test_certs.h MAKEFLAGS="$(MAKEFLAGS)")
	(cd $(MBEDTLS_UNPACKPROGDIR) && make test/query_config.c MAKEFLAGS="$(MAKEFLAGS)")
	mkdir -p $(MBEDTLS_UNPACKNAME)/build
	(cd $(MBEDTLS_UNPACKNAME)/build && cmake \
		-DCMAKE_VERBOSE_MAKEFILE=1 \
	 	-DCMAKE_INSTALL_PREFIX="install" \
		-DCMAKE_INSTALL_LIBDIR=lib \
		-DCMAKE_C_COMPILER=$(CC) \
		-DCMAKE_C_FLAGS="$(CFLAGS)" \
		-DENABLE_TESTING=OFF \
		-DENABLE_PROGRAMS=OFF \
		..)

clean_context:
	echo CALLED CLEAN_CONTEXT
	$(call DELDIR, $(MBEDTLS_UNPACKNAME)/build)
	$(call DELFILE, $(MBEDTLS_UNPACKNAME)/tests/src/test_certs.h)
	$(call DELFILE, $(MBEDTLS_UNPACKPROGDIR)/test/query_config.c)

distclean::
	echo CALLED DISTCLEAN
	$(call DELDIR, $(MBEDTLS_UNPACKNAME))

depend::
	(cd $(MBEDTLS_UNPACKNAME)/build && make install MAKEFLAGS="$(MAKEFLAGS)")

clean::
	echo CALLED CLEAN
	(test -d $(MBEDTLS_UNPACKNAME)/build && cd $(MBEDTLS_UNPACKNAME)/build && make clean MAKEFLAGS="$(MAKEFLAGS)" || :)
	$(call DELDIR, $(MBEDTLS_UNPACKNAME)/build/install)

# Application Configuration

ifneq ($(CONFIG_MBEDTLS_APPS),)

MODULE = $(CONFIG_MBEDTLS_APPS)

ifeq ($(CONFIG_MBEDTLS_APP_BENCHMARK),y)
PROGNAME  += $(CONFIG_MBEDTLS_APP_BENCHMARK_PROGNAME)
PRIORITY  += $(CONFIG_MBEDTLS_APP_BENCHMARK_PRIORITY)
STACKSIZE += $(CONFIG_MBEDTLS_APP_BENCHMARK_STACKSIZE)
MAINSRC += $(MBEDTLS_UNPACKPROGDIR)/test/benchmark.c
endif

ifeq ($(CONFIG_MBEDTLS_APP_SELFTEST),y)
PROGNAME  += $(CONFIG_MBEDTLS_APP_SELFTEST_PROGNAME)
PRIORITY  += $(CONFIG_MBEDTLS_APP_SELFTEST_PRIORITY)
STACKSIZE += $(CONFIG_MBEDTLS_APP_SELFTEST_STACKSIZE)
MAINSRC += $(MBEDTLS_UNPACKPROGDIR)/test/selftest.c
endif

ifeq ($(CONFIG_MBEDTLS_APP_SSL_CLIENT2),y)
PROGNAME += $(CONFIG_MBEDTLS_APP_SSL_CLIENT2_PROGNAME)
PRIORITY += $(CONFIG_MBEDTLS_APP_SSL_CLIENT2_PRIORITY)
STACKSIZE += $(CONFIG_MBEDTLS_APP_SSL_CLIENT2_STACKSIZE)
MAINSRC += $(MBEDTLS_UNPACKPROGDIR)/ssl/ssl_client2.c
$(MBEDTLS_UNPACKPROGDIR)/ssl/ssl_client2.c_CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/tests/include
endif

ifeq ($(CONFIG_MBEDTLS_APP_SSL_SERVER2),y)
PROGNAME += $(CONFIG_MBEDTLS_APP_SSL_SERVER2_PROGNAME)
PRIORITY += $(CONFIG_MBEDTLS_APP_SSL_SERVER2_PRIORITY)
STACKSIZE += $(CONFIG_MBEDTLS_APP_SSL_SERVER2_STACKSIZE)
MAINSRC += $(MBEDTLS_UNPACKPROGDIR)/ssl/ssl_server2.c
$(MBEDTLS_UNPACKPROGDIR)/ssl/ssl_server2.c_CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/tests/include
endif

CSRCS += $(MBEDTLS_UNPACKPROGDIR)/ssl/ssl_test_lib.c
mbedtls/programs/ssl/ssl_test_lib.c_CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/tests/include
./mbedtls/programs/ssl/ssl_test_lib.c_CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/tests/include
$(MBEDTLS_UNPACKPROGDIR)/ssl/ssl_test_lib.c_CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/tests/include
CSRCS += $(MBEDTLS_UNPACKPROGDIR)/test/query_config.c
CSRCS += mbedtls/tests/src/certs.c
CSRCS += mbedtls/tests/src/helpers.c
CSRCS += mbedtls/tests/src/psa_crypto_helpers.c
mbedtls/tests/src/helpers.c_CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/tests/include ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/library
mbedtls/tests/src/certs.c_CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/tests/include ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/library
mbedtls/tests/src/psa_crypto_helpers.c_CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/tests/include ${INCDIR_PREFIX}$(APPDIR)/crypto/mbedtls/mbedtls/library

ifeq ($(CONFIG_MBEDTLS_APP_X509_CERT_APP),y)
PROGNAME += $(CONFIG_MBEDTLS_APP_X509_CERT_APP_PROGNAME)
PRIORITY += $(CONFIG_MBEDTLS_APP_X509_CERT_APP_PRIORITY)
STACKSIZE += $(CONFIG_MBEDTLS_APP_X509_CERT_APP_STACKSIZE)
MAINSRC += $(MBEDTLS_UNPACKPROGDIR)/x509/cert_app.c
endif

ifeq ($(CONFIG_MBEDTLS_APP_X509_LOAD_ROOTS),y)
PROGNAME += $(CONFIG_MBEDTLS_APP_X509_LOAD_ROOTS_PROGNAME)
PRIORITY += $(CONFIG_MBEDTLS_APP_X509_LOAD_ROOTS_PRIORITY)
STACKSIZE += $(CONFIG_MBEDTLS_APP_X509_LOAD_ROOTS_STACKSIZE)
MAINSRC += $(MBEDTLS_UNPACKPROGDIR)/x509/load_roots.c
endif

endif

# Configuration alternative implementation

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
