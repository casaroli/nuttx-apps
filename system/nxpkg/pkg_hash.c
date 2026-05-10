/****************************************************************************
 * apps/system/nxpkg/pkg_hash.c
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pkg.h"

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct pkg_sha256_s
{
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t block[64];
  size_t used;
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const uint32_t g_pkg_sha256_k[64] =
{
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static uint32_t pkg_rotr32(uint32_t value, uint32_t shift)
{
  return (value >> shift) | (value << (32 - shift));
}

static uint32_t pkg_load_be32(FAR const uint8_t *buffer)
{
  return ((uint32_t)buffer[0] << 24) |
         ((uint32_t)buffer[1] << 16) |
         ((uint32_t)buffer[2] << 8) |
         (uint32_t)buffer[3];
}

static void pkg_store_be32(FAR uint8_t *buffer, uint32_t value)
{
  buffer[0] = (uint8_t)(value >> 24);
  buffer[1] = (uint8_t)(value >> 16);
  buffer[2] = (uint8_t)(value >> 8);
  buffer[3] = (uint8_t)value;
}

static void pkg_store_be64(FAR uint8_t *buffer, uint64_t value)
{
  int i;

  for (i = 7; i >= 0; i--)
    {
      buffer[i] = (uint8_t)value;
      value >>= 8;
    }
}

static void pkg_sha256_transform(FAR struct pkg_sha256_s *ctx,
                                 FAR const uint8_t *block)
{
  uint32_t w[64];
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f;
  uint32_t g;
  uint32_t h;
  int i;

  for (i = 0; i < 16; i++)
    {
      w[i] = pkg_load_be32(block + i * 4);
    }

  for (i = 16; i < 64; i++)
    {
      uint32_t s0;
      uint32_t s1;

      s0 = pkg_rotr32(w[i - 15], 7) ^ pkg_rotr32(w[i - 15], 18) ^
           (w[i - 15] >> 3);
      s1 = pkg_rotr32(w[i - 2], 17) ^ pkg_rotr32(w[i - 2], 19) ^
           (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; i++)
    {
      uint32_t s1;
      uint32_t ch;
      uint32_t temp1;
      uint32_t s0;
      uint32_t maj;
      uint32_t temp2;

      s1 = pkg_rotr32(e, 6) ^ pkg_rotr32(e, 11) ^ pkg_rotr32(e, 25);
      ch = (e & f) ^ ((~e) & g);
      temp1 = h + s1 + ch + g_pkg_sha256_k[i] + w[i];
      s0 = pkg_rotr32(a, 2) ^ pkg_rotr32(a, 13) ^ pkg_rotr32(a, 22);
      maj = (a & b) ^ (a & c) ^ (b & c);
      temp2 = s0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void pkg_sha256_init(FAR struct pkg_sha256_s *ctx)
{
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->bitlen = 0;
  ctx->used = 0;
}

static void pkg_sha256_update(FAR struct pkg_sha256_s *ctx,
                              FAR const uint8_t *data, size_t length)
{
  while (length > 0)
    {
      size_t remaining;
      size_t tocopy;

      remaining = sizeof(ctx->block) - ctx->used;
      tocopy = length < remaining ? length : remaining;

      memcpy(ctx->block + ctx->used, data, tocopy);
      ctx->used += tocopy;
      ctx->bitlen += (uint64_t)tocopy * 8;
      data += tocopy;
      length -= tocopy;

      if (ctx->used == sizeof(ctx->block))
        {
          pkg_sha256_transform(ctx, ctx->block);
          ctx->used = 0;
        }
    }
}

static void pkg_sha256_final(FAR struct pkg_sha256_s *ctx,
                             FAR uint8_t digest[32])
{
  size_t i;

  ctx->block[ctx->used++] = 0x80;

  if (ctx->used > 56)
    {
      while (ctx->used < 64)
        {
          ctx->block[ctx->used++] = 0;
        }

      pkg_sha256_transform(ctx, ctx->block);
      ctx->used = 0;
    }

  while (ctx->used < 56)
    {
      ctx->block[ctx->used++] = 0;
    }

  pkg_store_be64(ctx->block + 56, ctx->bitlen);
  pkg_sha256_transform(ctx, ctx->block);

  for (i = 0; i < 8; i++)
    {
      pkg_store_be32(digest + i * 4, ctx->state[i]);
    }
}

static void pkg_hex_encode(FAR const uint8_t *input, size_t length,
                           FAR char *output)
{
  static const char g_hex[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < length; i++)
    {
      output[i * 2] = g_hex[input[i] >> 4];
      output[i * 2 + 1] = g_hex[input[i] & 0x0f];
    }

  output[length * 2] = '\0';
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int pkg_hash_file_sha256(FAR const char *path,
                         FAR char digest[PKG_HASH_HEX_LEN + 1])
{
  struct pkg_sha256_s ctx;
  FAR FILE *stream;
  uint8_t raw[32];
  uint8_t buffer[512];
  size_t nread;

  stream = fopen(path, "rb");
  if (stream == NULL)
    {
      return -errno;
    }

  pkg_sha256_init(&ctx);

  for (; ; )
    {
      nread = fread(buffer, 1, sizeof(buffer), stream);
      if (nread > 0)
        {
          pkg_sha256_update(&ctx, buffer, nread);
        }

      if (nread < sizeof(buffer))
        {
          if (ferror(stream))
            {
              fclose(stream);
              return -EIO;
            }

          break;
        }
    }

  fclose(stream);
  pkg_sha256_final(&ctx, raw);
  pkg_hex_encode(raw, sizeof(raw), digest);
  return 0;
}
