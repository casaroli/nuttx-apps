/****************************************************************************
 * apps/system/mp3play/mp3play_main.c
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>

#include <nuttx/audio/audio.h>
#include <audioutils/nxaudio.h>

/* mad.h is generated on whatever host built the release, and this one
 * carries a hard-wired "# define FPM_INTEL" -- x86 inline assembly, which
 * does not assemble for Thumb-2.  The selection inside the header tests
 * FPM_64BIT before FPM_INTEL, so asking for the portable 64-bit multiply
 * here wins without patching the header.  It only affects code inlined into
 * this file; the library itself is built by its own Makefile.
 */

#define FPM_64BIT
#include <mad.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* The window kept on the bitstream.
 *
 * libmad hands back a pointer into this buffer when it runs out part way
 * through a frame, and the leftover has to be moved down and topped up
 * rather than discarded.  It only has to exceed the largest frame, which
 * for MPEG-1 Layer III at 320 kbit/s is 1441 bytes.
 */

#define MP3PLAY_INBUF     8192

/* Frames in one decoded MPEG granule pair.  1152 for Layer III, and the
 * most any layer produces, so one of these always holds a whole frame.
 */

#define MP3PLAY_MAXFRAMES 1152

#define MP3PLAY_MAXCHAN   2

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct mp3play_s
{
  struct nxaudio_s  nxaudio;

  int               fd;
  bool              eof;              /* The file has been read to the end */
  bool              done;             /* Decoding has finished */
  bool              running;
  bool              inited;           /* The audio device is open */

  struct mad_stream stream;
  struct mad_frame  frame;
  struct mad_synth  synth;

  unsigned int      chnum;            /* Channels being played */
  unsigned int      samprate;

  /* One decoded frame, interleaved and scaled, waiting to be handed out in
   * whatever sized pieces the audio buffers ask for.
   */

  int16_t           pcm[MP3PLAY_MAXFRAMES * MP3PLAY_MAXCHAN];
  unsigned int      pcmframes;
  unsigned int      pcmpos;

  /* Measurement.  The point of this program is partly to find out whether
   * a 150 MHz M33 can decode at full rate at all.
   */

  uint32_t          mp3frames;
  uint64_t          decodeus;
  uint64_t          outframes;

  uint8_t           inbuf[MP3PLAY_INBUF + MAD_BUFFER_GUARD];
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static void mp3play_interleave(FAR struct mp3play_s *priv);
static void mp3play_dequeue_cb(unsigned long arg,
                               FAR struct ap_buffer_s *apb);
static void mp3play_complete_cb(unsigned long arg);
static void mp3play_user_cb(unsigned long arg,
                            FAR struct audio_msg_s *msg,
                            FAR bool *running);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static struct nxaudio_callbacks_s g_mp3play_cbs =
{
  mp3play_dequeue_cb,
  mp3play_complete_cb,
  mp3play_user_cb
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: mp3play_now_us
 ****************************************************************************/

static uint64_t mp3play_now_us(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000ull + ts.tv_nsec / 1000;
}

/****************************************************************************
 * Name: mp3play_scale
 *
 * Description:
 *   Round and clip one of libmad's 28-bit fractional samples down to the
 *   16 bits the audio device wants.
 *
 ****************************************************************************/

static inline int16_t mp3play_scale(mad_fixed_t sample)
{
  /* Round rather than truncate:  truncation is a half-LSB DC offset, and
   * on a PWM output that is a click at every start and stop.
   */

  sample += (1L << (MAD_F_FRACBITS - 16));

  if (sample >= MAD_F_ONE)
    {
      sample = MAD_F_ONE - 1;
    }
  else if (sample < -MAD_F_ONE)
    {
      sample = -MAD_F_ONE;
    }

  return (int16_t)(sample >> (MAD_F_FRACBITS + 1 - 16));
}

/****************************************************************************
 * Name: mp3play_refill
 *
 * Description:
 *   Top the bitstream window up, preserving whatever libmad has not yet
 *   consumed.
 *
 * Returned Value:
 *   true if there is anything left to decode.
 *
 ****************************************************************************/

static bool mp3play_refill(FAR struct mp3play_s *priv)
{
  size_t keep = 0;
  ssize_t nread;

  if (priv->eof)
    {
      /* The guard bytes have already been fed; there is nothing more */

      return false;
    }

  if (priv->stream.next_frame != NULL)
    {
      keep = priv->stream.bufend - priv->stream.next_frame;
      memmove(priv->inbuf, priv->stream.next_frame, keep);
    }

  nread = read(priv->fd, priv->inbuf + keep, MP3PLAY_INBUF - keep);
  if (nread < 0)
    {
      fprintf(stderr, "mp3play: read failed: %d\n", errno);
      priv->eof = true;
      return false;
    }

  if (nread == 0)
    {
      /* libmad needs MAD_BUFFER_GUARD zero bytes past the end of the last
       * frame before it will decode it, or the file loses its final frame.
       */

      memset(priv->inbuf + keep, 0, MAD_BUFFER_GUARD);
      nread = MAD_BUFFER_GUARD;
      priv->eof = true;
    }

  mad_stream_buffer(&priv->stream, priv->inbuf, keep + nread);
  return true;
}

/****************************************************************************
 * Name: mp3play_decode
 *
 * Description:
 *   Decode the next frame into priv->pcm.
 *
 * Returned Value:
 *   true if a frame was produced.
 *
 ****************************************************************************/

static bool mp3play_decode(FAR struct mp3play_s *priv)
{
  uint64_t started = mp3play_now_us();

  for (; ; )
    {
      if (priv->stream.buffer == NULL ||
          priv->stream.error == MAD_ERROR_BUFLEN)
        {
          if (!mp3play_refill(priv))
            {
              return false;
            }
        }

      if (mad_frame_decode(&priv->frame, &priv->stream) != 0)
        {
          if (priv->stream.error == MAD_ERROR_BUFLEN)
            {
              /* Part of a frame; go round and fetch the rest */

              continue;
            }

          if (MAD_RECOVERABLE(priv->stream.error))
            {
              /* A bad frame.  ID3 tags land here too, which is why this is
               * not worth reporting:  most files start with one.
               */

              continue;
            }

          return false;
        }

      break;
    }

  mad_synth_frame(&priv->synth, &priv->frame);

  priv->mp3frames++;
  priv->decodeus += mp3play_now_us() - started;

  mp3play_interleave(priv);
  return true;
}

/****************************************************************************
 * Name: mp3play_interleave
 *
 * Description:
 *   Lay the decoded frame out as interleaved 16-bit samples.
 *
 *   Kept apart from decoding because the channel count is not known until
 *   the first frame has been decoded, and that frame is played rather than
 *   thrown away:  it is laid out once the count is known.
 *
 ****************************************************************************/

static void mp3play_interleave(FAR struct mp3play_s *priv)
{
  unsigned int i;

  priv->pcmframes = priv->synth.pcm.length;
  priv->pcmpos    = 0;

  if (priv->chnum == 2)
    {
      FAR const mad_fixed_t *left  = priv->synth.pcm.samples[0];
      FAR const mad_fixed_t *right =
        priv->synth.pcm.channels > 1 ? priv->synth.pcm.samples[1]
                                     : priv->synth.pcm.samples[0];

      for (i = 0; i < priv->pcmframes; i++)
        {
          priv->pcm[2 * i]     = mp3play_scale(left[i]);
          priv->pcm[2 * i + 1] = mp3play_scale(right[i]);
        }
    }
  else
    {
      FAR const mad_fixed_t *mono = priv->synth.pcm.samples[0];

      for (i = 0; i < priv->pcmframes; i++)
        {
          priv->pcm[i] = mp3play_scale(mono[i]);
        }
    }
}

/****************************************************************************
 * Name: mp3play_fill
 *
 * Description:
 *   Fill one audio buffer from the decoder, marking it final when the
 *   stream runs out.
 *
 ****************************************************************************/

static unsigned int mp3play_fill(FAR struct mp3play_s *priv,
                                 FAR struct ap_buffer_s *apb)
{
  FAR int16_t *out = (FAR int16_t *)apb->samp;
  unsigned int cap = apb->nmaxbytes / sizeof(int16_t);
  unsigned int n   = 0;

  /* Keep the buffer a whole number of frames, so a partly written frame
   * never splits a stereo pair across two buffers.
   */

  cap -= cap % priv->chnum;

  while (n < cap)
    {
      unsigned int avail;
      unsigned int take;

      if (priv->pcmpos >= priv->pcmframes)
        {
          if (!mp3play_decode(priv))
            {
              priv->done = true;
              break;
            }
        }

      avail = (priv->pcmframes - priv->pcmpos) * priv->chnum;
      take  = cap - n;
      if (take > avail)
        {
          take = avail;
        }

      memcpy(out + n, priv->pcm + priv->pcmpos * priv->chnum,
             take * sizeof(int16_t));

      n            += take;
      priv->pcmpos += take / priv->chnum;
    }

  apb->curbyte = 0;
  apb->nbytes  = n * sizeof(int16_t);
  apb->flags   = priv->done ? AUDIO_APB_FINAL : 0;

  priv->outframes += n / priv->chnum;
  return n;
}

/****************************************************************************
 * Name: mp3play_dequeue_cb
 *
 * Description:
 *   A buffer has been played.  Decode into it and hand it straight back.
 *
 ****************************************************************************/

static void mp3play_dequeue_cb(unsigned long arg,
                               FAR struct ap_buffer_s *apb)
{
  FAR struct mp3play_s *priv = (FAR struct mp3play_s *)(uintptr_t)arg;

  if (!priv->running || priv->done)
    {
      return;
    }

  if (mp3play_fill(priv, apb) > 0)
    {
      nxaudio_enqbuffer(&priv->nxaudio, apb);
    }
}

/****************************************************************************
 * Name: mp3play_complete_cb
 ****************************************************************************/

static void mp3play_complete_cb(unsigned long arg)
{
  FAR struct mp3play_s *priv = (FAR struct mp3play_s *)(uintptr_t)arg;

  priv->running = false;

  /* Completion alone does not end nxaudio_msgloop() -- only AUDIO_MSG_STOP
   * does, and nxaudio_stop() is what posts it.  Without this the player
   * decodes the whole file and then waits on the queue forever.
   */

  nxaudio_stop(&priv->nxaudio);
}

/****************************************************************************
 * Name: mp3play_user_cb
 ****************************************************************************/

static void mp3play_user_cb(unsigned long arg,
                            FAR struct audio_msg_s *msg,
                            FAR bool *running)
{
}

/****************************************************************************
 * Name: mp3play_audio_thread
 ****************************************************************************/

/****************************************************************************
 * Name: mp3play_audio_thread
 *
 * Description:
 *   Everything that touches libmad, from the first frame to the last.
 *
 *   All of it belongs on this one thread because layer III decoding is
 *   stack-hungry -- III_reorder() alone puts a 2304-byte array on the stack
 *   -- and this is the only thread given a stack sized for it.  Decoding
 *   the first frame on the caller's stack instead, merely to learn the
 *   sample rate, silently overran a default 2 KB task stack and took the
 *   whole board down with it.
 *
 ****************************************************************************/

static FAR void *mp3play_audio_thread(pthread_addr_t arg)
{
  FAR struct mp3play_s *priv = (FAR struct mp3play_s *)arg;
  int i;

  /* The sample rate and channel count are properties of the bitstream, so
   * the first frame has to be decoded before the device can be configured.
   * That frame is kept and played, not thrown away.
   */

  priv->chnum = 1;
  if (!mp3play_decode(priv))
    {
      fprintf(stderr, "mp3play: no decodable frame\n");
      return NULL;
    }

  priv->samprate = priv->frame.header.samplerate;
  priv->chnum    = MAD_NCHANNELS(&priv->frame.header);

  /* That first frame was laid out as mono, because the channel count was
   * not known until it had been decoded.  Lay it out again rather than
   * discard it, so playback starts at the beginning of the file.
   */

  mp3play_interleave(priv);

  printf("mp3play: %u Hz, %u channel%s\n", priv->samprate, priv->chnum,
         priv->chnum > 1 ? "s" : "");
  fflush(stdout);

  if (init_nxaudio_devname(&priv->nxaudio, priv->samprate, 16, priv->chnum,
                           CONFIG_AUDIOUTILS_NXAUDIO_DEVPATH,
                           "/tmp/mp3play_mq") < 0)
    {
      fprintf(stderr, "mp3play: cannot open %s at %u Hz\n",
              CONFIG_AUDIOUTILS_NXAUDIO_DEVPATH, priv->samprate);
      return NULL;
    }

  priv->inited  = true;
  priv->running = true;

  /* Fill the pipeline before starting, so the device is not chasing the
   * decoder from the very first buffer.
   */

  for (i = 0; i < priv->nxaudio.abufnum; i++)
    {
      if (mp3play_fill(priv, priv->nxaudio.abufs[i]) == 0)
        {
          break;
        }

      nxaudio_enqbuffer(&priv->nxaudio, priv->nxaudio.abufs[i]);
    }

  nxaudio_start(&priv->nxaudio);
  nxaudio_msgloop(&priv->nxaudio, &g_mp3play_cbs,
                  (unsigned long)(uintptr_t)priv);

  return NULL;
}

/****************************************************************************
 * Name: mp3play_report
 ****************************************************************************/

static void mp3play_report(FAR struct mp3play_s *priv)
{
  uint64_t audious;

  if (priv->mp3frames == 0)
    {
      printf("mp3play: nothing decoded\n");
      return;
    }

  /* How much time the decoder spent against how much sound it produced.
   * Over 100%% cannot play at full rate, whatever the buffering.
   */

  audious = priv->outframes * 1000000ull / priv->samprate;

  printf("mp3play: %" PRIu32 " frames, %llu ms of audio\n",
         priv->mp3frames, (unsigned long long)(audious / 1000));
  printf("mp3play: decode %llu ms = %llu%% of realtime, %llu us/frame\n",
         (unsigned long long)(priv->decodeus / 1000),
         (unsigned long long)(audious ? priv->decodeus * 100 / audious : 0),
         (unsigned long long)(priv->decodeus / priv->mp3frames));
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  FAR struct mp3play_s *priv;
  pthread_t tid;
  pthread_attr_t tattr;
  struct sched_param sparam;
  int ret = EXIT_FAILURE;

  if (argc != 2)
    {
      fprintf(stderr, "Usage: %s <file.mp3>\n", argv[0]);
      return EXIT_FAILURE;
    }

  /* libmad's frame and synth structures are tens of kilobytes between them,
   * which is too much for a task stack here.
   */

  priv = (FAR struct mp3play_s *)calloc(1, sizeof(struct mp3play_s));
  if (priv == NULL)
    {
      fprintf(stderr, "mp3play: out of memory (%zu bytes wanted)\n",
              sizeof(struct mp3play_s));
      return EXIT_FAILURE;
    }

  priv->fd = open(argv[1], O_RDONLY);
  if (priv->fd < 0)
    {
      fprintf(stderr, "mp3play: cannot open %s: %d\n", argv[1], errno);
      goto errout_free;
    }

  mad_stream_init(&priv->stream);
  mad_frame_init(&priv->frame);
  mad_synth_init(&priv->synth);

  printf("mp3play: %s\n", argv[1]);

  pthread_attr_init(&tattr);
  sparam.sched_priority = sched_get_priority_max(SCHED_FIFO) - 9;
  pthread_attr_setschedparam(&tattr, &sparam);
  pthread_attr_setstacksize(&tattr, CONFIG_SYSTEM_MP3PLAY_DECODESTACK);

  if (pthread_create(&tid, &tattr, mp3play_audio_thread,
                     (pthread_addr_t)priv) != 0)
    {
      fprintf(stderr, "mp3play: cannot start the audio thread\n");
      goto errout_close;
    }

  pthread_setname_np(tid, "mp3play");
  pthread_join(tid, NULL);

  if (priv->inited)
    {
      mp3play_report(priv);
      fin_nxaudio(&priv->nxaudio);
      ret = EXIT_SUCCESS;
    }

errout_close:
  mad_synth_finish(&priv->synth);
  mad_frame_finish(&priv->frame);
  mad_stream_finish(&priv->stream);
  close(priv->fd);

errout_free:
  free(priv);
  return ret;
}
