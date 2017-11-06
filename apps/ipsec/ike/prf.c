/**
 * \addtogroup ipsec
 * @{
 */
/*
 * Copyright (c) 2012, Vilhelm Jutvik.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */
/**
 * \file
 *    Implementations of pseudorandom functions for IKEv2 as described in RFC 5996
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se> - Removed
 */

#include "lib/random.h"

#include "string.h"
#include "contiki-conf.h"
#include "prf.h"
#include "machine.h"
#include "transforms/hmac-sha1.h"
#include "transforms/hmac-sha256.h"

/*---------------------------------------------------------------------------*/
void
random_ike(uint8_t *out, uint16_t len)
{

  uint8_t *ptr;
  for(ptr = out; ptr < out + len; ++ptr) {
    *ptr = (uint8_t)random_rand();
  }
}
/*---------------------------------------------------------------------------*/
void
prf(sa_prf_transform_type_t prf_type, prf_data_t *prf_data)
{
  switch(prf_type) {
  case SA_PRF_HMAC_SHA1:           /* MUST */
    hmac_sha1(prf_data);
    break;
  case SA_PRF_AES128_CBC:        /* SHOULD+ */
    IPSEC_PRINTF(IPSEC "Error: Not implemented\n");
    break;
  case SA_PRF_HMAC_SHA2_256:
    hmac_sha256(prf_data);
    break;
  default:
    IPSEC_PRINTF(IPSEC "Error: Unknown PRF request\n");
  }
}
/*---------------------------------------------------------------------------*/
void
prf_plus(prfplus_data_t *plus_data)
{
  const uint8_t prf_outputlen = sa_prf_output_len[plus_data->prf];

  /* Loop over chunks_len and find the longest chunk */
  uint16_t chunk_maxlen = 0;
  uint16_t i;
  for(i = 0; i < plus_data->no_chunks; ++i) {
    if(plus_data->chunks_len[i] > chunk_maxlen) {
      chunk_maxlen = plus_data->chunks_len[i];
      /* Set up the buffers */
    }
  }
  uint16_t outbuf_maxlen = chunk_maxlen + prf_outputlen;
  uint16_t msgbuf_maxlen = prf_outputlen + plus_data->datalen + 1;   /* Maximum length of TN + S + 0xNN */
  uint8_t outbuf[outbuf_maxlen];   /* The buffer for intermediate storage of the output from the PRF. To be copied into the chunks. */
  uint8_t msgbuf[msgbuf_maxlen];   /* Assembly buffer for the message */
  uint8_t lastout[prf_outputlen];

  /* Loop over the chunks */
  prf_data_t prf_data = {
    .key = plus_data->key,
    .keylen = plus_data->keylen,
    .data = msgbuf
  };
  uint8_t outbuf_len = 0;
  uint8_t prf_ctr = 1;
  uint8_t curr_chunk;
  for(curr_chunk = 0; curr_chunk < plus_data->no_chunks; ++curr_chunk) {
    uint8_t curr_chunk_len = plus_data->chunks_len[curr_chunk];

    /* Now, how much PRF output data do we need for this chunk? Generate more data if we don't have enough . */
    if(curr_chunk_len > outbuf_len) {
      /* We need more data in the output buffer */
      for(; outbuf_len < curr_chunk_len; outbuf_len += prf_outputlen, ++prf_ctr) {

        /* Compose the message */
        uint8_t *ptr = msgbuf;
        if(prf_ctr > 1) {
          /* The message is T(N - 1) | S | 0xN where N is ptr_ctr */
          memcpy(ptr, lastout, prf_outputlen); /* Copy TN (the last PRF output) */
          ptr += prf_outputlen;
        }
        memcpy(ptr, plus_data->data, plus_data->datalen);   /* Add S */

        ptr += plus_data->datalen;
        *ptr = prf_ctr;                                     /* Add 0xN */
        ++ptr;

        /* Message compiled. Run the PRF operation. */
        prf_data.out = &outbuf[outbuf_len];
        prf_data.datalen = ptr - msgbuf;
        prf(plus_data->prf, &prf_data);
        memcpy(lastout, &outbuf[outbuf_len], prf_outputlen); /* Take a copy of this output for use as the next TN string */
      }
      /* We have exited the loop and... given the complexity of the above loop... */
    }
    /* ... we can surmise that outbuf contains enough data to fill plus_data->chunks_len[curr_chunk] */
    memcpy(plus_data->chunks[curr_chunk], outbuf, curr_chunk_len); /* Copy the data to the chunk */

    /* We have probably left some trailing data in the buffer. Move it to the beginning so as to save it for the next chunk. */
    outbuf_len = outbuf_len - curr_chunk_len;
    memmove(outbuf, &outbuf[curr_chunk_len], outbuf_len);
  }
}
/** @} */