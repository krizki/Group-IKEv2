/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    Wrapper for calls to integrity transforms
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se> - added HMAC-SHA256
 *
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

#include "integ.h"
#include "ipsec.h"
#include "hmac-sha256.h"
#include "hmac-sha1.h"

extern void aes_xcbc(integ_data_t *data);

void
integ(integ_data_t *data)
{
  uint8_t type = data->type;
  uint8_t icvlength = SA_INTEG_ICV_LEN_BY_TYPE(type);
  hmac_data_t hmac;
  uint8_t tmp_sha[32];

  switch(type) {
  case SA_INTEG_HMAC_SHA1_96:           /* MUST         MUST          IMPLEMENTED */
    hmac.data = data->data;
    hmac.datalen = data->datalen;
    hmac.key = data->keymat;
    hmac.out = tmp_sha;
    hmac.keylen = 20;
    hmac_sha1(&hmac);
    /* Truncate the output to 96 bits*/
    memcpy(data->out, hmac.out, icvlength);
    break;
  case SA_INTEG_AES_XCBC_MAC_96:            /* SHOULD+      SHOULD+       IMPLEMENTED */
    aes_xcbc(data);
    break;
  case SA_INTEG_HMAC_SHA2_256_128:
    hmac.data = data->data;
    hmac.datalen = data->datalen;
    hmac.key = data->keymat;
    hmac.out = tmp_sha;
    hmac.keylen = 32;
    hmac_sha256(&hmac);
    /* Truncate the output to 128 bits*/
    memcpy(data->out, hmac.out, icvlength);

    break;
  default:
    IPSEC_PRINTF(IPSEC "Error: Integrity transform not supported\n");
    /* SA_INTEG_HMAC_MD5_95 = 1,          // MAY          MAY           NOT IMPLEMENTED */
  }
}
/** @} */
