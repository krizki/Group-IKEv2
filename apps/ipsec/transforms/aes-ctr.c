/*
 * Copyright (c) 2015, SICS
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
 *         AES-CTR block cipher mode of operation (RFC 3686)
 * \brief
 *				 Only 128 bit key sizes supported at this time
 * \author
 *         Simon Duquennoy <simonduq@sics.se>
 *				 Vilhelm Jutvik <ville@imorgon.se>, adapted for IKEv2
 *
 *
 */
/**
 * \addtogroup ipsec
 * @{
 */

#include <stdlib.h>
#include <string.h>
#include "sa.h"
#include "net/ip/uip.h"
#include "encr.h"
#include "ipsec.h"
#include "transforms/aes-moo.h"

#define AESCTR_NONCESIZE 4
#define AESCTR_BLOCKSIZE 16
#define AESCTR_IVSIZE 8 /* Same as in sa_encr_ivlen[encr_data->type] */

/*---------------------------------------------------------------------------*/
static void
aes_ctr_init(uint8_t *ctr_blk, const uint8_t *key,
             const uint8_t *iv, const uint8_t *nonce)
{
  /* Set key */
  CRYPTO_AES.init(key);
  /* Initialize counter block */
  memcpy(ctr_blk, nonce, AESCTR_NONCESIZE);
  memcpy(ctr_blk + AESCTR_NONCESIZE, iv, AESCTR_IVSIZE);

  /* Null counter */
  memset(ctr_blk + AESCTR_NONCESIZE + AESCTR_IVSIZE, 0, 4);
}
/*---------------------------------------------------------------------------*/
static void
aes_ctr_step(uint8_t *ctr_blk, uint8_t *data, uint16_t ctr, int len)
{
  /* Set the counter in ctr_blk */
  ctr = uip_htons(ctr);
  memcpy(ctr_blk + AESCTR_NONCESIZE + AESCTR_IVSIZE + 2, &ctr, sizeof(ctr));

  /* tmp = ctr_blk */
  uint8_t tmp[AESCTR_BLOCKSIZE];
  memcpy(tmp, ctr_blk, AESCTR_BLOCKSIZE);

  /* AES encrypt tmp */
  CRYPTO_AES.encrypt(tmp);

  /* buff ^= tmp */
  int i;
  for(i = 0; i < len; i++) {
    data[i] ^= tmp[i];
  }
}
/*---------------------------------------------------------------------------*/
/**
 * Encrypts and decrypts the data with AES-CTR mode.
 * @param encr_data
 */
/*---------------------------------------------------------------------------*/
void
aes_ctr(encr_data_t *encr_data)
{
  uint8_t ctr_blk[AESCTR_BLOCKSIZE];

  uint8_t *data = encr_data->encr_data + AESCTR_IVSIZE;
  uint16_t datalen = encr_data->encr_datalen - AESCTR_IVSIZE;

  /* Initialize the counter block and set the key */
  aes_ctr_init(ctr_blk, encr_data->keymat, encr_data->encr_data, &encr_data->keymat[encr_data->keylen]);

  uint16_t n = 0;
  for(n = 0; n *AESCTR_BLOCKSIZE < datalen; ++n) {
    uint8_t len = AESCTR_BLOCKSIZE;
    if((n + 1) * AESCTR_BLOCKSIZE > datalen) {
      len = len - ((n + 1) * AESCTR_BLOCKSIZE - datalen);
    }
    aes_ctr_step(ctr_blk, &data[n * AESCTR_BLOCKSIZE], n + 1, len);
  }
}
/** @} */