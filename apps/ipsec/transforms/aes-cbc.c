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
 *         AES-CBC block cipher mode of operation (RFC 3602)
 * \brief
 *				 Only 128 bit key sizes supported at this time
 * \author
 *         Runar Mar Magnusson <rmma@kth.se>
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

#define AESCBC_BLOCKSIZE 16
#define AESCBC_IVSIZE 16

#define CBC_DEBUG 0
#if CBC_DEBUG
#include <stdio.h>
#include "common-ipsec.h"
#define PRINTF(...) printf(__VA_ARGS__)
#define MEMPRINT(...) memprint(__VA_ARGS__)
#define HEXDUMP(...) hexdump(__VA_ARGS__)
#else
#define PRINTF(...)
#define MEMPRINT(...)
#define HEXDUMP(...)
#endif

/*---------------------------------------------------------------------------*/
static void
aes_cbc_init(uint8_t *xor_blk, const uint8_t *key, const uint8_t *iv)
{
  /* Set key */
  CRYPTO_AES.init(key);

  /* Initialize xor block */
  memcpy(xor_blk, iv, AESCBC_IVSIZE);
}
/*---------------------------------------------------------------------------*/
/**
 * Encrypts the data specified in encr_data with AES-CBC.
 * NOTE: The length of the data must be a multiple of 16
 * @param encr_data
 */
/*---------------------------------------------------------------------------*/
void
aes_cbc_encrypt(encr_data_t *encr_data)
{
  PRINTF("CBC ENCRYPT\n");
  uint8_t xor_blk[AESCBC_BLOCKSIZE];

  uint8_t *data = encr_data->encr_data + AESCBC_IVSIZE;
  uint16_t datalen = encr_data->encr_datalen - AESCBC_IVSIZE;

  PRINTF("Data before encrypt, %u\n", encr_data->encr_datalen);
  HEXDUMP(encr_data->encr_data, encr_data->encr_datalen);

  /* Initialize the XOR block with the IV */
  aes_cbc_init(xor_blk, encr_data->keymat, encr_data->encr_data);

  uint16_t blocks = datalen / AESCBC_BLOCKSIZE; /* datalen is a multiple of 16 */

  uint16_t n, j;
  for(n = 0; n < blocks; n++) {
    for(j = 0; j < AESCBC_BLOCKSIZE; j++) {
      xor_blk[j] ^= data[j];
    }
    CRYPTO_AES.encrypt(xor_blk);
    memcpy(data, xor_blk, AESCBC_BLOCKSIZE);
    data += AESCBC_BLOCKSIZE;
  }

  PRINTF("Data after encrypt, %u\n", encr_data->encr_datalen);
  HEXDUMP(encr_data->encr_data, encr_data->encr_datalen);
}
/*---------------------------------------------------------------------------*/
/**
 * Decrypts the data specified in encr_data with AES-CBC.
 *
 * NOTE: The length of the data must be a multiple of 16,
 * This function can only be used with the CC2538 hardware module because
 * Contiki does not have a built in aes-decrypt function only aes-encrypt
 * @param encr_data
 */
/*---------------------------------------------------------------------------*/
void
aes_cbc_decrypt(encr_data_t *encr_data)
{
  PRINTF("CBC DECRYPT\n");

  uint8_t xor_blk[AESCBC_BLOCKSIZE], tmp[AESCBC_BLOCKSIZE];

  uint8_t *data = encr_data->encr_data + AESCBC_IVSIZE;
  uint16_t datalen = encr_data->encr_datalen - AESCBC_IVSIZE;

  PRINTF("Data before decrypt, %u\n", datalen);
  HEXDUMP(encr_data->encr_data, encr_data->encr_datalen);

  /* Initialize the XOR block with the IV */
  aes_cbc_init(xor_blk, encr_data->keymat, encr_data->encr_data);

  uint16_t blocks = datalen / AESCBC_BLOCKSIZE; /* datalen is a multiple of 16 */

  uint16_t n, j;
  for(n = 0; n < blocks; n++) {
    memcpy(tmp, data, AESCBC_BLOCKSIZE);
    CRYPTO_AES.decrypt(data);
    for(j = 0; j < AESCBC_BLOCKSIZE; j++) {
      data[j] ^= xor_blk[j];
    }
    memcpy(xor_blk, tmp, AESCBC_BLOCKSIZE);
    data += AESCBC_BLOCKSIZE;
  }
  PRINTF("Data after decrypt, %u\n", encr_data->encr_datalen);
  HEXDUMP(encr_data->encr_data, encr_data->encr_datalen);
}
/** @} */