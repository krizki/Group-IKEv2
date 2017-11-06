/**
 * \addtogroup ipsec
 * @{
 */

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
 *      Mapping the CC2538 hardware crypto module to the generic aes_implem
 *      interface
 * \author
 *      Runar Mar Magnusson <rmma@kth.se>
 *
 * Created on April 21, 2015, 9:36 PM
 */

#ifdef HW_AES
#include "ipsec.h"
#include "aes-moo.h"
#include "cpu/cc2538/dev/crypto.h"
#include "cpu/cc2538/dev/aes.h"

#define AES_ECB_BLOCK_LEN 16

#define AES_ECB_DBG_PRINT 0

#define KEY_AREA 0

#if AES_ECB_DBG_PRINT
#include <stdio.h>
#include "common_ipsec.h"
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
aes_init(uint8_t *key)
{
  PRINTF("Enabling the cryptoprocessor\n");
  crypto_enable();

  /* Initialize  the key variables */
  uint8_t aes_status = 0;

  PRINTF("KEY %u\n", AES_ECB_BLOCK_LEN);
  HEXDUMP(key, AES_ECB_BLOCK_LEN);

  PRINTF("Loading key\n");
  aes_status = aes_load_keys((const void *)key, AES_KEY_STORE_SIZE_KEY_SIZE_128, 1, KEY_AREA);

  if(aes_status == AES_SUCCESS) {
    PRINTF("AES-ECB Loaded key successfully\n");
  } else {
    PRINTF("AES-ECB ERROR CODE %u", aes_status);
  }
}
/*---------------------------------------------------------------------------*/
static void
aes_encrypt(uint8_t *buff)
{
  PRINTF("IN aes_encrypt \n");

  /* Enable the crypto processor */
  PRINTF("Enabling the cryptoprocessor\n");
  crypto_enable();

  /* Run the AES-ECB operation */
  uint8_t result[AES_ECB_BLOCK_LEN];
  uint8_t aes_status = 0;
  memset(result, 0, AES_ECB_BLOCK_LEN);

  PRINTF("Buffer before encrypt %u\n", AES_ECB_BLOCK_LEN);
  HEXDUMP(buff, AES_ECB_BLOCK_LEN);

  PRINTF("Result before encrypt %u\n", AES_ECB_BLOCK_LEN);
  HEXDUMP(result, AES_ECB_BLOCK_LEN);

  aes_status = aes_ecb_start((const void *)buff, (const void *)result, KEY_AREA, 1, NULL);

  if(aes_status == AES_SUCCESS) {
    PRINTF("AES-ECB started\n");
    while(!aes_ecb_check_status()) ;

    aes_status = aes_ecb_get_result();

    if(aes_status == AES_SUCCESS) {
      PRINTF("AES-ECB ended without error\n");

      PRINTF("Buffer after encrypt %u\n", AES_ECB_BLOCK_LEN);
      HEXDUMP(buff, AES_ECB_BLOCK_LEN);

      PRINTF("Result after encrypt %u\n", AES_ECB_BLOCK_LEN);
      HEXDUMP(result, AES_ECB_BLOCK_LEN);

      memcpy(buff, result, AES_ECB_BLOCK_LEN);

      PRINTF("Final state of buffer %u\n", AES_ECB_BLOCK_LEN);
      HEXDUMP(buff, AES_ECB_BLOCK_LEN);
    } else {
      PRINTF("AES-ECB ERROR in get result %u\n", aes_status);
    }
  } else {
    PRINTF("AES-ECB ERROR in start %u\n", aes_status);
  }
  
  /* Disable the crypto processor */
  PRINTF("Disabling the cryptoprocessor\n");
  crypto_disable();
}
/*---------------------------------------------------------------------------*/
static void
aes_decrypt(uint8_t *buff)
{
  PRINTF("In aes_decrypt \n");

  /* Enable the crypto processor */
  PRINTF("Enabling the cryptoprocessor\n");
  crypto_enable();

  /* Run the AES-ECB operation */
  uint8_t result[AES_ECB_BLOCK_LEN];
  uint8_t aes_status = 0;
  memset(result, 0, AES_ECB_BLOCK_LEN);

  PRINTF("Buffer before decrypt %u\n", AES_ECB_BLOCK_LEN);
  HEXDUMP(buff, AES_ECB_BLOCK_LEN);

  PRINTF("Result before decrypt %u\n", AES_ECB_BLOCK_LEN);
  HEXDUMP(result, AES_ECB_BLOCK_LEN);

  aes_status = aes_ecb_start((const void *)buff, (const void *)result, KEY_AREA, 0, NULL);

  if(aes_status == AES_SUCCESS) {
    PRINTF("AES-ECB started\n");
    while(!aes_ecb_check_status()) ;

    aes_status = aes_ecb_get_result();

    if(aes_status == AES_SUCCESS) {
      PRINTF("AES-ECB ended without error\n");

      PRINTF("Buffer after decrypt %u\n", AES_ECB_BLOCK_LEN);
      HEXDUMP(buff, AES_ECB_BLOCK_LEN);

      PRINTF("Result after decrypt %u\n", AES_ECB_BLOCK_LEN);
      HEXDUMP(result, AES_ECB_BLOCK_LEN);

      memcpy(buff, result, AES_ECB_BLOCK_LEN);

      PRINTF("Final state of buffer %u\n", AES_ECB_BLOCK_LEN);
      HEXDUMP(buff, AES_ECB_BLOCK_LEN);
    } else {
      PRINTF("AES-ECB ERROR in get result %u\n", aes_status);
    }
  } else {
    PRINTF("AES-ECB ERROR in start %u\n", aes_status);
  }
  
  /* Disable the crypto processor */
  PRINTF("Disabling the cryptoprocessor\n");
  crypto_disable();
}
/*---------------------------------------------------------------------------*/
struct aes_implem cc2538_aes = {
  aes_init,
  aes_encrypt,
  aes_decrypt,
};
/*---------------------------------------------------------------------------*/
#endif
/** @} */