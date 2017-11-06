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
 *         AES-CCM block cipher mode of operation (RFC 4309)
 * \brief
 *				 Only 128 bit key sizes supported at this time
 * \author
 *         Runar Mar Magnusson <rmma@kth.se>
 *
 *
 */
/**
 * \addtogroup ipsec
 * @{
 */

#include "aes-ccm.h"
#include "encr.h"
#include "ipsec-ccm.h"

#include "aes-128.h"
#include "aes-moo.h"

#ifdef HW_CCM
#include "cpu/cc2538/dev/crypto.h"
#include "cpu/cc2538/dev/ccm.h"
#endif

#define CCM_DBG_PRINT 0

#if CCM_DBG_PRINT
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

void
ipsec_aes_ccm_encrypt(encr_data_t *encr_data, uint8_t miclength)
{
#ifdef HW_CCM
  PRINTF("Using hardware cryptoprocessor\n");
  PRINTF("Enabling cryptoprocessor for AES-CCM\n");
  /* crypto_init(); */
  crypto_enable();

  /* Initialize  the key variables */
  uint8_t aes_status = 0;
  uint8_t key_area;
  key_area = 0;

  PRINTF("Loading keys\n");
  aes_status = aes_load_keys((const void *)encr_data->keymat, AES_KEY_STORE_SIZE_KEY_SIZE_128, 1, key_area);

  if(aes_status == AES_SUCCESS) {
    PRINTF("Loading keys successful\n");

    /* Plaintext variables */
    unsigned char *pdata = encr_data->encr_data + CCM_IV_LEN;
    uint16_t pdata_len;
    pdata_len = encr_data->encr_datalen - CCM_IV_LEN;

    PRINTF("Plaintext message length: %u\n", pdata_len);
    HEXDUMP(pdata, pdata_len);

    /* Calculate the length of the associated data from the ESP header*/
    uint16_t adata_len;
    adata_len = (encr_data->encr_data - encr_data->integ_data);

    PRINTF("Associated data length: %u\n", adata_len);
    HEXDUMP(encr_data->integ_data, adata_len);

    /* Create the nonce for AES-CCM, salt + IV (11 bytes)*/
    uint8_t nonce[CCM_NONCE];
    memcpy(nonce, &encr_data->keymat[encr_data->keylen], CCM_SALT_LEN);
    memcpy(nonce + CCM_SALT_LEN, encr_data->encr_data, CCM_IV_LEN);

    PRINTF("Nonce length: %u\n", CCM_NONCE);
    HEXDUMP(nonce, CCM_NONCE);

    aes_status = ccm_auth_encrypt_start(IPSEC_L_SIZELEN, key_area,
                                        nonce, encr_data->integ_data, adata_len,
                                        pdata, pdata_len, miclength, NULL);

    if(aes_status == AES_SUCCESS) {
      PRINTF("Encryption started\n");
      /* Wait for the operation to finish*/
      while(!ccm_auth_encrypt_check_status()) ;

      /* Find the location of the ICV*/
      unsigned char *mic = encr_data->encr_data + encr_data->encr_datalen;

      aes_status = ccm_auth_encrypt_get_result(mic, miclength);
      PRINTF("AES STATUS get result %u \n", aes_status);
      if(aes_status == AES_SUCCESS) {
        PRINTF("Encryption ended without error\n");

        PRINTF("Encrypted message length: %u\n", pdata_len);
        HEXDUMP(pdata, pdata_len);

        PRINTF("ICV length %u\n", miclength);
        HEXDUMP(mic, miclength);
      } else {
        printf("ERROR: Could not get result from encryption, AES STATUS %u\n", aes_status);
      }
    } else {
      printf("ERROR: Could not start encryption, AES STATUS %u\n", aes_status);
    }
  } else {
    printf("ERROR: Could not load key for AES-CCM, AES STATUS %u\n", aes_status);
  }
  PRINTF("Disabling the Cryptoprocessor\n");
  crypto_disable();
#else
  int result = 0;

  /* Calculate lengths */
  uint16_t total_len, adata_len, pdata_len;
  adata_len = (encr_data->encr_data - encr_data->integ_data);
  pdata_len = encr_data->encr_datalen - CCM_IV_LEN;
  total_len = encr_data->encr_datalen + adata_len + miclength - CCM_IV_LEN;

  /* Initialize the output buffer */
  uint8_t tmp_output[total_len];
  memset(tmp_output, 0, total_len);

  uint8_t nonce[CCM_NONCE];
  memcpy(nonce, &encr_data->keymat[encr_data->keylen], CCM_SALT_LEN);
  memcpy(nonce + CCM_SALT_LEN, encr_data->encr_data, CCM_IV_LEN);

  unsigned char *pdata = encr_data->encr_data + CCM_IV_LEN;

  PRINTF("output buffer after encryption\n");
  HEXDUMP(tmp_output, total_len);

  result = aes_ccm_encrypt(encr_data->keymat, nonce,
                           encr_data->integ_data, adata_len,
                           pdata, pdata_len,
                           miclength, tmp_output);

  PRINTF("output buffer after encryption\n");
  HEXDUMP(tmp_output, total_len);

  if(result < 0) {
    printf("IPSEC CCM ERROR %u\n", result);
  } else {
    /* copy everything from the output buffer except the associated data
       and write it after the IV */
    memcpy(pdata, (uint8_t *)&tmp_output[adata_len], total_len);
  }
#endif
}
void
ipsec_aes_ccm_decrypt(encr_data_t *encr_data, uint8_t miclength)
{
  PRINTF("\n----------IN AES-CCM DECRYPT---------\n");

#ifdef HW_CCM
  PRINTF("Using hardware cryptoprocessor\n");
  PRINTF("Enabling cryptoprocessor for AES-CCM\n");
  /* crypto_init(); */
  crypto_enable();

  /* Initialize the key variables */
  uint8_t aes_status = 0;
  uint8_t key_area;
  key_area = 0;

  aes_status = aes_load_keys((const void *)encr_data->keymat, AES_KEY_STORE_SIZE_KEY_SIZE_128, 1, key_area);

  if(aes_status == AES_SUCCESS) {
    PRINTF("Loading keys successful\n");

    /* Create the nonce for AES-CCM, salt + IV (11 bytes)*/
    uint8_t nonce[CCM_NONCE];
    memcpy(nonce, &encr_data->keymat[encr_data->keylen], CCM_SALT_LEN);
    memcpy(nonce + CCM_SALT_LEN, encr_data->encr_data, CCM_IV_LEN);

    /* Encrypted message */
    unsigned char *cdata = encr_data->encr_data + CCM_IV_LEN;
    uint16_t cdata_len;
    cdata_len = encr_data->encr_datalen - CCM_IV_LEN;

    /* Calculate the length of the associated data */
    uint16_t adata_len;
    adata_len = (encr_data->encr_data - encr_data->integ_data);

    PRINTF("Encrypted message length: %u\n", cdata_len);
    HEXDUMP(cdata, cdata_len);

    PRINTF("Associated data length: %u\n", adata_len);
    HEXDUMP(encr_data->integ_data, adata_len);

    PRINTF("Nonce length: %u\n", CCM_NONCE);
    HEXDUMP(nonce, CCM_NONCE);

    aes_status = ccm_auth_decrypt_start(IPSEC_L_SIZELEN, key_area,
                                        nonce, encr_data->integ_data, adata_len,
                                        cdata, cdata_len, miclength, NULL);

    if(aes_status == AES_SUCCESS) {
      PRINTF("Decryption started\n");

      /* Wait for the operation to finish*/
      while(!ccm_auth_decrypt_check_status()) ;

      /* Get the result from the decryption */
      aes_status = ccm_auth_decrypt_get_result(cdata, cdata_len, encr_data->icv, miclength);
      if(aes_status == AES_SUCCESS) {
        PRINTF("Decryption ended without error\n");

        PRINTF("Decrypted message length: %u\n", cdata_len);
        HEXDUMP(cdata, cdata_len);

        PRINTF("ICV length %u\n", miclength);
        HEXDUMP(encr_data->icv, miclength);
      } else {
        PRINTF("AES-CCM ERROR: Could not get result from encryption, AES STATUS %u\n", aes_status);
      }
    } else {
      printf("AES-CCM ERROR: Could not start encryption, AES STATUS %u\n", aes_status);
    }
  } else {
    printf("AES-CCM ERROR: Could not load key for AES-CCM, AES STATUS %u\n", aes_status);
  }
  PRINTF("Disabling the Cryptoprocessor\n");
  crypto_disable();
#else
  int result = 0;

  /* Calculate the lengths of the message */
  uint16_t total_len, adata_len, cdata_len;
  adata_len = (encr_data->encr_data - encr_data->integ_data);
  cdata_len = encr_data->encr_datalen - CCM_IV_LEN;
  total_len = cdata_len;

  /* Start of the message to be decrytped and authenticated*/
  unsigned char *cdata = encr_data->encr_data + CCM_IV_LEN;

  /* Initialize output buffer */
  uint8_t tmp_output[total_len];
  memset(tmp_output, 0, sizeof(tmp_output));

  /* Initialize the nonce */
  unsigned char nonce[CCM_NONCE];
  memcpy(nonce, &encr_data->keymat[encr_data->keylen], CCM_SALT_LEN);
  memcpy(nonce + CCM_SALT_LEN, encr_data->encr_data, CCM_IV_LEN);

  PRINTF("tmp_output len %u\n", total_len);
  HEXDUMP(tmp_output, total_len);

  /* Print the nonce */
  PRINTF("IV length: %u\n", CCM_IV_LEN);
  HEXDUMP(encr_data->encr_data, CCM_IV_LEN);
  PRINTF("salt length: %u\n", CCM_SALT_LEN);
  HEXDUMP(&encr_data->keymat[encr_data->keylen], CCM_SALT_LEN);

  PRINTF("nonce length %u\n", CCM_NONCE);
  HEXDUMP(nonce, CCM_NONCE);

  PRINTF("adata %u length\n", adata_len);
  HEXDUMP(encr_data->integ_data, adata_len);

  PRINTF("encr-data length %u\n", encr_data->encr_datalen);
  HEXDUMP(encr_data->encr_data, encr_data->encr_datalen);

  PRINTF("data length %u\n", cdata_len);
  HEXDUMP(cdata, cdata_len);

  /* Decrypt the message */
  result = aes_ccm_decrypt((const unsigned char *)encr_data->keymat, nonce,
                           (const unsigned char *)encr_data->integ_data, adata_len,
                           cdata, cdata_len,
                           miclength, tmp_output);

  PRINTF("tmp_output len %u\n", total_len);
  HEXDUMP(tmp_output, total_len);

  if(result < 0) {
    printf("IPSEC CCM ERROR %d\n", result);
  } else {
    PRINTF("IPSEC CCM NO ERROR %d\n", result);

    /* Copy the MIC and the decrypted message over the original */
    memcpy(encr_data->icv, &tmp_output[(total_len - miclength)], miclength);
    memcpy(encr_data->encr_data + CCM_IV_LEN, tmp_output, total_len);
  }
#endif
}
/** @} */
