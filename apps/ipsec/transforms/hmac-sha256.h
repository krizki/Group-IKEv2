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
 *      HMAC-SHA256 implementation for IPsec
 * \author
 *      Runar Mar Magnusson <rmma@kth.se>
 *
 */

#ifndef HMACSHA256_H_
#define HMACSHA256_H_
#include "sha.h"
#include "hmac-sha1.h" /* For the hmac_data_t structure */
#define HMAC_SHA256_OUTPUT_LEN 32
#define USHA_Max_Message_Block_Size SHA256_Message_Block_Size
#define USHAMaxHashSize SHA256HashSize

#ifdef HW_SHA
#include "cpu/cc2538/dev/crypto.h"
#include "cpu/cc2538/dev/sha256.h"
typedef struct HMACContext {
  int hashSize;                 /* hash size of SHA being used */
  int blockSize;                /* block size of SHA being used */
  sha256_state_t shaContext;       /* SHA context */
  unsigned char k_opad[USHA_Max_Message_Block_Size];
  /* outer padding - key XORd with opad */
  int Computed;                 /* Is the MAC computed? */
  int Corrupted;                /* Cumulative corruption code */
} HMACContext;
#else
typedef struct HMACContext {
  int hashSize;                 /* hash size of SHA being used */
  int blockSize;                /* block size of SHA being used */
  SHA256Context shaContext;       /* SHA context */
  unsigned char k_opad[USHA_Max_Message_Block_Size];
  /* outer padding - key XORd with opad */
  int Computed;                 /* Is the MAC computed? */
  int Corrupted;                /* Cumulative corruption code */
} HMACContext;
#endif

void hmac_sha256(hmac_data_t *hmac_data);
extern int hmac(const unsigned char *message_array, int length,
                const unsigned char *key, int key_len, uint8_t digest[USHAMaxHashSize]);
#ifdef HW_SHA
/* Final bits not needed for hmac so not implemented*/
extern int hmac_hw_Reset(HMACContext *context, const unsigned char *key, int key_len);
extern int hmac_hw_Input(HMACContext *context, const unsigned char *text, int text_len);
extern int hmac_hw_Result(HMACContext *context, uint8_t *digest);
#else
extern int hmacReset(HMACContext *context, const unsigned char *key, int key_len);
extern int hmacInput(HMACContext *context, const unsigned char *text, int text_len);
extern int hmacResult(HMACContext *context, uint8_t *digest);
extern int hmacFinalBits(HMACContext *context, uint8_t bits, unsigned int bit_count);
#endif

#endif /* HMACSHA196_H_ */
