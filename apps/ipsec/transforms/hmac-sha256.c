/* Original File:
 *  ***************** See RFC 6234 for details. *******************
 *  Copyright (c) 2011 IETF Trust and the persons identified as
 *  authors of the code.  All rights reserved.
 *  See sha.h for terms of use and redistribution.
 *
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
 *    HMAC algorithm for SHA256 (modified from RFC6234 to support only SHA256)
 * \author
 *		Runar Mar Magnusson <rmma@kth.se> - adapted for IKE
 */

/*
 *  Description:
 *      This file implements the HMAC algorithm (Keyed-Hashing for
 *      Message Authentication, [RFC 2104]), expressed in terms of
 *      the various SHA algorithms.
 */
#include "sha.h"
#include "hmac-sha256.h"
#define USHA_Max_Message_Block_Size SHA256_Message_Block_Size
#define USHAMaxHashSize SHA256HashSize

#ifdef HW_SHA
#include "cpu/cc2538/dev/crypto.h"
#include "cpu/cc2538/dev/sha256.h"
#endif

#if IPSEC_DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

/*
 *  hmac
 *
 *  Description:
 *      This function will compute an HMAC message digest.
 *
 *  Parameters:
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      message_array[ ]: [in]
 *          An array of octets representing the message.
 *          Note: in RFC 2104, this parameter is known
 *          as 'text'.
 *      length: [in]
 *          The length of the message in message_array.
 *      key[ ]: [in]
 *          The secret shared key.
 *      key_len: [in]
 *          The length of the secret shared key.
 *      digest[ ]: [out]
 *          Where the digest is to be returned.
 *          NOTE: The length of the digest is determined by
 *              the value of whichSha.
 *
 * *  Returns:
 *      sha Error Code.
 *
 */
void
hmac_sha256(hmac_data_t *hmac_data)
{
  hmac(hmac_data->data, hmac_data->datalen, hmac_data->key, hmac_data->keylen, hmac_data->out);
}
int
hmac(const unsigned char *message_array, int length,
     const unsigned char *key, int key_len,
     uint8_t digest[USHAMaxHashSize])
{
  HMACContext context;
#ifdef HW_SHA
  PRINTF("using hardware SHA256\n");
  crypto_enable();
  uint8_t result = 0;
  result = (hmac_hw_Reset(&context, key, key_len)
            || hmac_hw_Input(&context, message_array, length)
            || hmac_hw_Result(&context, digest));
  crypto_disable();
  return result;
#else
  PRINTF("using non-hardware SHA256\n");

  return hmacReset(&context, key, key_len)
         || hmacInput(&context, message_array, length)
         || hmacResult(&context, digest);
#endif
}
#ifdef HW_SHA
/**
 * Same as hmac_Reset bellow but uses hardware SHA256 functions
 */
int
hmac_hw_Reset(HMACContext *context,
              const unsigned char *key, int key_len)
{
  int i, blocksize, hashsize, ret;

  /* inner padding - key XORd with ipad */
  unsigned char k_ipad[USHA_Max_Message_Block_Size];

  /* temporary buffer when keylen > blocksize */
  unsigned char tempkey[USHAMaxHashSize];

  if(!context) {
    return shaNull;
  }
  context->Computed = 0;
  context->Corrupted = shaSuccess;

  blocksize = context->blockSize = SHA256_Message_Block_Size;
  hashsize = context->hashSize = SHA256HashSize;
  /* context->whichSha = whichSha; */

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if(key_len > blocksize) {
    sha256_state_t tcontext;
    int err = sha256_init(&tcontext) ||
      sha256_process(&tcontext, key, key_len) ||
      sha256_done(&tcontext, tempkey);
    if(err != shaSuccess) {
      return err;
    }
    key = tempkey;
    key_len = hashsize;
  }

  /*
   * The HMAC transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, text))
   *
   * where K is an n byte key, 0-padded to a total of blocksize bytes,
   * ipad is the byte 0x36 repeated blocksize times,
   * opad is the byte 0x5c repeated blocksize times,
   * and text is the data being protected.
   */

  /* store key into the pads, XOR'd with ipad and opad values */
  for(i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36;
    context->k_opad[i] = key[i] ^ 0x5c;
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for(; i < blocksize; i++) {
    k_ipad[i] = 0x36;
    context->k_opad[i] = 0x5c;
  }

  /* perform inner hash */
  /* init context for 1st pass */
  ret = sha256_init(&context->shaContext) ||
    /* and start with inner pad */
    sha256_process(&context->shaContext, k_ipad, blocksize);
  return context->Corrupted = ret;
}
/**
 * Same as hmac_Input bellow but uses hardware SHA256 functions
 */
int
hmac_hw_Input(HMACContext *context, const unsigned char *text,
              int text_len)
{
  if(!context) {
    return shaNull;
  }
  if(context->Corrupted) {
    return context->Corrupted;
  }
  if(context->Computed) {
    return context->Corrupted = shaStateError;
  }
  
  /* then text of datagram */
  return context->Corrupted =
    sha256_process(&context->shaContext, text, text_len);
}
/**
 * Same as hmac_Result bellow but uses hardware SHA256 functions
 */
int
hmac_hw_Result(HMACContext *context, uint8_t *digest)
{
  int ret;
  if(!context) {
    return shaNull;
  }
  if(context->Corrupted) {
    return context->Corrupted;
  }
  if(context->Computed) {
    return context->Corrupted = shaStateError;
  }
  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  ret =
    sha256_done(&context->shaContext, digest) ||
    /* perform outer SHA */
    /* init context for 2nd pass */
    sha256_init(&context->shaContext) ||

    /* start with outer pad */
    sha256_process(&context->shaContext, context->k_opad,
                   context->blockSize) ||

    /* then results of 1st hash */
    sha256_process(&context->shaContext, digest, context->hashSize) ||
    /* finish up 2nd pass */
    sha256_done(&context->shaContext, digest);

  context->Computed = 1;
  return context->Corrupted = ret;
}
#else
/*
 *  hmacReset
 *
 *  Description:
 *      This function will initialize the hmacContext in preparation
 *      for computing a new HMAC message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      key[ ]: [in]
 *          The secret shared key.
 *      key_len: [in]
 *          The length of the secret shared key.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hmacReset(HMACContext *context,
          const unsigned char *key, int key_len)
{
  int i, blocksize, hashsize, ret;

  /* inner padding - key XORd with ipad */
  unsigned char k_ipad[USHA_Max_Message_Block_Size];

  /* temporary buffer when keylen > blocksize */
  unsigned char tempkey[USHAMaxHashSize];

  if(!context) {
    return shaNull;
  }
  context->Computed = 0;
  context->Corrupted = shaSuccess;

  blocksize = context->blockSize = SHA256_Message_Block_Size;
  hashsize = context->hashSize = SHA256HashSize;
  /* context->whichSha = whichSha; */

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if(key_len > blocksize) {
    SHA256Context tcontext;
    int err = SHA256Reset(&tcontext) ||
      SHA256Input(&tcontext, key, key_len) ||
      SHA256Result(&tcontext, tempkey);
    if(err != shaSuccess) {
      return err;
    }
    key = tempkey;
    key_len = hashsize;
  }

  /*
   * The HMAC transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, text))
   *
   * where K is an n byte key, 0-padded to a total of blocksize bytes,
   * ipad is the byte 0x36 repeated blocksize times,
   * opad is the byte 0x5c repeated blocksize times,
   * and text is the data being protected.
   */

  /* store key into the pads, XOR'd with ipad and opad values */
  for(i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36;
    context->k_opad[i] = key[i] ^ 0x5c;
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for(; i < blocksize; i++) {
    k_ipad[i] = 0x36;
    context->k_opad[i] = 0x5c;
  }

  /* perform inner hash */
  /* init context for 1st pass */
  ret = SHA256Reset(&context->shaContext) ||
    /* and start with inner pad */
    SHA256Input(&context->shaContext, k_ipad, blocksize);
  return context->Corrupted = ret;
}
/*
 *  hmacInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.  It may be called multiple times.
 *
 *  Parameters:
 *      context: [in/out]
 *          The HMAC context to update.
 *      text[ ]: [in]
 *          An array of octets representing the next portion of
 *          the message.
 *      text_len: [in]
 *          The length of the message in text.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hmacInput(HMACContext *context, const unsigned char *text,
          int text_len)
{
  if(!context) {
    return shaNull;
  }
  if(context->Corrupted) {
    return context->Corrupted;
  }
  if(context->Computed) {
    return context->Corrupted = shaStateError;
  }
  
  /* then text of datagram */
  return context->Corrupted =
    SHA256Input(&context->shaContext, text, text_len);
}
/*
 * hmacFinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The HMAC context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 * *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int
hmacFinalBits(HMACContext *context,
              uint8_t bits, unsigned int bit_count)
{
  if(!context) {
    return shaNull;
  }
  if(context->Corrupted) {
    return context->Corrupted;
  }
  if(context->Computed) {
    return context->Corrupted = shaStateError;
  }
  /* then final bits of datagram */
  
  return context->Corrupted =
    SHA256FinalBits(&context->shaContext, bits, bit_count);
}
/*
 * hmacResult
 *
 * Description:
 *   This function will return the N-byte message digest into the
 *   Message_Digest array provided by the caller.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the HMAC hash.
 *   digest[ ]: [out]
 *     Where the digest is returned.
 *     NOTE 2: The length of the hash is determined by the value of
 *      whichSha that was passed to hmacReset().
 *
 * Returns:
 *   sha Error Code.
 *
 */
int
hmacResult(HMACContext *context, uint8_t *digest)
{
  int ret;
  if(!context) {
    return shaNull;
  }
  if(context->Corrupted) {
    return context->Corrupted;
  }
  if(context->Computed) {
    return context->Corrupted = shaStateError;
  }
  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  ret =
    SHA256Result(&context->shaContext, digest) ||
    /* perform outer SHA */
    /* init context for 2nd pass */
    SHA256Reset(&context->shaContext) ||

    /* start with outer pad */
    SHA256Input(&context->shaContext, context->k_opad,
                context->blockSize) ||

    /* then results of 1st hash */
    SHA256Input(&context->shaContext, digest, context->hashSize) ||
    /* finish up 2nd pass */
    SHA256Result(&context->shaContext, digest);

  context->Computed = 1;
  return context->Corrupted = ret;
}
#endif