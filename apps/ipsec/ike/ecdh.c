/**
 * \addtogroup ecc
 *
 * @{
 */

/*
 * Copyright (c) SICS.
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
 *      Interface to Diffie–Hellman functions
 * \author
 *      Kasun Hewage <kasun.ch@gmail.com>, port to Contiki
 *			Vilhelm Jutvik <ville@imorgon.se>, created the interface and reshuffled some stuff
 *      Runar Mar Magnusson <rmma@kth.seA> Updated for new ECC library
 */
#include <string.h>
#include "contiki.h"
#include "bigint.h"
#include "ecc.h"

#ifndef IPSEC_DEBUG
#define IPSEC_DEBUG 0
#endif

#if IPSEC_DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

/*---------------------------------------------------------------------------*/
uint8_t *
ecdh_encode_public_key(uint32_t *start, u_word *myPrvKey)
{
  uint8_t *ptr = (uint8_t *)start;
  u_byte len = NUMWORDS * WORD_LEN_BYTES;
  ecc_point_a pubKey;
  uint8_t i;

  PRINTF("In encode public key\n");

  ecc_generate_public_key(myPrvKey, &pubKey);

  PRINTF("After ecc_gen_public key encode public key\n");

  bigint_encode(ptr, len, pubKey.x, NUMWORDS);
  ptr += len;
  bigint_encode(ptr, len, pubKey.y, NUMWORDS);

  return ptr + len;
}
/*---------------------------------------------------------------------------*/
void
ecdh_get_shared_secret(uint8_t *shared_key, uint8_t *peerKeData, u_word *myPrvKey)
{

  ecc_point_a peerPubPoint;

  bigint_decode(peerPubPoint.x, NUMWORDS, peerKeData, NUMWORDS * WORD_LEN_BYTES);
  peerKeData += NUMWORDS * WORD_LEN_BYTES;
  bigint_decode(peerPubPoint.y, NUMWORDS, peerKeData, NUMWORDS * WORD_LEN_BYTES);

  u_word shar[NUMWORDS];

  ecc_generate_shared_key(shar, myPrvKey, &peerPubPoint);

#if IPSEC_DEBUG
  PRINTF("Diffie-Hellman Shared Secret\n");
  bigint_print(shar, NUMWORDS);
#endif

  /* Encode the shared key to string. Big endian. */
  bigint_encode(shared_key, NUMWORDS * WORD_LEN_BYTES, shar, NUMWORDS);
  PRINTF("Encoding of shared_key done\n");
}
/*---------------------------------------------------------------------------*/
/** @} */
