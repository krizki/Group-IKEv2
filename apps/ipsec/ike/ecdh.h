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
 *      Source file for the Elliptic Curve point arithmetic functions.
 * \author
 *      Kasun Hewage <kasun.ch@gmail.com>, port to Contiki
 *	Vilhelm Jutvik <ville@imorgon.se>, bug fixes, adaption to IKEv2
 *      Runar Mar Magnusson <rmma@kth.se>, changed ecc libraries
 *
 */

#include "ecc.h"
#include "bigint.h"

/**
 * \brief      Encodes my public key to the memory beginning at start. Returns a pointer to
 *             the first byte after the public key.
 * \parameter  start Start of the public key. 48 bytes (2 * 192 bits) will be written.
 * \parameter  myPrvKey My private key of 24 bytes length (192 bits)
 */
uint8_t *ecdh_encode_public_key(uint32_t *start, u_word *myPrvKey);

/**
 * Calculate the shared key
 *
 * \parameter shared_key Pointer to the shared key. Must be 48 bytes long (2 * 192 bits).\
    The X coordinate is stored in the first 24 bytes, then comes the Y coordinate in the remaining 24 bytes. Both are stored in network byte order.
 * \parameter peerPubKey The public key (commonly that of the other party)
 * \parameter myPrvKey The private key (commonly ours). 24 bytes long.
 */
void ecdh_get_shared_secret(uint8_t *shared_key, uint8_t *peerPubKey, u_word *myPrvKey);

/* Deserialization. Takes an u8_t * as argument. */
#define ECDH_DESERIALIZE_TO_POINTT(ptr) ((point_t *)ptr)
#define ECDH_DESERIALIZE_TO_BIGINT(ptr) ((NN_DIGIT *)ptr)

/** @} */