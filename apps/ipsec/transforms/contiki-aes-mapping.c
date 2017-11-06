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
 *      Mapping the Contiki AES library to the generic aes_implem
 *      interface
 * \author
 *      Runar Mar Magnusson <rmma@kth.se>
 *
 * Created on April 21, 2015, 9:36 PM
 */

#include "ipsec.h"
#include "aes-moo.h"
#include "core/lib/aes-128.h"
#include "stdio.h"

/* Only support for 128 bit (16 bytes) blocksize in contiki */
#define CONTIKI_AES_BLOCK_SIZE 16

/*---------------------------------------------------------------------------*/
static void
aes_init(uint8_t *key)
{
  aes_128_set_padded_key(key, CONTIKI_AES_BLOCK_SIZE);
}
/*---------------------------------------------------------------------------*/
static void
aes_encrypt(uint8_t *buff)
{
  aes_128_padded_encrypt(buff, CONTIKI_AES_BLOCK_SIZE);
}
/*---------------------------------------------------------------------------*/
struct aes_implem contiki_aes = {
  aes_init,
  aes_encrypt,
  NULL, /* NULL because aes-decrypt not implemented */
};
/*---------------------------------------------------------------------------*/

/** @} */