/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    Interface that pads, unpads, encrypts and decrypts ESP headers using any given encryption method
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
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

#include "encr.h"
#include "prf.h"
#include "aes-moo.h"
#include "ipsec-ccm.h"
#include "ipsec-random.h"

extern void aes_ctr(encr_data_t *encr_data);
extern void ipsec_aes_ccm_encrypt(encr_data_t *encr_data, uint8_t miclength);
extern void ipsec_aes_ccm_decrypt(encr_data_t *encr_data, uint8_t miclength);

/*---------------------------------------------------------------------------*/
/**
 * Pads the end of an ESP or SK payload with the monotonically increasing
 * byte pattern 1, 2, 3, 4... as described in RFC 4303 p. 15.
 * The pad length field will be populated accordingly,
 * and, if non-zero, the ip_next_hdr field will be written.
 *
 * data.encr_datalen and data.tail will be updated accordingly.
 */
/*---------------------------------------------------------------------------*/
static void
espsk_pad(encr_data_t *data, uint8_t blocklen)
{
  uint8_t *tail = data->encr_data + data->encr_datalen;

  /* CBC requires a padding of 16 bytes not 4 like all the other */
  uint8_t modulus = (data->type == SA_ENCR_AES_CBC) ? 16 : 4;

  uint8_t hdrlen = 1 + (data->ip_next_hdr > 0);
  uint8_t pad = blocklen - (data->encr_datalen + hdrlen) % modulus;

  /* Write the 1, 2, 3... pattern */
  uint8_t n;
  for(n = 0; n <= pad; ++n) {
    tail[n] = n + 1;
  }
  tail += pad + hdrlen;
  data->encr_datalen += pad + hdrlen;
  data->padlen = pad;
  if(data->ip_next_hdr) {
    /* negative indices... undefined behaviour across compilers,
     * but this works in mspgcc */
    tail[-1] = *data->ip_next_hdr;
    tail[-2] = pad;
  } else {
    tail[-1] = pad;
  }
}
/*---------------------------------------------------------------------------*/
/**
 * Reads the trailing headers and adjust data.encr_datalen, data.tail and
 * data.ip_next_hdr
 */
/*---------------------------------------------------------------------------*/
static void
espsk_unpad(encr_data_t *data)
{
  uint16_t encr_icv = SA_ENCR_ICV_LEN_BY_TYPE(data->type);
  if(data->ip_next_hdr) {
    /* Next header comes last */
    data->ip_next_hdr = data->encr_data + data->encr_datalen - 1 - encr_icv;
    data->padlen = *(data->encr_data + data->encr_datalen - 2 - encr_icv);
  } else {
    /* No next header */
    data->padlen = *(data->encr_data + data->encr_datalen - 1 - encr_icv);
  }
  /* According to the RFC of ESP we SHOULD check that the padding pattern is correct (p. 15), */
  /* (presumably to assert correct cryptographic handling) but I don't see that we can afford it. */
  /* The pattern is specific to each transform, requiring something more than just a plain for-loop. */
}
/*---------------------------------------------------------------------------*/
void
espsk_pack(encr_data_t *data)
{
  switch(data->type) {
#ifdef HW_AES
  case SA_ENCR_AES_CBC:
    /* If a driver that supports aes-decrypt in software is added the HW_AES defines can be removed*/
    espsk_pad(data, 16);
    random_ike(data->encr_data, 16);
    aes_cbc_encrypt(data);
    break;
#endif
  case SA_ENCR_AES_CTR:           /* SHOULD */
    /* Confidentiality only */
    /* Pad the data for 32 bit-word alignment, add trailing headers and adjust
     * encr_datalen accordingly */
    espsk_pad(data, 4);
    *((uint32_t *)data->encr_data) = data->ops;    /* AES CTR's IV must be unique, but not necessarily random. */

    /* Encrypt everything from encr_data continuing for encr_datalen bytes */
    aes_ctr(data);
    break;

  case SA_ENCR_NULL:
    espsk_pad(data, 4);
    break;
  case SA_ENCR_AES_CCM_8:
    /* RFC 4309 - Using AES CCM Mode with ESP*/

    espsk_pad(data, 4);
    *((uint32_t *)data->encr_data) = data->ops;    /* AES-CCM's IV must be unique, but not necessarily random. */
    ipsec_aes_ccm_encrypt(data, CCM_8_ICV_LEN);
    break;
  case SA_ENCR_AES_CCM_12:
    /* RFC 4309 - Using AES CCM Mode with ESP*/

    espsk_pad(data, 4);
    *((uint32_t *)data->encr_data) = data->ops;    /* AES-CCM's IV must be unique, but not necessarily random. */
    ipsec_aes_ccm_encrypt(data, CCM_12_ICV_LEN);
    break;
  case SA_ENCR_AES_CCM_16:
    /* RFC 4309 - Using AES CCM Mode with ESP*/

    espsk_pad(data, 4);
    *((uint32_t *)data->encr_data) = data->ops;    /* AES-CCM's IV must be unique, but not necessarily random. */
    ipsec_aes_ccm_encrypt(data, CCM_16_ICV_LEN);
    break;
  default:
    IPSEC_PRINTF(IPSEC "Error: Unknown encryption type\n");
    /*
       SA_ENCR_RESERVED = 0,
       SA_ENCR_3DES = 3,             // MUST-
       SA_ENCR_NULL = 11,            // MAY
       SA_ENCR_UNASSIGNED = 255
     */
  }
}
/*---------------------------------------------------------------------------*/
void
espsk_unpack(encr_data_t *data)
{
  switch(data->type) {
#ifdef HW_AES
  case SA_ENCR_AES_CBC:           /* SHOULD+ */
    /* If a driver that supports aes-decrypt in software is added the HW_AES defines can be removed*/
    aes_cbc_decrypt(data);
    break;
#endif
  case SA_ENCR_AES_CTR:           /* SHOULD */
    /* Confidentiality only */
    aes_ctr(data);
    break;
  case SA_ENCR_NULL:
    break;
  case SA_ENCR_AES_CCM_8:
    ipsec_aes_ccm_decrypt(data, CCM_8_ICV_LEN);
    break;
  case SA_ENCR_AES_CCM_12:
    ipsec_aes_ccm_decrypt(data, CCM_12_ICV_LEN);
    break;
  case SA_ENCR_AES_CCM_16:
    ipsec_aes_ccm_decrypt(data, CCM_16_ICV_LEN);
    break;
  default:
    IPSEC_PRINTF(IPSEC "Error: Unknown encryption type\n");
    /*
       SA_ENCR_RESERVED = 0,
       SA_ENCR_3DES = 3,             // MUST-
       SA_ENCR_NULL = 11,            // MAY
       SA_ENCR_AES_CTR = 13,         // SHOULD
       SA_ENCR_UNASSIGNED = 255
     */
  }
  espsk_unpad(data);
}
/** @} */