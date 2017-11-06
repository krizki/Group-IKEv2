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

#ifndef __ENCR_H__
#define __ENCR_H__

#include "sa.h"
#include "ipsec.h"

/**
 * Data struct used in conjunction with encr() and decr() for writing the
 * IKE Encrypted (SK) payload and the ESP header of IPsec.
 *
 * Please note that ip_next_hdr MUST be set to indicate ESP or SK when using
 * encr() _as well as_ decr()
 */
typedef struct {
  /* Algorithm */
  sa_encr_transform_type_t type;
  /* KEYMAT is the source of the key + other necessary information */
  uint8_t *keymat;

  /* Length of the _key_ in bytes. Always assigned, irrespective of if the
   * transform has static or dynamic key length. */
  /* NOTE: That the key is merely a subset of keymat which may contain
   * more information such as nonce values etc. */
  uint8_t keylen;

  /* Integrity */
  /* integ_datalen will be encr_datalen + (encr_data - integ_data) */
  /* Beginning of the ESP header (ESP) or the IKEv2 header (SK) */
  uint8_t *integ_data;

  /* Confidentiality */
  /* The beginning of the IV */
  uint8_t *encr_data;
  /* From the beginning of the IV to the IP next header field (ESP) or
   * the padding field (SK). */
  uint16_t encr_datalen;

  /* Next Header for ESP. If this pointer is set to NULL the IKE SK format
   * is used, ESP otherwise. */
  /* Is to be trusted on output. */
  uint8_t *ip_next_hdr;

  /* Number of operations that have been performed utilizing this key.
   * Used for IV in some transforms. */
  uint32_t ops;

  /*
   * Information that is to be filled by the called (callee) function
   * (encr_pad and encr_unpad).
   * The caller can leave the fields as-is upon calling the functions.
   */
  /* ICV information to be filled by the callee. Only used in unpacking. */
  uint8_t *icv; /* [IPSEC_ICVLEN]; */
  /* Length of padding (number of bytes between end of decrypted data and padding field) */
  uint8_t padlen;
} encr_data_t;

/**
 * Decrypts the data in an SK payload in situ. data.start should point to the IV
 * payload.
 *
 * data.datalen should be the length of the the IV field, the encrypted IKE
 * payload, the padding and the pad length field.
 *
   BEFORE:
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                    Encrypted IKE Payloads                     ~
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |               |             Padding (0-255 octets)            |
 |+-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
 |                                               |  Pad Length   |
 |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   AFTER:
 |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                    Decrypted IKE Payloads                     ~
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |               |             Padding (0-255 octets)            |
 |+-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
 |                                               |  Pad Length   |
 |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void espsk_unpack(encr_data_t *data);

/**
 * The Encryption payload of IKEv2 (abbreviated SK) is closely modelled upon
 * the ESP header of IPsec. This is true in regard to transforms as well as
 * the wire format.
 *
 * The unpack (used in conjunction with incoming traffic) and the
 * pack (for outgoing) functions in this file can handle both formats.
 *
 * The functions accepts an argument of type *encr_data_t.
 * Please see espsk.h for an explanation of
 * the significance of this struct's members.
 *
 *
 * Takes the data at data->data + block-size and encrypts it in situ, adding
 * padding at the end.
 * This is what the memory will look like after the function has returned:
 *
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                    Encrypted IKE Payloads                     ~
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |               |             Padding (0-255 octets)            |
 |+-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
 |                                               |  Pad Length   |
 |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * \return The number of bytes encrypted (the length of the fields Encrypted
 *  IKE Payloads (including the IV), Padding and Pad Length).
 */
void espsk_pack(encr_data_t *data);

#endif

/** @} */

