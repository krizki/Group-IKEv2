/*
 * Copyright (c) 2015,
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
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 * Author: Runar Mar Magnusson <rmma@kth.se>
 */
/**
 * \file
 *      AES-CCM block cipher mode of operation (RFC 4309)
 * \brief
 *	Only 128 bit key sizes supported at this time
 * \author
 *      Runar Mar Magnusson <rmma@kth.se>
 *
 *
 */
/**
 * \addtogroup ipsec
 * @{
 */

#ifndef IPSEC_CCM_H
#define IPSEC_CCM_H

#include "encr.h"

/* IPSEC CCM parameters from RFC4309 */
#define CCM_FLAGS_LEN 1
#define IPSEC_L_SIZELEN 4 /* Only length of 4 supported in ipsec  */
#define CCM_SALT_LEN 3 /* Length of salt in bytes */
#define CCM_IV_LEN 8
#define CCM_NONCE (15 - IPSEC_L_SIZELEN)

#define CCM_KEYLEN 16 /* Only 128 bit AES supported */
#define CCM_8_ICV_LEN 8
#define CCM_12_ICV_LEN 12
#define CCM_16_ICV_LEN 16

/**
 * Encrypts the data with AES-CCM
 * @param encr_data
 * @param miclength is 8,12 or 16
 */
void ipsec_aes_ccm_encrypt(encr_data_t *encr_data, uint8_t miclength);

/**
 * Decrypts the data with AES-CCM
 * @param encr_data
 * @param miclength is 8,12 or 16
 */
void ipsec_aes_ccm_decrypt(encr_data_t *encr_data, uint8_t miclength);

#endif /* IPSEC_CCM_H */

/** @} */