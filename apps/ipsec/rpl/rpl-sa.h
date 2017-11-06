/*
 * Copyright (c) 2015, SICS.
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

/*
 * File:   rpl-sa.h
 * Author: Runar Mar Magnusson <rmma@kth.se>
 *
 * Created on June 16, 2015, 5:53 AM
 */

#ifndef RPL_SA_H
#define RPL_SA_H

#define IKE_RPL_KEYMAT_LEN 16 /* RFC6550 only 128 bit keys supported */

/**
 * Returns the ICV/MIC/MAC length for an RPL encryption transform
 * @param transform
 * @return The ICV length of the transform (0,4,8)
 */
uint8_t get_encr_rpl_icvlen(uint8_t transform);

/**
 * Returns the ICV/MIC/MAC length for an RPL integrity transform
 * @param transform
 * @return The ICV length of the transform (0,4,8)
 */
uint8_t get_integ_rpl_icvlen(uint8_t transform);

/**
 * Returns the keymat length for an RPL encryption transform
 * @param transform
 * @return 0 if the transform is not defined, IKE_RPL_KEY_LEN otherwise
 */
uint8_t get_encr_rpl_keymat_len(uint8_t transform);

/**
 * Returns the keymat length for an RPL integrity transform
 * @param transform
 * @return 0 if the transform is not defined, IKE_IEEE_KEY_LEN otherwise
 */
uint8_t get_integ_rpl_keymat_len(uint8_t transform);

/**
 * Returns the LVL of a RPL secure packet for a given transform (see RFC 6550)
 */
uint8_t get_rpl_lvl_from_transform(uint8_t transform);

/* Macros that return the ICV lengths based on the RPL transform ID */
#define SA_ENCR_RPL_ICV_LEN_BY_TYPE(encr) get_encr_rpl_icvlen(encr)
#define SA_INTEG_RPL_ICV_LEN_BY_TYPE(integ) get_integ_rpl_icvlen(integ)

/**
 * Protocol to use with IKE
 */
typedef enum {
  SA_PROTO_RPL = 6,
} sa_rpl_proto_type_t;

/**
 * Transform type #1 for RPL: Encryption (confidentiality / combined mode)
 */
typedef enum {
  /* Specific to this implementation only for RPL and IEEE 802.15.4 */
  SA_ENCR_RPL_AES_CCM_128_4 = 28,        /* RPL AES-CCM with L=2, M=4 */
  SA_ENCR_RPL_AES_CCM_128_8 = 29,        /* RPL AES-CCM with L=2, M=8 */
} sa_encr_rpl_transform_type_t;

/**
 * Transform type #3 for RPL: Integrity
 */
typedef enum {
  /* Only defined for RPL and IEEE 802.15.4 */
  SA_INTEG_RPL_AES_CCM_128_4 = 15,          /* RPL AES-CCM with L=2, M=4 */
  SA_INTEG_RPL_AES_CCM_128_8 = 16,          /* RPL AES-CCM with L=2, M=8 */
} sa_integ_rpl_transform_type_t;

#endif /* RPL_SA_H */
