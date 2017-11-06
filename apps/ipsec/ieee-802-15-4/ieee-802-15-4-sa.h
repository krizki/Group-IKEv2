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
 * Contains transform IDs definitions for use with IKE and IEEE 802.15.4
 * Note that the Definitions are contained here instead of sa.h to keep the
 * definitions seperate.
 *
 * Created on June 16, 2015, 5:53 AM
 */

#ifndef IEEE_802_15_4_SA_H
#define IEEE_802_15_4_SA_H

#define IKE_IEEE_KEY_LEN 16 /* IEEE 802.15.4-2011 standard only 128 bit keys supported */

/**
 * Returns the ICV/MIC/MAC length for an IEEE 802.15.4 integrity transform
 * @param transform
 * @return The ICV length of the encryption transform (0,4,8,16)
 */
uint8_t get_encr_ieee_icvlen(uint8_t transform);

/**
 * Returns the ICV/MIC/MAC length for an IEEE 802.15.4 integrity transform
 * @param transform
 * @return The ICV length of the transform (0,4,8,16)
 */
uint8_t get_integ_ieee_icvlen(uint8_t transform);

/**
 * Returns the keymat length for an IEEE 802.15.4 encryption transform
 * @param transform
 * @return 0 if the transform is not defined, IKE_IEEE_KEY_LEN otherwise
 */
uint8_t get_encr_ieee_keymat_len(uint8_t transform);

/**
 * Returns the keymat length for an IEEE 802.15.4 integrity transform
 * @param transform
 * @return 0 if the transform is not defined, IKE_IEEE_KEY_LEN otherwise
 */
uint8_t get_integ_ieee_keymat_len(uint8_t transform);

/**
 * Returns the level of a transform
 * @param transform
 * @return returns the security level for an IEEE 802.15.4 frame
 */
uint8_t get_ieee_lvl_from_transform(uint8_t transform);

/* Macros that return the ICV lengths based on the IEEE 802.15.4 transform ID */
#define SA_ENCR_IEEE_ICV_LEN_BY_TYPE(encr) get_encr_ieee_icvlen(encr)
#define SA_INTEG_IEEE_ICV_LEN_BY_TYPE(integ) get_integ_ieee_icvlen(integ)

/**
 * Protocol to use with IKE SA
 */
typedef enum {
  SA_PROTO_IEEE_802_15_4 = 7,
} sa_ieee_proto_type_t;

/**
 * Transform type #1 for IEEE 802.15.4: Encryption (confidentiality / combined mode)
 */
typedef enum {
  /* Specific to this implementation only for IEEE 802.15.4 */
  SA_ENCR_IEEE_AES_CCM_STAR_128_0 = 30, /* IEEE 802.15.4 AES-CCM*(encryption only) with L=2, M=0 */
  SA_ENCR_IEEE_AES_CCM_STAR_128_4 = 31, /* IEEE 802.15.4 AES-CCM* with L=2, M=4 */
  SA_ENCR_IEEE_AES_CCM_STAR_128_8 = 32, /* IEEE 802.15.4 AES-CCM* with L=2, M=8 */
  SA_ENCR_IEEE_AES_CCM_STAR_128_16 = 33, /* IEEE 802.15.4 AES-CCM* with L=2, M=16 */
} sa_encr_ieee_transform_type_t;

/**
 * Transform type #3 for IEEE 802.15.4: Integrity
 */
typedef enum {
  /* Only defined for IEEE 802.15.4 */
  SA_INTEG_IEEE_AES_CCM_STAR_128_4 = 17,  /*IEEE 802.15.4 AES-CCM*(integrity only) with L=2, M=4 */
  SA_INTEG_IEEE_AES_CCM_STAR_128_8 = 18,  /*IEEE 802.15.4 AES-CCM*(integrity only) with L=2, M=8 */
  SA_INTEG_IEEE_AES_CCM_STAR_128_16 = 19, /*IEEE 802.15.4 AES-CCM*(integrity only) with L=2, M=16 */
} sa_integ_ieee_transform_type_t;

#endif /* IEEE_802_15_4_SA_H */
