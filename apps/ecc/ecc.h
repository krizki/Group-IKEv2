/*
 * Copyright (c) SICS
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
 *    ECC arithmetic operations
 * \author
 *		Oriol Piñol <oriol@sics.se>
 *    Runar Mar Magnusson <rmma@kth.se> - added HW ECC functions for CC2538
 *
 */

#ifndef _ECC_H__
#define _ECC_H__

#include "bigint.h"

typedef struct curve {
  u_word a[NUMWORDS];
  u_word b[NUMWORDS];
} ecc_curve;

typedef struct point_affine {
  u_word x[NUMWORDS];
  u_word y[NUMWORDS];
} ecc_point_a;

typedef struct point_projective {
  u_word x[NUMWORDS];
  u_word y[NUMWORDS];
  u_word z[NUMWORDS];
} ecc_point_p;

typedef struct elliptic_param {
  u_word p[NUMWORDS];

  ecc_curve curve;

  ecc_point_a point;

  u_word order[NUMWORDS + 1];
} ecc_param;

void new_ecc_init();

/** 
 * A=B+C 
 */
void ecc_affine_add(ecc_point_a *a, ecc_point_a *b, ecc_point_a *c,
                    u_word *p, u_word *a_c);

void ecc_aff_scalar_multiplication(ecc_point_a *R, ecc_point_a *a,
                                   u_word *k, u_byte digitsk, u_word *P,
                                   u_word *a_c);

void ecc_homogeneous_add(ecc_point_p *a, ecc_point_p *b, ecc_point_p *c,
                         u_word *p, u_word *a_c);

void ecc_scalar_multiplication_homo(ecc_point_a *R, ecc_point_a *a,
                                    u_word *k, u_byte digitsk,
                                    u_word *P, u_word *a_c);

void ecc_jacobian_add(ecc_point_p *a, ecc_point_p *b, ecc_point_p *c,
                      u_word *p, u_word *a_c);

void ecc_scalar_multiplication_jacob(ecc_point_a *R, ecc_point_a *a,
                                     u_word *k, u_byte digitsk, u_word *p,
                                     u_word *a_c);

void ecc_scalar_multiplication_ltr_jacob(ecc_point_a *R, ecc_point_a *a,
                                         u_word *k, u_byte digitsk, u_word *p,
                                         u_word *a_c);

void ecc_jacobian_double(ecc_point_p *a, ecc_point_p *b, u_word *p,
                         u_word *a_c);

#ifdef HW_ECC
void ecc_aff_hw_add(ecc_point_a *a, ecc_point_a *b, ecc_point_a *c,
                    u_word *p, u_word *a_c);

void ecc_scalar_multiplication_hw(ecc_point_a *R, ecc_point_a *a,
                                  u_word *k, u_byte digitsk, u_word *p,
                                  u_word *a_c);
#endif /* HW_ECC */

void ecc_generate_private_key(u_word *secr);

void ecc_generate_public_key(u_word *secr, ecc_point_a *publ);

#ifdef COMPACT_COORDINATES
uint8_t ecc_generate_shared_key(u_word *shar, u_word *secr, u_word *publx);
#else
uint8_t ecc_generate_shared_key(u_word *shared, u_word *secr,
                                ecc_point_a *publ);
#endif /* COMPACT_COORDINATES */

uint32_t ecc_generate_shared_key_and_iv(uint8_t *shared, uint8_t *iv,
                                        u_word *secr, ecc_point_a *publ);

void ecc_generate_signature(u_word *secr, const unsigned char *message, u_byte message_len,
                            u_word *signature, u_word *rx);

uint8_t ecc_check_signature(ecc_point_a *public, uint8_t *message, u_byte message_len,
                            u_word *signature, u_word *r);

uint8_t ecc_check_sha1_signature(ecc_point_a *public, const uint8_t *message, u_byte message_len,
                                 u_word *signature, u_word *r);

void ecc_generate_sha1_signature(u_word *secr, const unsigned char *message, u_byte message_len,
                                 u_word *signature, u_word *rx);

uint8_t ecc_check_signature_from_sha(ecc_point_a *public, u_word *e, u_word *signature, u_word *r);

uint32_t ecc_check_point(ecc_point_a *point);

void bigint_generate_full_point_from_x(ecc_point_a *point);

#endif
