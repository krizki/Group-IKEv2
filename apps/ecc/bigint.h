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
 *    Big Integer arithmetic operations
 * \author
 *    Oriol Piñol <oriol@sics.se>
 *    Runar Mar Magnusson <rmma@kth.se> - added HW ECC functions for CC2538
 *
 */

#ifndef _BIGINT_H__
#define _BIGINT_H__

#include "stdint.h"

/* #define COMPACT_COORDINATES */

#if defined(SECP256R1) || defined(BPOOLP256R1)
#define KEY_LENGTH_BITS 256
#else
#if defined(BPOOLP160R1)
#define KEY_LENGTH_BITS 160
#else
#define KEY_LENGTH_BITS 192
#endif
#endif

#ifdef WORDS_32_BITS
typedef uint32_t u_word;
typedef uint64_t u_doubleword;
typedef uint16_t u_byte;

#define BIGINT_WORD_BITS 32
#define WORD_LEN_BYTES (BIGINT_WORD_BITS / 8) /**<-- Length of a word in bytes */
#define NUMWORDS (KEY_LENGTH_BITS / BIGINT_WORD_BITS) /**<-- length of key in words */

#define MAX_BIGINT_WORD 0xffffffff
#endif /* WORDS_32_BITS */

#ifdef WORDS_16_BITS
typedef uint16_t u_word;
typedef uint32_t u_doubleword;
typedef uint16_t u_byte;

#define BIGINT_WORD_BITS 16
#define WORD_LEN_BYTES (BIGINT_WORD_BITS / 8) /**<-- Length of a word in bytes */
#define NUMWORDS (KEY_LENGTH_BITS / BIGINT_WORD_BITS) /**<-- length of key in words */

#define MAX_BIGINT_WORD 0xffff
#endif /* WORDS_16_BITS */

void bigint_null(u_word *a, u_byte digits);

void bigint_print(u_word *a, u_byte digits);

void bigint_copy(u_word *a, u_word *b, u_byte digits);

u_byte bigint_is_zero(u_word *a, u_byte digits);

u_byte bigint_digit_length(u_word *a, u_byte digits);

uint16_t bigint_bit_length(u_word *a, u_byte digits);

/**
 *  Encodes the character string data into bigint
 * @param data pointer to the character string
 * @param len length of the character string
 * @param a pointer to the bigint
 * @param digits the length of bigint in words
 */
void bigint_encode(unsigned char *a, u_byte len, u_word *b, u_byte digits);

/**
 * Decodes the character string data into bigint a
 * @param a pointer to bigint of length digits
 * @param digits length of bigint in words
 * @param data pointer to character string
 * @param len the length of the character string in bytes
 */
void bigint_decode(u_word *a, u_byte digits, unsigned char *b, u_byte len);

void bigint_to_network_bytes(uint8_t data[], u_word * a, u_byte digits);

void bigint_network_bytes_to_bigint(u_word * a, uint8_t data[], u_byte bytes);

/**
 * Increment by 1, return if carry 
 * @param a
 * @param digits
 * @return Carry from increment
 */
u_byte bigint_increment(u_word *a, u_byte digits);

/**
 * Returns a carry from addition
 * a = b + c
 * @param a
 * @param b
 * @param c
 * @param digits
 * @return Carry from addition
 */
u_word bigint_add(u_word *a, u_word *b, u_word *c, u_byte digits);

void bigint_negate(u_word *a, u_byte digits);

/**
 * Carry = 1 if result positive, else 0 
 * a = b - c
 * @param a
 * @param b
 * @param c
 * @param digits
 * @return Carry from subtraction
 */
u_word bigint_substract(u_word *a, u_word *b, u_word *c, u_byte digits);

void bigint_basic_mult(u_word *a, u_word b, u_word c);

/** 
 * BigNum Math implementing cryptography page 150 
 */
void bigint_square(u_word *a, u_word *b, u_byte digits);

/**
 *  From handbook of applied cryptography pg 595 
 */
void bigint_multiply(u_word *a, u_word *b, u_word *c, u_byte m, u_byte n);

/** 
 * From handbook of applied cryptography pg 595  
 */
void bigint_multiply_trunc(u_word *a, u_word *b, u_word *c, u_byte n);

void bigint_shift_digits_left(u_word *a, u_byte positions, u_byte digits);

void bigint_shift_digits_right(u_word *a, u_byte positions, u_byte digits);

u_word bigint_shift_bits_left(u_word *a, u_byte bits, u_byte digits);

void bigint_shift_bits_right(u_word *a, u_byte bits, u_byte digits);

signed char bigint_compare(u_word *a, u_word *b, u_byte digits);

/** 
 * Improved division by invariant integers, requires b/2<=d 
 */
u_word reciprocal(u_word *d);

/** 
 * From Improved division by invariant integers 
 */
u_word basic_division(u_word *u, u_word *d, u_word *q, u_word *v);

/* 
 * From improved division by invariant int 
 */
u_word bigint_divisionNby1(u_word *u, u_word *d, u_word *q, u_byte digits);

/** 
 * From HAC p 598 
 */
void bigint_divisionMbyN(u_word *u, u_word *d, u_word *q, u_word *r,
                         u_byte m, u_byte n);

void bigint_amodb(u_word *r, u_word *a, u_word *b, u_byte digitsA,
                  u_byte digitsB);

void bigint_mod_add(u_word *a, u_word *b, u_word *c, u_word *n,
                    u_byte digits);

void bigint_mod_substract(u_word *a, u_word *b, u_word *c, u_word *n,
                          u_byte digits);

void bigint_mod_multiply(u_word *a, u_word *b, u_word *c, u_word *n,
                         u_byte digitsb, u_byte digitsc);

void bigint_mod_square(u_word *a, u_word *b, u_word *n, u_byte digits);

void bigint_mod_dividebypow2(u_word *a, u_word *b, u_byte power,
                             u_word *p, u_byte digits);

void bigint_mod_square_root(u_word *a, u_word *b, u_word *p,
                            u_byte digits);

/**  
 * From Knuth pg 337 
 */
void bigint_gcd(u_word *a, u_word *u, u_word *v, u_byte digitsu,
                u_byte digitsv);

/**
 *  HAC p 606 
 */
void bigint_binary_gcd(u_word *a, u_word *u, u_word *v, u_byte digits);

/** 
 * FROM Knuth, taking away v2,t2,u2 
 */
u_byte bigint_modif_extended_euclids(u_word *u1, u_word *u, u_word *v,
                                     u_byte digits);

void bigint_modular_inverse(u_word *a, u_word *b, u_word *n,
                            u_byte digits);

void power_mod(u_word *a, u_word *b, u_byte x, u_byte digits, u_word *m,
               u_byte mdigits);

void NN_power_mod(u_word *a, u_word *b, u_word *x, u_byte digits,
                  u_word *m, u_byte mdigits);

void bigint_modsmall(u_word *a, u_word *b, u_byte digits);

#endif
