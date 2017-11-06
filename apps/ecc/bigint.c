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
 *		Oriol Piñol <oriol@sics.se>
 *    Runar Mar Magnusson <rmma@kth.se> - added HW ECC functions for CC2538
 *
 */

#include "bigint.h"
#include <stdio.h>              /* For printf() */

#ifdef HW_ECC
#include "cpu/cc2538/dev/pka.h"
#include "cpu/cc2538/dev/ecc-curve-info.h"
#endif
/*---------------------------------------------------------------------------*/
void
bigint_null(u_word *a, u_byte digits)
{

  u_byte i;

  for(i = 0; i < digits; i++) {
    a[i] = 0;
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_print(u_word *a, u_byte digits)
{
  signed char j;

  printf("0x");
  for(j = digits - 1; j >= 0; j--) {
#ifdef WORDS_32_BITS
    printf("%08x", (unsigned int)a[j]);
#endif
#ifdef WORDS_16_BITS
    printf("%04x", a[j]);
#endif
  }
  printf("\n");
}
/*---------------------------------------------------------------------------*/
void
bigint_copy(u_word *a, u_word *b, u_byte digits)
{
  u_byte i;

  for(i = 0; i < digits; i++) {
    b[i] = a[i];
  }
}
/*---------------------------------------------------------------------------*/
u_byte
bigint_is_zero(u_word *a, u_byte digits)
{

  u_byte i;

  for(i = 0; i < digits; i++) {
    if(a[i] != 0) {
      return 0;
    }
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
u_byte
bigint_digit_length(u_word *a, u_byte digits)
{
  u_byte length = digits;
  signed char j;

  for(j = (digits - 1); j >= 0; j--) {
    if(a[j]) {
      return length;
    }
    length--;
  }
  return length;
}
/*---------------------------------------------------------------------------*/
uint16_t
bigint_bit_length(u_word *a, u_byte digits)
{
  uint16_t length;
  signed char j;

  digits = bigint_digit_length(a, digits);
  if(digits == 0) {
    return 0;
  }
  length = digits * BIGINT_WORD_BITS;

  for(j = (BIGINT_WORD_BITS - 1); j >= 0; j--) {
    if(a[digits - 1] & (1 << j)) {
      return length;
    }
    length--;
  }
  return length;
}
/*---------------------------------------------------------------------------*/
void
bigint_encode(unsigned char *a, u_byte len, u_word *b, u_byte digits)
{
  u_word t;
  int j;
  unsigned int i, u;

  for(i = 0, j = len - 1; (i < digits) && (j >= 0); i++) {
    t = b[i];
    for(u = 0; j >= 0 && u < BIGINT_WORD_BITS; j--, u += 8) {
      a[j] = (unsigned char)(t >> u);
    }
  }

  for(; j >= 0; j--) {
    a[j] = 0;
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_decode(u_word *a, u_byte digits, unsigned char *b, u_byte len)
{
  u_word t;
  int j;
  unsigned int i, u;

  for(i = 0, j = len - 1; (i < digits) && (j >= 0); i++) {
    t = 0;
    for(u = 0; j >= 0 && u < BIGINT_WORD_BITS; j--, u += 8) {
      t |= ((u_word)b[j]) << u;
    }
    a[i] = t;
  }

  for(; i < digits; i++) {
    a[i] = 0;
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_to_network_bytes(uint8_t data[], u_word *a, u_byte digits)
{
  u_byte i;

  for(i = 0; i < digits; i++) {       /* 32-BITS-WORDS */
    data[4 * i] = (uint8_t)(a[digits - 1 - i] >> 24);
    data[4 * i + 1] = (uint8_t)(a[digits - 1 - i] >> 16);
    data[4 * i + 2] = (uint8_t)(a[digits - 1 - i] >> 8);
    data[4 * i + 3] = (uint8_t)(a[digits - 1 - i]);
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_network_bytes_to_bigint(u_word *a, uint8_t data[], u_byte bytes)
{
  u_byte i;

  for(i = 0; i < bytes / 4; i++) {
    a[i] = data[bytes - 1 - 4 * i];
    a[i] |= (data[bytes - 1 - 4 * i - 1] << 8);
    a[i] |= (data[bytes - 1 - 4 * i - 2] << 16);
    a[i] |= (data[bytes - 1 - 4 * i - 3] << 24);
  }
}
/*---------------------------------------------------------------------------*/
u_byte
bigint_increment(u_word *a, u_byte digits) 
{ 
  u_byte i;

  a[0]++;
  if(!a[0]) {
    for(i = 1; i < digits; i++) {
      a[i]++;
      if(a[i]) {
        return 0;
      }
    }
  } else {
    return 0;
  } 
  return 1;
}
/*---------------------------------------------------------------------------*/
u_word
bigint_add(u_word *a, u_word *b, u_word *c, u_byte digits) 
{ 
  u_word carry, ai;
  u_byte i;

  carry = 0;

  for(i = 0; i < digits; i++) {
    if((ai = b[i] + carry) < carry) {
      ai = c[i];
    } else if((ai += c[i]) < c[i]) {
      carry = 1;
    } else {
      carry = 0;
    }
    a[i] = ai;
  }

  return carry;
}
/*---------------------------------------------------------------------------*/
void
bigint_negate(u_word *a, u_byte digits)
{
  u_byte i;

  for(i = 0; i < digits; i++) {
    a[i] = ~a[i];
  }
}
/*---------------------------------------------------------------------------*/
u_word
bigint_substract(u_word *a, u_word *b, u_word *c, u_byte digits) 
{ 
  u_word c_neg[digits];

  bigint_copy(c, c_neg, digits);

  bigint_negate(c_neg, digits);

  bigint_increment(c_neg, digits);

  return bigint_add(a, b, c_neg, digits);
}
/*---------------------------------------------------------------------------*/
void
bigint_basic_mult(u_word *a, u_word b, u_word c)
{
  u_doubleword aux;

  aux = (u_doubleword)(b) * (c);
  a[0] = (u_word)aux;
  a[1] = (u_word)((u_doubleword)aux >> BIGINT_WORD_BITS);
}
/*---------------------------------------------------------------------------*/
void
bigint_square(u_word *a, u_word *b, u_byte digits) 
{ 
  u_word aux_a[2 * digits + 1];

  u_byte i, j;

  u_word uv[3];

  u_word c[2];

  bigint_null(aux_a, 2 * digits + 1);
  bigint_null(uv, 3);
  bigint_null(c, 2);

  for(i = 0; i < digits; i++) {
    bigint_null(uv, 3);
    bigint_basic_mult(uv, b[i], b[i]);

    uv[0] = uv[0] + aux_a[2 * i];
    if(uv[0] < aux_a[2 * i]) {
      uv[1]++;
      if(uv[1] == 0) {
        uv[2]++;                /* 0xFFFF^2+0xFFFF < 0xFFFFFFFFFFFF */
      }
    }

    aux_a[2 * i] = uv[0];

    bigint_copy(&uv[1], c, 2);

    for(j = i + 1; j < digits; j++) {
      bigint_null(uv, 3);
      bigint_basic_mult(uv, b[j], b[i]);
      uv[2] = bigint_shift_bits_left(uv, 1, 2);
      uv[0] = uv[0] + aux_a[i + j];
      if(uv[0] < aux_a[i + j]) {
        uv[1]++;
        if(uv[1] == 0) {
          uv[2]++;
        }
      }
      uv[2] += bigint_add(uv, uv, c, 2);
      aux_a[i + j] = uv[0];
      bigint_copy(&uv[1], c, 2);
    }
    while(!bigint_is_zero(c, 2)) {
      bigint_null(uv, 3);
      uv[0] = aux_a[i + j];
      uv[2] = bigint_add(uv, uv, c, 2);
      aux_a[i + j] = uv[0];
      bigint_copy(&uv[1], c, 2);
      j++;
    }
  }
  bigint_copy(aux_a, a, digits * 2);
}
/*---------------------------------------------------------------------------*/
void
bigint_multiply(u_word *a, u_word *b, u_word *c, u_byte m, u_byte n) 
{ 
#ifdef HW_ECC
  /* Variables used by the hardware module */
  uint32_t resultVector, pui32Len;
  uint8_t pka_status;

  resultVector = 0;
  pui32Len = m + n;

  /* Wait for the PKA driver to become available */
  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);

  pka_status = PKABigNumMultiplyStart(b, m, c, n, &resultVector);
  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);
  if(pka_status == PKA_STATUS_SUCCESS) {
    /* Assuming that a is always m + n */
    pka_status = PKABigNumMultGetResult(a, &pui32Len, resultVector);
  }
#else

  u_word uv[2];
  u_word result[m + n];
  u_byte i, j;
  u_word carry;

  bigint_null(result, m + n);
  uv[0] = 0;
  uv[1] = 0;

  for(i = 0; i < n; i++) {
    carry = 0;
    for(j = 0; j < m; j++) {
      bigint_basic_mult(uv, b[j], c[i]);
      uv[0] = uv[0] + result[i + j];
      if(uv[0] < result[i + j]) {
        uv[1]++;
      }
      uv[0] = uv[0] + carry;
      if(uv[0] < carry) {
        uv[1]++;
      }
      result[i + j] = uv[0];
      carry = uv[1];
    }
    result[i + m] = uv[1];
  }

  bigint_copy(result, a, m + n);
#endif
}
/*---------------------------------------------------------------------------*/
void
bigint_multiply_trunc(u_word *a, u_word *b, u_word *c, u_byte n) 
{ 
  u_word uv[2];
  u_word result[n];
  u_byte i, j;
  u_word carry;

  bigint_null(result, n);

  for(i = 0; i < bigint_digit_length(c, n); i++) {      /* Avoid 0's on top, smaller */
    carry = 0;
    for(j = 0; j < (n - i); j++) {
      bigint_basic_mult(uv, b[j], c[i]);
      uv[0] = uv[0] + result[i + j];
      if(uv[0] < result[i + j]) {
        uv[1]++;
      }
      uv[0] = uv[0] + carry;
      if(uv[0] < carry) {
        uv[1]++;
      }
      result[i + j] = uv[0];
      carry = uv[1];
    }
  }
  bigint_copy(result, a, n);
}
/*---------------------------------------------------------------------------*/
void
bigint_shift_digits_left(u_word *a, u_byte positions, u_byte digits)
{
  signed char i;

  if(positions == 0) {
    return;
  }
  for(i = digits - 1; i >= positions; i--) {
    a[i] = a[i - positions];
  }
  for(; i >= 0; i--) {
    a[i] = 0;
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_shift_digits_right(u_word *a, u_byte positions, u_byte digits)
{

  u_byte i;

  for(i = 0; i < digits - positions; i++) {
    a[i] = a[i + positions];
  }
  for(; i < digits; i++) {
    a[i] = 0;
  }
}
/*---------------------------------------------------------------------------*/
u_word
bigint_shift_bits_left(u_word *a, u_byte bits, u_byte digits)
{

  u_byte i = 0;
  u_word aux, carry;

  carry = 0;

  if(bits >= BIGINT_WORD_BITS) {
    i = bits / BIGINT_WORD_BITS;
    bigint_shift_digits_left(a, i, digits);
    bits = bits % BIGINT_WORD_BITS;
    if(bits == 0) {
      return carry;
    }
  }
  for(; i < digits; i++) {
    aux = a[i];
    a[i] = (aux << bits);
    a[i] |= carry;
    carry = aux >> (BIGINT_WORD_BITS - bits);
  }

  return carry;
}
/*---------------------------------------------------------------------------*/
void
bigint_shift_bits_right(u_word *a, u_byte bits, u_byte digits)
{

  u_byte i;

  if(bits >= BIGINT_WORD_BITS) {
    i = bits / BIGINT_WORD_BITS;
    bigint_shift_digits_right(a, i, digits);
    bits = bits % BIGINT_WORD_BITS;
    if(bits == 0) {
      return;
    }
    digits -= i;
  }

  if(bits == 0) {
    return;
  }

  for(i = 0; i < (digits - 1); i++) {
    a[i] = a[i] >> bits;
    a[i] |= (a[i + 1] << (BIGINT_WORD_BITS - bits));
  }
  a[digits - 1] = a[digits - 1] >> bits;
}
/*---------------------------------------------------------------------------*/
signed char
bigint_compare(u_word *a, u_word *b, u_byte digits)
{
#ifdef HW_ECC   /* slower than non hw? */
  uint8_t pka_status;

  /* Check if there is a PKA operation running then start the comparison*/
  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);
  pka_status = PKABigNumCmpStart(a, b, digits);

  /* Wait for the PKA driver to finish the operation */
  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);
  if(pka_status == PKA_STATUS_SUCCESS) {
    pka_status = PKABigNumCmpGetResult();
    if(pka_status == PKA_STATUS_A_GR_B) {
      return 1;
    } else if(pka_status == PKA_STATUS_A_LT_B) {
      return -1;
    } else if(pka_status == PKA_STATUS_SUCCESS) {
      return 0;
    }
  }

  return 0;
#else
  signed char j;

  for(j = (digits - 1); j >= 0; j--) {
    if(a[j] != b[j]) {
      if(a[j] > b[j]) {
        return 1;
      } else {
        return -1;
      }
    }
  }
  return 0;
#endif
}
/*---------------------------------------------------------------------------*/
u_word
reciprocal(u_word *d)           
{ 
  u_doubleword aux = MAX_BIGINT_WORD - (*d);

  aux = aux << BIGINT_WORD_BITS;
  aux += MAX_BIGINT_WORD;
  return (u_word)(aux / (*d));
}
/*---------------------------------------------------------------------------*/
u_word
basic_division(u_word *u, u_word *d, u_word *q, u_word *v) 
{ 
  /* Requires B/2<=d<B u1<d                        //algorithm 4 */
  u_word q_aux[2];
  u_word r;

  bigint_basic_mult(q_aux, *v, u[1]);
  bigint_add(q_aux, q_aux, u, 2);
  q_aux[1]++;
  r = (u_word)(q_aux[1] * (*d));
  r = u[0] - r;
  if(r > q_aux[0]) {
    q_aux[1]--;
    r = r + (*d);
  }
  if(r >= (*d)) {
    q_aux[1]++;
    r = r - (*d);
  }

  if(q != NULL) {
    q[0] = q_aux[1];
  }
  return r;
}
/*---------------------------------------------------------------------------*/
u_word
bigint_divisionNby1(u_word *u, u_word *d, u_word *q, u_byte digits) 
{ 
  int8_t j;                     /* algorithm 7 */
  u_word v, r, d_aux;
  u_word cpy_u[digits];         /* Always called with 2 */
  u_word aux[2];
  u_byte k = 0;

  bigint_copy(u, cpy_u, digits);
  d_aux = *d;
  r = 0;
  if(!((*d) & (1 << (BIGINT_WORD_BITS - 1)))) { /* Normalize d */
    k = BIGINT_WORD_BITS - bigint_bit_length(d, 1);
    d_aux = d_aux << k;
    r = bigint_shift_bits_left(cpy_u, k, digits);       /* NOT LOOSE THE TOP BITS */
  }
  v = reciprocal(&d_aux);
  for(j = (digits - 1); j >= 0; j--) {
    aux[1] = r;
    aux[0] = cpy_u[j];
    if(q != NULL) {
      r = basic_division(aux, &d_aux, &q[j], &v);       /* We are sure d normalized and aux[1]<d (comes from r or from shift). */
    } else {
      r = basic_division(aux, &d_aux, NULL, &v);
    }
  }
  return r >> k;                /* fix reminder after normalizing */
}
/*---------------------------------------------------------------------------*/
void
bigint_divisionMbyN(u_word *u, u_word *d_a, u_word *q, u_word *r,
                    u_byte m, u_byte n) 
{ 
  /* Assumes q and r have m digits, m>=n */

  u_byte i, m_aux, n_aux;
  u_byte k = 0;
  u_word u_aux[m + 1];          /* +1 To fit the normalization */
  u_word q_aux[m + 1];          /* +1 To fit the normalization */
  u_word d[n];
  u_word aux[3];
  u_word aux2[n + 1];

  m_aux = bigint_digit_length(u, m);
  n_aux = bigint_digit_length(d_a, n);

  if(m_aux < n_aux) {
    if(q != NULL) {
      bigint_null(q, m);
    }
    if(r != NULL) {
      bigint_copy(u, r, m);
    }
    return;
  }

  bigint_copy(u, u_aux, m);
  bigint_copy(d_a, d, n);
  bigint_null(q_aux, m + 1);
  bigint_null(aux, 3);
  bigint_null(aux2, n + 1);

  if(!((d[n_aux - 1]) & (1 << (BIGINT_WORD_BITS - 1)))) {       /* Normalize d */
    k = BIGINT_WORD_BITS - bigint_bit_length(&d[n_aux - 1], 1);
    bigint_shift_bits_left(d, k, n_aux);
    u_aux[m_aux] = bigint_shift_bits_left(u_aux, k, m_aux);     /* NOT LOOSE THE TOP BITS */
    if(u_aux[m_aux]) {
      m_aux++;
    }
  }

  while(bigint_compare(&u_aux[m_aux - n_aux], d, n_aux) >= 0) { /* bigint_compare u, d*b^(m-n) */
    q_aux[m_aux - n_aux]++;
    bigint_substract(&u_aux[m_aux - n_aux], &u_aux[m_aux - n_aux], d, n_aux);
  }

  for(i = m_aux - 1; i >= n_aux; i--) {
    if(u_aux[i] == d[n_aux - 1]) {
      q_aux[i - n_aux] = MAX_BIGINT_WORD;
    } else {
      bigint_divisionNby1(&u_aux[i - 1], &d[n_aux - 1], aux, 2);        /* Using aux variable to fit 2 digits quotient */
      q_aux[i - n_aux] = aux[0];
    }
    if(n_aux > 1) {
      bigint_multiply(aux, &d[n_aux - 2], &q_aux[i - n_aux], 2, 1);
      while(bigint_compare(aux, &u_aux[i - 2], 3) > 0) {
        q_aux[i - n_aux]--;
        bigint_multiply(aux, &d[n_aux - 2], &q_aux[i - n_aux], 2, 1);
      }
    } else {
      bigint_basic_mult(&aux[1], *d, q_aux[i - n_aux]);
      if(i != n_aux) {
        while(bigint_compare(aux, &u_aux[i - 2], 3) > 0) {
          q_aux[i - n_aux]--;
          bigint_basic_mult(&aux[1], *d, q_aux[i - n_aux]);
        }
      } else {
        while(bigint_compare(&aux[1], &u_aux[i - 1], 2) > 0) {
          q_aux[0]--;
          bigint_basic_mult(&aux[1], *d, q_aux[0]);
        }
      }
    }
    bigint_multiply(aux2, d, &q_aux[i - n_aux], n_aux, 1);
    if(bigint_compare(&u_aux[i - n_aux], aux2, n_aux + 1) >= 0) {
      bigint_substract(&u_aux[i - n_aux], &u_aux[i - n_aux], aux2, n_aux + 1);
    } else {
      q_aux[i - n_aux]--;
      bigint_multiply(aux2, d, &q_aux[i - n_aux], n_aux, 1);
      bigint_substract(&u_aux[i - n_aux], &u_aux[i - n_aux], aux2, n_aux + 1);
    }
  }

  if(q != NULL) {
    bigint_copy(q_aux, q, m);
  }
  if(r != NULL) {
    bigint_null(r, m);
    bigint_shift_bits_right(u_aux, k, n);
    bigint_copy(u_aux, r, n);
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_amodb(u_word *r, u_word *a, u_word *b, u_byte digitsA,
             u_byte digitsB)
{
#ifdef HW_ECC
  uint32_t resultVector;
  uint8_t ui8NLen, pka_status;

  resultVector = 0;
  ui8NLen = digitsB;

  /* Wait for the PKA driver to become available */
  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);
  pka_status = PKABigNumModStart(a, digitsA, b, digitsB, &resultVector);

  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);
  if(pka_status == PKA_STATUS_SUCCESS) {
    /* Assuming that a is always 2 * digits */
    pka_status = PKABigNumModGetResult(r, ui8NLen, resultVector);
  }
#else
  bigint_divisionMbyN(a, b, NULL, r, digitsA, digitsB); /* Module with simple division. */
#endif
}
void
bigint_mod_add(u_word *a, u_word *b, u_word *c, u_word *n, u_byte digits)
{
  /* Assumes b = b mod N  .. c = c mod N */

  if(bigint_add(a, b, c, digits)) {     /* If carry */
    bigint_substract(a, a, n, digits);
  } else if(bigint_compare(a, n, digits) > 0) {
    bigint_substract(a, a, n, digits);
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_mod_substract(u_word *a, u_word *b, u_word *c, u_word *n,
                     u_byte digits)
{
  /* Assumes b = b mod N, c = c mod N, returns a = (b-c) mod n */

  if(bigint_compare(b, c, digits) >= 0) {
    bigint_substract(a, b, c, digits);
  } else {                      /* (b-c) mod n = n - (c-b) mod n */
    bigint_substract(a, c, b, digits);
    bigint_substract(a, n, a, digits);
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_mod_multiply(u_word *a, u_word *b, u_word *c, u_word *n,
                    u_byte digitsb, u_byte digitsc) 
{ 
  /* n has NUMWORD  digits */
  u_word aux[digitsb + digitsc];

  bigint_null(aux, digitsb + digitsc);
  bigint_multiply(aux, b, c, digitsb, digitsc);
  bigint_amodb(aux, aux, n, digitsb + digitsc, NUMWORDS);
  bigint_copy(aux, a, NUMWORDS);        /* RECHECK ALL THIS */
}
/*---------------------------------------------------------------------------*/
void
bigint_mod_square(u_word *a, u_word *b, u_word *n, u_byte digits) 
{ 
  /* n[digits-1] != 0 */
  u_word aux[2 * digits];

  bigint_null(aux, digits * 2);
  bigint_square(aux, b, digits);
  bigint_amodb(aux, aux, n, digits * 2, digits);
  bigint_copy(aux, a, digits);
}
/*---------------------------------------------------------------------------*/
void
bigint_mod_dividebypow2(u_word *a, u_word *b, u_byte power, u_word *p,
                        u_byte digits) 
{ 
  /* Idea from IEEE */
  u_byte i;
  u_word aux;

  bigint_copy(b, a, digits);

  for(i = 0; i < power; i++) {
    if(a[0] & 1) {              /* Divide by 2. If odd add p and shift right */
      aux = bigint_add(a, a, p, NUMWORDS);
      bigint_shift_bits_right(a, 1, NUMWORDS);
      if(aux != 0) {            /* if there was carry */
        a[NUMWORDS - 1] |= (1 << (BIGINT_WORD_BITS - 1));
      }
    } else {                    /* If even simply shift right */
      bigint_shift_bits_right(a, 1, NUMWORDS);
    }
  }
}
/*---------------------------------------------------------------------------*/
void
bigint_mod_square_root(u_word *a, u_word *b, u_word *p, u_byte digits) 
{ 
  /* From IEEE 1363-2000 Only for p = 3 (mod 4) */
  u_word aux[NUMWORDS];

  bigint_copy(p, aux, NUMWORDS);
  bigint_increment(aux, NUMWORDS);      /* (p+1)/4 From RFC6090 */
  bigint_mod_dividebypow2(aux, aux, 2, p, digits);
  NN_power_mod(a, b, aux, digits, p, digits);   /* DIGITS? //RFC6090 Appendix C */
}
/*---------------------------------------------------------------------------*/
void
bigint_gcd(u_word *a, u_word *u, u_word *v, u_byte digitsu, u_byte digitsv) 
{ 
  u_word u_aux[digitsu];
  u_word v_aux[digitsv];
  u_word r[digitsv];

  bigint_copy(u, u_aux, digitsu);
  bigint_copy(v, v_aux, digitsv);

  while(!bigint_is_zero(v_aux, digitsv)) {
    bigint_amodb(r, u_aux, v_aux, digitsu, digitsv);
    bigint_null(u_aux, digitsu);
    bigint_copy(v_aux, u_aux, digitsv);
    bigint_copy(r, v_aux, digitsv);
  }

  bigint_copy(u_aux, a, digitsu);
}
/*---------------------------------------------------------------------------*/
void
bigint_binary_gcd(u_word *a, u_word *u, u_word *v, u_byte digits) 
{ 
  /* digits a = digits b = digits c */  
  u_word u_aux[digits];
  u_word v_aux[digits];
  u_byte k = 0;

  if(bigint_compare(u, v, digits) >= 0) {
    bigint_copy(u, u_aux, digits);
    bigint_copy(v, v_aux, digits);
  } else {
    bigint_copy(u, v_aux, digits);
    bigint_copy(v, u_aux, digits);
  }
  while(!((1 & u_aux[0]) || (1 & v_aux[0]))) {
    k++;
    bigint_shift_bits_right(u_aux, 1, digits);
    bigint_shift_bits_right(v_aux, 1, digits);
  }

  while(!bigint_is_zero(u_aux, digits)) {
    while(!(1 & u_aux[0])) {
      bigint_shift_bits_right(u_aux, 1, digits);
    }
    while(!(1 & v_aux[0])) {
      bigint_shift_bits_right(v_aux, 1, digits);
    }
    if(bigint_compare(u_aux, v_aux, digits) >= 0) {
      bigint_substract(u_aux, u_aux, v_aux, digits);
      bigint_shift_bits_right(u_aux, 1, digits);
    } else {
      bigint_substract(v_aux, v_aux, u_aux, digits);
      bigint_shift_bits_right(v_aux, 1, digits);
    }
  }

  bigint_copy(v_aux, a, digits);
  if(k != 0) {
    bigint_shift_bits_left(a, k, digits);
  }
}
/*---------------------------------------------------------------------------*/
u_byte
bigint_modif_extended_euclids(u_word *u1, u_word *u, u_word *v,
                              u_byte digits) 
{ 
  u_word v1[digits], v3[digits], t1[digits], t3[digits], q[digits], u3[digits]; /* Algorithm X p 342 */

  /* u1,u2,v1,v2 remain bounded by size of u,v */

  u_byte u1sign;

  bigint_null(u1, digits);
  u1[0] = 1;
  u1sign = 1;

  bigint_copy(u, u3, digits);

  bigint_null(v1, digits);
  bigint_copy(v, v3, digits);

  while(!bigint_is_zero(v3, digits)) {
    bigint_null(q, digits);
    bigint_divisionMbyN(u3, v3, q, NULL, digits, digits);
    bigint_multiply_trunc(t1, v1, q, digits);
    bigint_multiply_trunc(t3, v3, q, digits);
    bigint_add(t1, u1, t1, digits);
    bigint_substract(t3, u3, t3, digits);       /* Always positive */
    u1sign = (u1sign + 1) % 2;
    bigint_copy(v1, u1, digits);
    bigint_copy(v3, u3, digits);
    bigint_copy(t1, v1, digits);
    bigint_copy(t3, v3, digits);
  }

  return u1sign;
}
/*---------------------------------------------------------------------------*/
void
bigint_modular_inverse(u_word *a, u_word *b, u_word *n, u_byte digits)
{
#ifdef HW_ECC
  uint32_t resultVector;
  uint8_t ui8NLen, pka_status;

  ui8NLen = digits;
  resultVector = 0;

  /* Wait for the PKA driver to become available */
  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);

  pka_status = PKABigNumInvModStart(b, digits, n, digits, &resultVector);

  do {} while(PKAGetOpsStatus() == PKA_STATUS_OPERATION_INPRG);
  if(pka_status == PKA_STATUS_SUCCESS) {
    /* Assuming that a is always digits length*/
    pka_status = PKABigNumInvModGetResult(a, ui8NLen, resultVector);
  }
#else
  u_word res[digits];

  bigint_null(res, digits);

  bigint_binary_gcd(res, b, n, digits);

  if(res[0] == 1) {
    if(!bigint_modif_extended_euclids(res, b, n, digits)) {     /* if res = -(b^-1) */
      bigint_substract(res, n, res, digits);    /* res = b^-1 mod n */
    }
    bigint_copy(res, a, digits);
  } else {                      /* bigint_gcd(b,n)=!1, no inverse */
    bigint_null(a, digits);
  }
#endif
}
/*---------------------------------------------------------------------------*/
void
power_mod(u_word *a, u_word *b, u_byte x, u_byte digits, u_word *m,
          u_byte mdigits)       
{ 
  /* a = b^x mod m //digits = mdigits now */
  /* digits is digits b. a has mdigits From HAC pp 614 */
  u_word s[digits];

  bigint_copy(b, s, digits);
  bigint_null(a, digits);
  a[0] = 1;

  while(x) {
    if(x & 1) {                 /* x odd */
      bigint_mod_multiply(a, s, a, m, digits, bigint_digit_length(a, digits));
    }
    x = x >> 1;
    if(x) {
      bigint_mod_square(s, s, m, digits);
    }
  }
}
/*---------------------------------------------------------------------------*/
void
NN_power_mod(u_word *a, u_word *b, u_word *x, u_byte digits, u_word *m,
             u_byte mdigits)    
{ 
  /* a = b^x mod m //digits = mdigits now */
  /* Following right-to-left binary but not dividing, just going through all digits */
  u_word y[digits], z[digits];
  u_byte i;
  uint16_t j;

  bigint_null(y, digits);
  bigint_null(z, digits);

  y[0] = 1;
  bigint_copy(b, z, digits);
  for(i = 0; i < (bigint_digit_length(x, digits) - 1); i++) {
    for(j = 0; j < BIGINT_WORD_BITS; j++) {
      if((x[i] >> j) & 1) {     
        /* N odd */
        bigint_mod_multiply(y, z, y, m, digits, digits);
      }
      bigint_mod_square(z, z, m, digits);
    }
  }

  i = bigint_digit_length(x, digits) - 1;
  for(j = 0; j < bigint_bit_length(&x[i], 1); j++) {
    if((x[i] >> j) & 1) {       
      /* N odd */
      bigint_mod_multiply(y, z, y, m, digits, digits);
    }
    bigint_mod_square(z, z, m, digits);
  }
  bigint_copy(y, a, digits);
}
/*---------------------------------------------------------------------------*/
void
bigint_modsmall(u_word *a, u_word *b, u_byte digits)
{
  while(bigint_compare(a, b, digits) > 0) {
    bigint_substract(a, a, b, digits);
  }
}
