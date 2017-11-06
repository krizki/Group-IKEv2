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

/**
 * \file
 *    Length of material consumed or produced by cryptographic functions
 *    used by IEEE 802.15.4
 * \author
 *    Runar Mar Magnusson <rmma@kth.se>
 *
 */

#include <contiki.h>
#include "ieee-802-15-4-sa.h"

/*---------------------------------------------------------------------------*/
uint8_t
get_encr_ieee_icvlen(uint8_t transform)
{
  switch(transform) {
    case SA_ENCR_IEEE_AES_CCM_STAR_128_0:
      return 0;
    case SA_ENCR_IEEE_AES_CCM_STAR_128_4:
      return 4;
    case SA_ENCR_IEEE_AES_CCM_STAR_128_8:
      return 8;
    case SA_ENCR_IEEE_AES_CCM_STAR_128_16:
      return 16;
    default:
      return 0;
  }
}
/*---------------------------------------------------------------------------*/
uint8_t
get_integ_ieee_icvlen(uint8_t transform)
{
  switch(transform) {
    case SA_INTEG_IEEE_AES_CCM_STAR_128_4:
      return 4;
    case SA_INTEG_IEEE_AES_CCM_STAR_128_8:
      return 8;
    case SA_INTEG_IEEE_AES_CCM_STAR_128_16:
      return 16;
    default:
      return 0;
  }
}
/*---------------------------------------------------------------------------*/
uint8_t
get_integ_ieee_keymat_len(uint8_t transform)
{
  if(transform == SA_INTEG_IEEE_AES_CCM_STAR_128_4
     || transform == SA_INTEG_IEEE_AES_CCM_STAR_128_8
     || transform == SA_INTEG_IEEE_AES_CCM_STAR_128_16) {
    return IKE_IEEE_KEY_LEN;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
uint8_t
get_encr_ieee_keymat_len(uint8_t transform)
{
  if(transform == SA_ENCR_IEEE_AES_CCM_STAR_128_0
     || transform == SA_ENCR_IEEE_AES_CCM_STAR_128_4
     || transform == SA_ENCR_IEEE_AES_CCM_STAR_128_8
     || transform == SA_ENCR_IEEE_AES_CCM_STAR_128_16) {
    return IKE_IEEE_KEY_LEN;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
uint8_t
get_ieee_lvl_from_transform(uint8_t transform)
{
  switch(transform) {
    case SA_INTEG_IEEE_AES_CCM_STAR_128_4:
      return 1;
    case SA_INTEG_IEEE_AES_CCM_STAR_128_8:
      return 2;
    case SA_INTEG_IEEE_AES_CCM_STAR_128_16:
      return 3;
    case SA_ENCR_IEEE_AES_CCM_STAR_128_0:
      return 4;
    case SA_ENCR_IEEE_AES_CCM_STAR_128_4:
      return 5;
    case SA_ENCR_IEEE_AES_CCM_STAR_128_8:
      return 6;
    case SA_ENCR_IEEE_AES_CCM_STAR_128_16:
      return 7;
  }

  return 0;
}
/*---------------------------------------------------------------------------*/
