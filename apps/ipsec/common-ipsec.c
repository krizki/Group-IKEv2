/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *      Common functionality for IPsec described in RFC 4301
 * \author
 *			Vilhelm Jutvik <ville@imorgon.se>
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

#include <string.h>
#include "common-ipsec.h"

/**
 * DEBUG stuff
 */
/*---------------------------------------------------------------------------*/
void
memprint(uint8_t *ptr, const uint16_t len)
{
  uint16_t r, s, t;
  for(r = 0; r < (len / 16) + 1; ++r) {  /* Row */
    printf("%p (%4u) ", (uint8_t *)ptr + r * 16, r * 16);
    for(s = 0; s < 4; ++s) {  /* Group */
      for(t = 0; t < 4; ++t) {
        printf("%.2X ", ptr[r * 16 + s * 4 + t]);
      }
      printf(" ");
    }
    printf("\n");
  }
}
/*---------------------------------------------------------------------------*/
void
hexdump(const unsigned char *packet, int length)
{
  if(length > 0) {
    int n = 0;

    while(length--) {
      if(n % 16 == 0) {
        printf("%08X ", n);
      }
      printf("%02X ", *packet++);

      n++;
      if(n % 8 == 0) {
        if(n % 16 == 0) {
          printf("\n");
        } else {
          printf(" ");
        }
      }
    }
  }
  printf("\n");
}
/*---------------------------------------------------------------------------*/
uint8_t
uip6_addr_a_is_in_closed_interval_bc(uip_ip6addr_t *a, uip_ip6addr_t *b, uip_ip6addr_t *c)
{
  return memcmp(a, b, sizeof(uip_ip6addr_t)) >= 0 && memcmp(a, c, sizeof(uip_ip6addr_t)) <= 0;
}
/*---------------------------------------------------------------------------*/
uint8_t
ipsec_a_is_member_of_b(ipsec_addr_t *a, ipsec_addr_set_t *b)
{
  return uip6_addr_a_is_in_closed_interval_bc(&a->peer_addr, b->peer_addr_from, b->peer_addr_to) &&
         a_is_in_closed_interval_bc(a->my_port, b->my_port_from, b->my_port_to) &&
         a_is_in_closed_interval_bc(a->peer_port, b->peer_port_from, b->peer_port_to) &&
         (b->nextlayer_proto == SPD_SELECTOR_NL_ANY_PROTOCOL || a->nextlayer_proto == b->nextlayer_proto);
}
/** @} */
