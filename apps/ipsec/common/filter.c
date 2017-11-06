/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *        Filtering of IP packets as described in RFC 4301
 * \author
 *				Vilhelm Jutvik <ville@imorgon.se>
 *				Argyro Lamproudi <argyro@student.chalmers.se>
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

#include <contiki.h>
#include "ipsec.h"
#include "sad.h"
#include "spd.h"
#include "common-ipsec.h"

uint8_t
ipsec_filter(sad_entry_t *sad_entry, ipsec_addr_t *addr, uint8_t security_proto)
{
  if(sad_entry) {
    /**
     * This packet was protected.
     *
     * Assert that the packet's addr is a subset of the SA's selector
     * (p. 62 part 4 and 5)
     * We don't implement the IKE notification as described in part 5.
     *
     * The reason that we don't assert this earlier is that the next layer
     * might enjoy confidentiality protection and hence we must decrypt it first to
     * get the port numbers from the next layer protocol.
     */
    IPSEC_PRINTF("TRAFFIC DESC:\n");
    PRINTADDRSET(&sad_entry->traffic_desc);
    IPSEC_PRINTF("ADDR:\n");
    PRINTADDR(addr);
    printf("\n");
    if(ipsec_a_is_member_of_b(addr, &sad_entry->traffic_desc)) {
      /* FIX: Update SA statistics */
      return 0;
    }
      /* Drop the packet */
    IPSEC_PRINTF(IPSEC "Dropping incoming packet because the SAD entry's (referenced by the packet's SPI) selector didn't match the address of the packet\n");
  } else {
    /*
     * This packet was unprotected. We fetch the SPD entry so that we can verify
     * that this is in accordance with our policy.
     */
    spd_entry_t *spd_entry = spd_get_entry_by_addr(addr, security_proto);

    IPSEC_PRINTF("Applicable packet policy:\n");
    PRINTSPDENTRY(spd_entry);
    switch(spd_entry->proc_action) {
    case SPD_ACTION_BYPASS:
      return 0;

    case SPD_ACTION_PROTECT:
      /**
       * Unprotected packets that match a PROTECT policy MUST
       *   1) be discarded
       *   2) there should not be any attempt of negotiating an SA
       * (3b. p. 62)
       */
      IPSEC_PRINTF(IPSEC "Dropping unprotected incoming packet (policy PROTECT)\n");
      break;

    case SPD_ACTION_DISCARD:
      IPSEC_PRINTF(IPSEC "Dropping unprotected incoming packet (policy DISCARD)\n");
    }
  }
  return 1; /* Drop the packet */
}
/** @} */
