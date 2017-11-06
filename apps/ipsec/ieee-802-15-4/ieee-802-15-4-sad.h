/**
 * \file
 *    The SAD for IEEE 802.15.4 and its interface
 * \author
 *	Runar Mar Magnusson <rmma@kth.se>
 *
 */

/*
 * Copyright (c) 2015, SICS
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

#ifndef __IEEE_SAD_H__
#define __IEEE_SAD_H__

#include "sa.h"
#include "ipsec.h"
#include "common-ipsec.h"
#include "ieee-802-15-4-traffic-selector.h"

#ifndef IKE_IEEE_SAD_ENTRIES
#define IKE_IEEE_SAD_ENTRIES 5
#endif

/**
 * Debug stuff
 */
/* Prints the SAD entry located at entry */

#ifndef IEEE_SAD_DBG
#define IEEE_SAD_DBG 1
#endif

#if IEEE_SAD_DBG
#include "net/ip/uip-debug.h"
#define SAD_PRINTF(...) printf(__VA_ARGS__)
#define SAD_HEXDUMP(...) hexdump(__VA_ARGS__)
#define SAD_PRINTIEEEADDRSET(addr_set) \
  do { \
    SAD_PRINTF("Peer address from to: "); \
    PRINTLLADDR((addr_set)->peer_lladdr_from); \
    SAD_PRINTF(" - "); \
    PRINTLLADDR((addr_set)->peer_lladdr_to); \
  } while(0)
#define PRINTIEEESADENTRY(entry) \
  do { \
    SAD_PRINTIEEEADDRSET(&(entry)->traffic_desc); \
    SAD_PRINTF("\nCounter: %u\n", (entry)->counter); \
    SAD_PRINTF("KIM: %u, LVL: %u\n", (entry)->KIM, (entry)->LVL); \
    SAD_PRINTF("Time of creation: %u\n", (entry)->time_of_creation); \
    SAD_PRINTF("SA proto: %u\n", (entry)->sa.proto); \
    SAD_PRINTF("Encr type: %u\n", (entry)->sa.encr); \
    SAD_PRINTF("Encr type: %u, length %u : ", (entry)->sa.encr, get_encr_ieee_keymat_len((entry)->sa.encr)); \
    SAD_HEXDUMP((entry)->sa.sk_e, get_encr_ieee_keymat_len((entry)->sa.encr)); \
    SAD_PRINTF("Integ type: %u, length %u : ", (entry)->sa.integ, get_encr_ieee_keymat_len((entry)->sa.integ)); \
    SAD_HEXDUMP((entry)->sa.sk_a, get_integ_ieee_keymat_len((entry)->sa.encr)); \
  } while(0);
#else
#define SAD_PRINTF(...)
#define SAD_HEXDUMP(...)
#define SAD_PRINT6ADDR(...)
#define SAD_PRINTIEEEADDRSET(addr_set)
#define PRINTIEEESADENTRY(entry)
#endif

/**
 * Make a SAD entry ready for use by resetting counters etc
 */
#define IEEE_SAD_RESET_ENTRY(entry, seconds) \
  entry->counter = 0; \
  entry->time_of_creation = seconds; \
  entry->LVL = 0; \
  entry->KIM = 0;

/**
 * Implementation of the SAD.
 *
 * This implementation also serves as the SPD-S cache.
 *
 * Standard violations:
 *   * Sequence number can only be 32 bits, never 64 (extended sequence numbers).
 *   * No sequence counter overflow flag. Rollover occurs everytime.
 *      (FIX: Confliciting in implementation)
 *   * No anti-replay window
 *   * Nothing related to tunneling: Mode not supported
 *   * No fragment flag: Only required for tunnel mode (which we don't support)
 *   * No bypass DF flag: As only IPv6 is supported, this override for a
 *      IPv4-flag is not implemented
 *   * No DSCP fields: Differentiated services are not supported
 *   * No path MTU: This needs to be reviewed...
 *   * The system can not handle multiple SAs using the same selector
 *      (traffic_desc). RFC 4301, p. 13: "IPsec implementation MUST permit
 *      establishment and maintenance of multiple SAs between a given sender
 *      and receiver"
        However, I cannot se any problems with this as Contiki doesn't
 *      implement DSCP.
 *
 * INVARIANT: None of the address spaces expressed by the traffic_desc field overlaps that of another.
 * INVARIANT: The field spi is unique for all entries.
 *
 */
typedef struct x4 {
  struct y *next;

  /**
   * Traffic descriptor for the SA entry.
   *
   * This field is used to associate \b outgoing traffic with certain SAs.
   * For example; a packet whose traffic selector is destined for the PROTECT
   * policy in the SPD might be associated with an SA in the SAD.
   * Remember that for every SPD entry there might be several SAs in the SAD
   * due to the PFP mechanism. \c traffic_desc allows us to discriminate what
   * SA to apply to an outgoing packet on the basis of source port, destination
   * port and destination address. This makes this table a SPD-S cache
   * implementation as well.
   *
   *
   * Please note that although the \c traffic_desc can express IPv6 address
   * ranges only one address is used on for each end in sad_entry_t.
   * This is because this implementation only supports transport mode
   * (see section 1.1.2 RFC 5996) unicast.
   *
   */
  ieee_addr_set_t traffic_desc;

  /* Source and destination used to identify SA */
  uip_lladdr_t peer; /* Remote peer. To be used by traffic_desc */

  /* Key and transform used(algorithm) */
  sa_child_t sa;

  /* Number of secure IEEE 802.15.4 Frames sent */

  uint32_t counter;

  uint8_t LVL;
  uint8_t KIM;

  /**
   * Timestamp indicating the time of creation of the SA. It also serves the
   * purpose of distinguishing between manual SAs (created by an administrator)
   * and automatic ones (created by IKE).
   * The former has a value of zero, while the value of the latter is the time
   * of its creation (and thus non-zero).
   *
   * Manual SAs does not enjoy anti-replay protection as it's too much to ask
   * from an administrator to keep the sequence numbers synchronized between
   * the hosts across reboots etc.
   * This is not a problem in the automatic case though as the SAs are
   * synchronized upon creation and discarded at reboot.
   */
  uint32_t time_of_creation;
} ieee_sad_entry_t;

/**
 * IP header to SPDS Key
 */
void ieee_sad_init(void);

/**
 * SAD lookup by destination and source for IEEE 802.15.4 traffic.
 * @param outgoing_pkt
 * @return A pointer to the SAD entry whose \c traffic_desc address set
 * includes the address of \c addr. NULL is returned if there's no such match.
 */
ieee_sad_entry_t *ieee_sad_get_outgoing_entry(uip_lladdr_t *peer);

/**
 * SAD lookup by SPI number for incoming traffic.
 * @param spi The SPI number of the sought entry (in network byte order)
 * @return A pointer to the SAD entry whose SPI match that of \c spi.
 * NULL is returned if there's no such match.
 */
ieee_sad_entry_t *ieee_sad_get_incoming_entry(uip_lladdr_t *peer);

/**
 * Create a new SAD entry for incoming traffic, insert it into the incoming
 * SAD and allocate a new SPI
 * @param time_of_creation Time of creation. A value of zero signifies that
 * this is a manual SA.
 * @return A pointer to the created SAD entry
 */
ieee_sad_entry_t *ieee_sad_create_incoming_entry(uint32_t time_of_creation);

/**
 *
 *
 * \param time_of_creation
 */
/**
 * Inserts an entry into the SAD for outgoing traffic.
 * @param time_of_creation Time of creation. A value of zero signifies that this is a manual SA.
 * @return a pointer to the created SAD entry.
 */
ieee_sad_entry_t *ieee_sad_create_outgoing_entry(uint32_t time_of_creation);

/**
 * Remove outgoing SAD entry (i.e. kill SA)
 */
void ieee_sad_remove_outgoing_entry(ieee_sad_entry_t *ieee_sad_entry);

/**
 * Remove incoming SAD entry (i.e. kill SA)
 */
void ieee_sad_remove_incoming_entry(ieee_sad_entry_t *ieee_sad_entry);

#endif /* IEEE_SAD_H */

