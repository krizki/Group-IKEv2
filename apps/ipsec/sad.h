/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    The SAD and its interface
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
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

#ifndef __SAD_H__
#define __SAD_H__

#include "sa.h"
#include "ipsec.h"
#include "common-ipsec.h"

extern uint32_t next_sad_local_spi;

#ifndef IKE_SAD_ENTRIES

#define IKE_SAD_ENTRIES NUM_OF_MEMBERS

#endif

/**
 * Debug stuff
 */
/* Prints the SAD entry located at entry */
#ifndef IPSEC_SAD_DBG
#define IPSEC_SAD_DBG 0
#endif

#if IPSEC_SAD_DBG
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"
#define SAD_PRINTF(...) printf(__VA_ARGS__)
#define SAD_HEXDUMP(...) hexdump(__VA_ARGS__)
#define SAD_PRINTSADADDRSET(addr_set) \
  do { \
    SAD_PRINTF("Peer address from to: "); \
    PRINT6ADDR((addr_set)->peer_addr_from); \
    SAD_PRINTF(" - "); \
    PRINT6ADDR((addr_set)->peer_addr_to); \
    SAD_PRINTF("\nNextlayer proto: %u\n", (addr_set)->nextlayer_proto); \
    SAD_PRINTF("My ports: %u - %u\n", (addr_set)->my_port_from, (addr_set)->my_port_to); \
    SAD_PRINTF("Peer ports: %u - %u\n", (addr_set)->peer_port_from, (addr_set)->peer_port_to); \
  } while(0)
#else
#define SAD_PRINTF(...)
#define SAD_HEXDUMP(...)
#define SAD_PRINTSADADDRSET(addr_set)
#endif

#if IPSEC_SAD_DBG
#define PRINTSADENTRY(entry) \
  do { \
    SAD_PRINTSADADDRSET(&(entry)->traffic_desc); \
    SAD_PRINTF("Peer Address\n"); \
    PRINT6ADDR(&(entry)->peer); \
    SAD_PRINTF("SPI: %x\n", uip_ntohl((entry)->spi)); \
    SAD_PRINTF("Sequence number: %u\n", (entry)->seqno); \
    SAD_PRINTF("Window: 0x%x\n", (entry)->win); \
    SAD_PRINTF("Time of creation: %u\n", (entry)->time_of_creation); \
    SAD_PRINTF("Bytes transported: %u\n", (entry)->bytes_transported); \
    SAD_PRINTF("SA proto: %u\n", (entry)->sa.proto); \
    SAD_PRINTF("Encr type: %u, length %u\n", (entry)->sa.encr, SA_ENCR_KEYMATLEN_BY_SA((entry)->sa)); \
    SAD_HEXDUMP((entry)->sa.sk_e, SA_ENCR_KEYMATLEN_BY_SA((entry)->sa)); \
    SAD_PRINTF("Integ type: %u, length %u\n", (entry)->sa.integ, SA_INTEG_KEYMATLEN_BY_TYPE((entry)->sa.integ)); \
    SAD_HEXDUMP((entry)->sa.sk_a, SA_INTEG_KEYMATLEN_BY_TYPE((entry)->sa.integ)); \
  } while(0)
#else
#define PRINTSADENTRY(entry)
#endif

#define SAD_DYNAMIC_SPI_START 1000
#define SAD_ENTRY_IS_DYNAMIC(sad_entry) (uip_ntohl(sad_entry->spi) >= SAD_DYNAMIC_SPI_START)

#define SAD_REPLAY_ASSERT(sad_entry, new_seqno) \


/* For retrieving the next SPI for inbound traffic */
#define SAD_GET_NEXT_SAD_LOCAL_SPI uip_htonl(next_sad_local_spi++)

/* No SPI magic value, as implied by the RFC */
#define SAD_NO_SPI 0

/**
 * Make a SAD entry ready for use by resetting counters etc
 */
#define SAD_RESET_ENTRY(entry, seconds) \
  entry->seqno = 0; \
  entry->time_of_creation = seconds; \
  entry->bytes_transported = 0; \
  entry->win = 0

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
typedef struct x2 {
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
   * In the context of \b incoming traffic it's used to verify that an SA
   * referenced (via the SPI) by the packet has a traffic selector that
   * includes the incoming packet's source address.
   *
   * Please note that although the \c traffic_desc can express IPv6 address
   * ranges only one address is used on for each end in sad_entry_t.
   * This is because this implementation only supports transport mode
   * (see section 1.1.2 RFC 5996) unicast.
   *
   */
  ipsec_addr_set_t traffic_desc;

  uip_ip6addr_t peer; /* Remote peer. To be used by traffic_desc */

  /* The author can't see any reason as to why we should store the SPIs in
   * host byte order. */
  /* Therefore the SPI below is stored in network byte order.
   * This saves some memory by eliding the conversion. */
  uint32_t spi; /* Stored in network byte order. Suggestion for the future: 16 bits for incoming traffic, 32 bits for outgoing */

  /* Encryption */
  sa_child_t sa;

  /* Sequence number overflow is always permitted for static
   * (FIX: Different policies for overflow in different parts of the code) */
  /**
   * Replay protection
   *
   * Replay protection is described in the RFC 4301 (IPsec), 4303 (ESP) and 4302 (AH).
   * This implementation offers a 32 packet wide sliding window for all dynamic SAs.
   */
  /* Incoming traffic: Highest verified sequence number of this SA. The right edge of the window. */
  /* Outgoing traffic: Sequence number of the last transmitted packet */
  uint32_t seqno;

  /* Incoming traffic: 32 positions long window mask */
  /* Outgoing traffic: Unused */
  uint32_t win;

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

  /* The number of bytes transported over the SA */
  uint32_t bytes_transported;
} sad_entry_t;

/**
 * IP header to SPDS Key
 */
void sad_init(void);

/**
 * Anti-replay: Assert that the sequence number fits in the window of this SA
 * and update it.
 */
uint8_t sad_incoming_replay(sad_entry_t *entry, uint32_t seqno);

/**
 * SAD lookup by address for outgoing traffic.
 * @param outgoing_pkt
 * @return A pointer to the SAD entry whose \c traffic_desc address set
 * includes the address of \c addr. NULL is returned if there's no such match.
 */
sad_entry_t *sad_get_outgoing_entry(ipsec_addr_t *outgoing_pkt);

/**
 * SAD lookup by SPI number for incoming traffic.
 * @param spi The SPI number of the sought entry (in network byte order)
 * @return A pointer to the SAD entry whose SPI match that of \c spi.
 * NULL is returned if there's no such match.
 */
sad_entry_t *sad_get_incoming_entry(uint32_t spi, ipsec_addr_t *ipsec_addr);
sad_entry_t * find_sad_outgoing_entry(uip_ip6addr_t *group_ip);
sad_entry_t * find_sad_incoming_entry(uip_ip6addr_t *peer, uint32_t spi);
void populate_incoming_sad_entries(sad_entry_t *outgoing_sad);
/**
 * Create a new SAD entry for incoming traffic, insert it into the incoming
 * SAD and allocate a new SPI
 * @param time_of_creation Time of creation. A value of zero signifies that
 * this is a manual SA.
 * @return A pointer to the created SAD entry
 */
sad_entry_t *sad_create_incoming_entry(uint32_t time_of_creation);

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
sad_entry_t *sad_create_outgoing_entry(uint32_t time_of_creation);

/**
 * Remove outgoing SAD entry (i.e. kill SA)
 */
void sad_remove_outgoing_entry(sad_entry_t *sad_entry);

/**
 * Remove incoming SAD entry (i.e. kill SA)
 */
void sad_remove_incoming_entry(sad_entry_t *sad_entry);
void gsad_conf();
void sad_conf();


#endif

/** @} */
