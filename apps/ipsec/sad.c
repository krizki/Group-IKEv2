/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    The SAD and its interface
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se>
 *    Argyro Lamproudi
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

/**
 * Implementation of the SAD (and the SPD-S cache) as described in RFC 4301.
 *
 */
#include <lib/list.h>
#include <net/ip/uip.h>
#include "sad.h"
#include "spd.h"
#include "memb.h"
#include "common-ipsec.h"

/* Security Association Database */
LIST(sad_incoming); /* Invariant: The struct member spi is the primary key */
LIST(sad_outgoing);
MEMB(sad_incoming_memb, sad_entry_t, IKE_SAD_ENTRIES);
MEMB(sad_outgoing_memb, sad_entry_t, NUM_OF_GROUPS);

/**
 * Allocating SPI values for incoming traffic.
 *
 * We can match an incoming packet to the IPSec stack by using its SPI
 * (given that we don't support NAT nor multicast, which we don't).
 * This is possible since we're the one assigning this value in the SAi2
 * payload of the IKE exchange. next_sad_initiator_spi keeps track of the
 * highest value we've assigned so far.
 */
uint32_t next_sad_local_spi;

/*---------------------------------------------------------------------------*/
void
sad_init()
{
  /* Initialize the linked list */
  list_init(sad_incoming);
  list_init(sad_outgoing);
  memb_init(&sad_incoming_memb);
  memb_init(&sad_outgoing_memb);

  next_sad_local_spi = SAD_DYNAMIC_SPI_START;

  /* I expect the compiler to inline this function as this is the */
  /* only point where it's called. */
#if WITH_CONF_MANUAL_SA
  sad_conf();
#endif

#if WITH_CONF_MANUAL_GSA
  gsad_conf();
#endif
}
/*---------------------------------------------------------------------------*/
uint8_t
sad_incoming_replay(sad_entry_t *entry, uint32_t seqno)
{
  /* Get offset to the highest registered sequence number */
  SAD_PRINTF("Incoming SA replay protection: seqno %u spi %x\n", entry->seqno, uip_ntohl(entry->spi));

  if(seqno > entry->seqno) {
    /* Highest sequence number observed. Window shifts to the right. */
    entry->win = entry->win << (seqno - entry->seqno);
    entry->win = entry->win | 1U;
    entry->seqno = seqno;
  } else {
    /* Sequence number is below the high end of the window */
    uint32_t offset = entry->seqno - seqno;
    uint32_t mask = 1U << offset;
    if(offset > 31 || entry->win & mask) {
      SAD_PRINTF(IPSEC "Error: Dropping packet because its sequence number is outside the reception window or it has been seen before (replay)\n");
      return 1; /* The sequence number is outside the window or the window position is occupied */
    }

    entry->win |= mask;
  }

  return 0;
}
/*---------------------------------------------------------------------------*/
sad_entry_t *
sad_create_outgoing_entry(uint32_t time_of_creation)
{
  SAD_PRINTF(IPSEC "Allocating memory for outgoing SA struct\n");
  sad_entry_t *newentry = NULL;
  newentry = memb_alloc(&sad_outgoing_memb);
  if(newentry == NULL) {
    SAD_PRINTF(IPSEC "SAD outgoing list full, removing oldest entry\n");
    sad_entry_t *delete;
    delete = list_chop(sad_outgoing);
    sad_remove_outgoing_entry(delete);
    newentry = memb_alloc(&sad_outgoing_memb);
  }

  /* Outgoing entry's SPI is usually decided by the other party */
  SAD_RESET_ENTRY(newentry, time_of_creation);
  list_push(sad_outgoing, newentry);
  return newentry;
}
/*---------------------------------------------------------------------------*/
sad_entry_t *
sad_create_incoming_entry(uint32_t time_of_creation)
{
  SAD_PRINTF(IPSEC "Allocating memory for incoming SA struct\n");
  sad_entry_t *newentry = NULL;
  newentry = memb_alloc(&sad_incoming_memb);

  if(newentry == NULL) {
    SAD_PRINTF(IPSEC "SAD incoming list full, removing oldest entry\n");
    sad_entry_t *delete;
    delete = list_chop(sad_incoming);
    sad_remove_incoming_entry(delete);
    newentry = memb_alloc(&sad_incoming_memb);
  }

  SAD_RESET_ENTRY(newentry, time_of_creation);
  newentry->spi = uip_htonl(next_sad_local_spi++);
  list_push(sad_incoming, newentry);

  return newentry;
}
/*---------------------------------------------------------------------------*/
sad_entry_t *
sad_get_outgoing_entry(ipsec_addr_t *addr)
{
  sad_entry_t *entry;

  /* FIX: The cross-check with the SPD is ugly. Move it to uip6.c or
   * stop creating SAs that overlap SPD entries of different actions */
  spd_entry_t *spd_entry = spd_get_entry_by_addr(addr, SA_PROTO_ESP);
 //printf("The spd_entry addr from is: "); PRINT6ADDR(spd_entry->selector.peer_addr_from); printf("\n");
 //printf("The spd_entry addr to is: "); PRINT6ADDR(spd_entry->selector.peer_addr_to); printf("\n");
  if(spd_entry->proc_action != SPD_ACTION_PROTECT) {
    return NULL;
  }
  for(entry = list_head(sad_outgoing); entry != NULL; entry = list_item_next(entry)) {
    SAD_PRINTF("==== OUTGOING SAD entry at %p ====\n  SPI no %x\n", entry, uip_ntohl(entry->spi));
    PRINTSADENTRY(entry);

    if(ipsec_a_is_member_of_b(addr, &entry->traffic_desc)) {
      SAD_PRINTF(IPSEC "sad_get_outgoing: found SAD entry with SPI %x\n", uip_ntohl(entry->spi));
      return entry;
    }
  }

  return NULL;
}

/*---------------------------------------------------------------------------*/
sad_entry_t *
find_sad_outgoing_entry(uip_ip6addr_t *group_ip){
	sad_entry_t *entry;
		for(entry = list_head(sad_outgoing); entry!=NULL; entry = list_item_next(entry)){
			if(memcmp((const void *)&entry->peer,(const void *)group_ip,sizeof(uip_ip6addr_t))==0){

				return entry;
			}else{
				return NULL;
				SAD_PRINTF("No OUTGOING SAD found.\n");
			}
		}
}
/*---------------------------------------------------------------------------*/
/*
 * This function takes as an argument the outgoing_sad entry and updates the entries of incoming_sad
 * in the GCKS, assuming that:
 * 1. The incoming and outgoing traffic has the same Group Security Associations
 * 2. The incoming and outgoing traffic has the same keys.
 */
void populate_incoming_sad_entries(sad_entry_t *outgoing_sad){
	sad_entry_t *entry;
	for(entry = list_head(sad_incoming); entry!=NULL; entry = list_item_next(entry)){
		if(outgoing_sad->spi == entry->spi){
		SAD_PRINTF("Updating INCOMING SAD ENTRIES for spi %u.\n", outgoing_sad->spi);
		entry->sa.proto = outgoing_sad->sa.proto;
		entry->sa.encr = outgoing_sad->sa.encr;
		entry->sa.encr_keylen = outgoing_sad->sa.encr_keylen;
		entry->sa.integ = outgoing_sad->sa.integ;
		uint8_t i;
			for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++){
			entry->sa.sk_e[i] = outgoing_sad->sa.sk_e[i];
			}
			for(i=0;i<KEY_LENGTH;i++){
			entry->sa.sk_a[i] = outgoing_sad->sa.sk_a[i];
			}
		}
		PRINTSADENTRY(entry);
	}
}
/*---------------------------------------------------------------------------*/
/*
 * This function returns only one entry, which is reasonable since in members only one incoming entry
 * exists with specific peer address and specific spi.
 */
sad_entry_t *
find_sad_incoming_entry(uip_ip6addr_t *peer, uint32_t spi){
	sad_entry_t *entry;
	for(entry = list_head(sad_incoming); entry != NULL; entry = list_item_next(entry)) {
		if((memcmp((const void *)&entry->peer,(const void *)peer,sizeof(uip_ip6addr_t))==0) && entry->spi == spi){
			return entry;
		}else{
			SAD_PRINTF("NO INCOMING SAD found .\n");
			return NULL;
		}
	}
}
/*---------------------------------------------------------------------------*/

sad_entry_t *
sad_get_incoming_entry(uint32_t spi, ipsec_addr_t *ipsec_addr){

  sad_entry_t *entry;
  if((ipsec_addr->peer_addr.u8[0]==0xfe)&&(ipsec_addr->peer_addr.u8[1]==0x80)){
          	ipsec_addr->peer_addr.u16[0] = 0xaaaa;
          }
  for(entry = list_head(sad_incoming); entry != NULL; entry = list_item_next(entry)) {



    if(entry->spi == spi){
    	if(ipsec_a_is_member_of_b(ipsec_addr, &entry->traffic_desc)){
    		SAD_PRINTF("==== INCOMING SAD entry at %p ====\n  SPI no %x\n", entry, uip_ntohl(spi));
    		    	PRINTSADENTRY(entry);

    		      return entry;
    }


    }
  }
  IPSEC_PRINTF("SAD: No entry found\n");
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
sad_remove_outgoing_entry(sad_entry_t *sad_entry)
{
  SAD_PRINTF("Removing outgoing SAD entry %p\n", sad_entry);
  memb_free(&sad_outgoing_memb, sad_entry);
  list_remove(sad_outgoing, sad_entry);
}
/*---------------------------------------------------------------------------*/
void
sad_remove_incoming_entry(sad_entry_t *sad_entry)
{
  SAD_PRINTF("Removing incoming SAD entry %p\n", sad_entry);
  memb_free(&sad_incoming_memb, sad_entry);
  list_remove(sad_incoming, sad_entry);
}
/*---------------------------------------------------------------------------*/
/** @} */
