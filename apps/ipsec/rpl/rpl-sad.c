/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    The RPL SAD and its interface
 * \author
 *    Runar Mar Magnusson <rmma@kth.se>
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
#include "rpl-sad.h"
#include "spd.h"
#include "memb.h"
#include "rpl-sa.h"

/* Security Association Database */
LIST(rpl_sad_incoming); /* Invariant: The struct member spi is the primary key */
LIST(rpl_sad_outgoing);
MEMB(rpl_sad_incoming_memb, rpl_sad_entry_t, IKE_RPL_SAD_ENTRIES);
MEMB(rpl_sad_outgoing_memb, rpl_sad_entry_t, IKE_RPL_SAD_ENTRIES);

/*---------------------------------------------------------------------------*/
void
rpl_sad_init()
{
  /* Initialize the linked list */
  list_init(rpl_sad_incoming);
  list_init(rpl_sad_outgoing);
  memb_init(&rpl_sad_incoming_memb);
  memb_init(&rpl_sad_outgoing_memb);
}
/*---------------------------------------------------------------------------*/
rpl_sad_entry_t *
rpl_sad_create_outgoing_entry(uint32_t time_of_creation)
{
  SAD_PRINTF("Allocating memory for outgoing RPL SA struct\n");
  rpl_sad_entry_t *newentry = NULL;
  newentry = memb_alloc(&rpl_sad_outgoing_memb);
  if(newentry == NULL) {
    SAD_PRINTF("RPL SAD outgoing list full, removing oldest entry\n");
    rpl_sad_entry_t *delete;
    delete = list_chop(rpl_sad_outgoing);
    rpl_sad_remove_outgoing_entry(delete);
    newentry = memb_alloc(&rpl_sad_outgoing_memb);
  }

  /* Initialize the entry and put it into */
  RPL_SAD_RESET_ENTRY(newentry, time_of_creation);
  list_push(rpl_sad_outgoing, newentry);
  return newentry;
}
/*---------------------------------------------------------------------------*/
rpl_sad_entry_t *
rpl_sad_create_incoming_entry(uint32_t time_of_creation)
{
  SAD_PRINTF("Allocating memory for incoming SA struct\n");
  rpl_sad_entry_t *newentry = NULL;
  newentry = memb_alloc(&rpl_sad_incoming_memb);

  if(newentry == NULL) {
    SAD_PRINTF("SAD incoming list full, removing oldest entry\n");
    rpl_sad_entry_t *delete;
    delete = list_chop(rpl_sad_incoming);
    rpl_sad_remove_incoming_entry(delete);
    newentry = memb_alloc(&rpl_sad_incoming_memb);
  }

  RPL_SAD_RESET_ENTRY(newentry, time_of_creation);
  list_push(rpl_sad_incoming, newentry);

  return newentry;
}
/*---------------------------------------------------------------------------*/
rpl_sad_entry_t *
rpl_sad_get_outgoing_entry(uip_ip6addr_t *peer)
{
  rpl_sad_entry_t *entry;

  for(entry = list_head(rpl_sad_outgoing); entry != NULL; entry = list_item_next(entry)) {
    SAD_PRINTF("==== OUTGOING SAD entry at %p ====\n", entry);
    PRINTRPLSADENTRY(entry);
    if(uip_ip6addr_cmp(peer, &entry->peer)) {
      SAD_PRINTF("sad_get_outgoing: found SAD entry\n");
      return entry;
    }
  }
  SAD_PRINTF("SAD: No entry found\n");
  return NULL;
}
/*---------------------------------------------------------------------------*/
rpl_sad_entry_t *
rpl_sad_get_incoming_entry(uip_ip6addr_t *peer)
{
  rpl_sad_entry_t *entry;
  for(entry = list_head(rpl_sad_incoming); entry != NULL; entry = list_item_next(entry)) {
    SAD_PRINTF("==== INCOMING SAD entry at %p ====\n", entry);
    PRINTRPLSADENTRY(entry);
    if(uip_ip6addr_cmp(peer, &entry->peer)) {
      return entry;
    }
  }
  SAD_PRINTF("SAD: No entry found\n");
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
rpl_sad_remove_outgoing_entry(rpl_sad_entry_t *rpl_sad_entry)
{
  SAD_PRINTF("Removing outgoing RPL SAD entry %p\n", rpl_sad_entry);
  memb_free(&rpl_sad_outgoing_memb, rpl_sad_entry);
  list_remove(rpl_sad_outgoing, rpl_sad_entry);
}
/*---------------------------------------------------------------------------*/
void
rpl_sad_remove_incoming_entry(rpl_sad_entry_t *rpl_sad_entry)
{
  SAD_PRINTF("Removing incoming RPL SAD entry %p\n", rpl_sad_entry);
  memb_free(&rpl_sad_incoming_memb, rpl_sad_entry);
  list_remove(rpl_sad_incoming, rpl_sad_entry);
}
/*---------------------------------------------------------------------------*/
/** @} */
