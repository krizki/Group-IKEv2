/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    The IEEE 802.15.4  and its interface
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
#include "ieee-802-15-4-sad.h"
#include "spd.h"
#include "memb.h"
#include "ieee-802-15-4-sa.h"

/* Security Association Database */
LIST(ieee_sad_incoming);
LIST(ieee_sad_outgoing);
MEMB(ieee_sad_incoming_memb, ieee_sad_entry_t, IKE_IEEE_SAD_ENTRIES);
MEMB(ieee_sad_outgoing_memb, ieee_sad_entry_t, IKE_IEEE_SAD_ENTRIES);

/*---------------------------------------------------------------------------*/
void
ieee_sad_init()
{
  /* Initialize the linked list */
  list_init(ieee_sad_incoming);
  list_init(ieee_sad_outgoing);
  memb_init(&ieee_sad_incoming_memb);
  memb_init(&ieee_sad_outgoing_memb);
}
/*---------------------------------------------------------------------------*/
ieee_sad_entry_t *
ieee_sad_create_outgoing_entry(uint32_t time_of_creation)
{
  SAD_PRINTF("Allocating memory for outgoing IEEE SA struct\n");
  ieee_sad_entry_t *newentry = NULL;
  newentry = memb_alloc(&ieee_sad_outgoing_memb);
  if(newentry == NULL) {
    SAD_PRINTF("IEEE SAD outgoing list full, removing oldest entry\n");
    ieee_sad_entry_t *delete;
    delete = list_chop(ieee_sad_outgoing);
    ieee_sad_remove_outgoing_entry(delete);
    newentry = memb_alloc(&ieee_sad_outgoing_memb);
  }

  /* Initialize the entry and put it into */
  IEEE_SAD_RESET_ENTRY(newentry, time_of_creation);
  list_push(ieee_sad_outgoing, newentry);
  return newentry;
}
/*---------------------------------------------------------------------------*/
ieee_sad_entry_t *
ieee_sad_create_incoming_entry(uint32_t time_of_creation)
{
  SAD_PRINTF("Allocating memory for incoming SA struct\n");
  ieee_sad_entry_t *newentry = NULL;
  newentry = memb_alloc(&ieee_sad_incoming_memb);

  if(newentry == NULL) {
    SAD_PRINTF("SAD incoming list full, removing oldest entry\n");
    ieee_sad_entry_t *delete;
    delete = list_chop(ieee_sad_incoming);
    ieee_sad_remove_incoming_entry(delete);
    newentry = memb_alloc(&ieee_sad_incoming_memb);
  }

  IEEE_SAD_RESET_ENTRY(newentry, time_of_creation);
  list_push(ieee_sad_incoming, newentry);

  return newentry;
}
/*---------------------------------------------------------------------------*/
ieee_sad_entry_t *
ieee_sad_get_outgoing_entry(uip_lladdr_t *peer)
{
  ieee_sad_entry_t *entry;

  for(entry = list_head(ieee_sad_outgoing); entry != NULL; entry = list_item_next(entry)) {
    SAD_PRINTF("==== OUTGOING SAD entry at %p ====\n", entry);
    PRINTIEEESADENTRY(entry);

    if(memcmp(peer, &entry->peer, sizeof(uip_lladdr_t)) == 0) {
      SAD_PRINTF("sad_get_outgoing: found SAD entry\n");
      return entry;
    }
  }
  SAD_PRINTF("SAD: No entry found\n");
  return NULL;
}
/*---------------------------------------------------------------------------*/
ieee_sad_entry_t *
ieee_sad_get_incoming_entry(uip_lladdr_t *peer)
{
  ieee_sad_entry_t *entry;

  for(entry = list_head(ieee_sad_incoming); entry != NULL; entry = list_item_next(entry)) {
    SAD_PRINTF("==== INCOMING SAD entry at %p ====\n", entry);
    PRINTIEEESADENTRY(entry);

    if(memcmp(peer, &entry->peer, sizeof(uip_lladdr_t)) == 0) {
      SAD_PRINTF("sad_get_outgoing: found SAD entry\n");
      return entry;
    }
  }
  SAD_PRINTF("SAD: No entry found\n");
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
ieee_sad_remove_outgoing_entry(ieee_sad_entry_t *ieee_sad_entry)
{
  SAD_PRINTF("Removing outgoing IEEE 802.15.4 SAD entry %p\n", ieee_sad_entry);
  memb_free(&ieee_sad_outgoing_memb, ieee_sad_entry);
  list_remove(ieee_sad_outgoing, ieee_sad_entry);
}
/*---------------------------------------------------------------------------*/
void
ieee_sad_remove_incoming_entry(ieee_sad_entry_t *ieee_sad_entry)
{
  SAD_PRINTF("Removing incoming IEEE 802.15.4 SAD entry %p\n", ieee_sad_entry);
  memb_free(&ieee_sad_incoming_memb, ieee_sad_entry);
  list_remove(ieee_sad_incoming, ieee_sad_entry);
}
/*---------------------------------------------------------------------------*/
/** @} */
