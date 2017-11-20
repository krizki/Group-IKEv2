/**
 * \addtogroup ipsec
 * @{
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
 * \file
 *    Main IKEv2 functions
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se>
 *    Argyro Lamproudi
 *
 */

#include "machine.h"
#include "ike.h"
#include "common-ipsec.h"
#include "common-ike.h"
#include "spd.h"
#include "clock.h"

#if WITH_COMPOWER
#include "powertrace.h"
#endif

#if IPSEC_TIME_STATS
#include <clock.h>
#endif

#if defined(HW_SHA) || defined(HW_CCM) || defined(HW_AES)
#include "cpu/cc2538/dev/crypto.h"
#endif
/*
 * Addition for GroupIKEv2
 */
#include "g-ike-conf.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

ipsec_addr_t ike_arg_packet_tag; //from uip6.c
process_event_t ike_negotiate_event;
process_event_t rekey_event;
static struct etimer rekey_timer;
clock_time_t negotiation_time;
clock_time_t total_group_download_time;
clock_time_t current_total_time;
uint8_t numOfmembers_reqDownload;
uint16_t i;
//static int count1;
//static int count2;
static int rekey_counter = 0;

/**
 * Functions for (roughly) finding the stack's maximum extent.
 *
 * cover()              covers STACK_MAX_MEM B of stack memory with the character 'h'
 * get_cover_consumed()   counts the number of bytes from the current stack
 *												offset to the beginning of the area covered by 'h'
 */
#if IPSEC_MEM_STATS

#define STACK_MAX_MEM 2000

void
dummy(uint8_t *ptr)
{
}
uint8_t *
cover(void)
{

  volatile uint8_t buff[STACK_MAX_MEM];
  uint16_t i;
  for(i = 0; i < STACK_MAX_MEM; ++i) {
    buff[i] = 'h';
  }
  return (uint8_t *)buff;
}
uint16_t
get_cover_consumed(uint8_t *buff)
{
  uint16_t i;
  for(i = STACK_MAX_MEM - 5; i > 4 && strncmp((const char *)(buff + i), "hhhhh", 5); --i) {
  }
  return i;
}
#endif

void
ike_init()
{
#if defined(HW_SHA) || defined(HW_CCM) || defined(HW_AES)
  IPSEC_PRINTF("Initializing cryptoprocesor\n");
  crypto_init();
#endif
  i = 0;
  new_ecc_init();
  ike_negotiate_event = process_alloc_event();
  rekey_event = process_alloc_event();

  process_start(&ike2_service, NULL);
}
static void
ike_negotiate_sa(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry)
{
  /**
   * We're here because the outgoing packet associated with trigger_pkt_addr didn't find any SAD entry
   * with matching traffic selectors. The expected result of a call to this function is that the Child SA
   * is negotiated with the other peer and inserted into the SAD. Until that happens, traffic of this type
   * is simply dropped.
   *
   * Search the session table for an IKE session where the remote peer's IP matches that of the triggering
   * packet's. If such is found, start at state
   * ike_statem_state_common_createchildsa(session, addr_t triggering_pkt, spd_entry_t commanding_entry)
   * if busy, discard pkt
   *
   */
  ike_statem_session_t *session;

  /*
   * We have to differentiate when to invoke IKEv2 or GroupIKEv2.
   *
   */
  	  	  if(!uip_is_addr_mcast(&triggering_pkt_addr->peer_addr)){

			   printf("Invoke IKEv2. \n");
			   session = ike_statem_get_session_by_addr(&triggering_pkt_addr->peer_addr);

			   if(session == NULL) {
				 #if WITH_COMPOWER
					 powertrace_print("#P IKE start");
				 #endif
					 negotiation_time = clock_time();

					 ike_statem_setup_initiator_session(triggering_pkt_addr, commanding_entry);
				 #if WITH_COMPOWER
					 powertrace_print("#P IKE start");
				 #endif
				   } else {
					 IPSEC_PRINTF("Session already started not sending IKE_SA_INIT\n");
				 }

		   }else{
				   uip_ip6addr_t server_ipaddr;
				   uiplib_ipaddrconv(GCKS_HARDCODED_ADDRESS, &server_ipaddr);

				   printf("Invoke Group-IKEv2\n");
				   session = ike_statem_get_session_by_addr(&server_ipaddr);//get session with respect to server's IP address.


		   	   	 if(session == NULL) {
				 #if WITH_COMPOWER
					 powertrace_print("#P Group-IKE start <.");
				 #endif
					 negotiation_time = clock_time();
					 total_group_download_time = clock_time();
					 gike_statem_setup_member_session(triggering_pkt_addr, commanding_entry, server_ipaddr);
				 #if WITH_COMPOWER
					 powertrace_print("#P Group-IKE start >");
				 #endif
				   } else {
					 IPSEC_PRINTF("Session already started not sending IKE_SA_INIT\n");
				   }
		   	   }

}

/**
 * IKEv2 protothread. Handles the events by which the service is controlled.
 *
   EVENTS

    TYPE: ike_negotiate_event
    DESCRIPTION: Initiates an IKEv2 negotiation with the destination host. Data points to SPD entry that required the
                packet to be protected. The address of the triggering packet must be stored in ike_arg_packet_tag

    TYPE: tcpip_event
    DESCRIPTION: Dispatched by the uIP stack upon reception of new data. Data is undefined.

    (More to come? SAD operations likely)
 *
 */
PROCESS(ike2_service, "IKEv2 Service");
PROCESS_THREAD(ike2_service, ev, data)
{
  PROCESS_BEGIN();

  ike_statem_init();

  while(1) {
    PROCESS_WAIT_EVENT();

   static unsigned long tx_start_time = 0;
   static unsigned long tx_new_time = 0;
#if IPSEC_MEM_STATS
#ifdef CC2538_CHECK_STACK_USAGE
    cover();
#else
    uint8_t *stackbuff = cover();
#endif
#endif
    if(ev == ike_negotiate_event) {
      IPSEC_PRINTF(IPSEC_IKE "Negotiating child SAs in response to SPD entry %p for triggering packet\n", data);

      ike_negotiate_sa(&ike_arg_packet_tag, (spd_entry_t *)data);
    } else if(ev == tcpip_event) {
      //IPSEC_PRINTF(IPSEC_IKE "TCPIP event %u\n", uip_datalen());
      printf("TCPIP event %u\n", uip_datalen());
#if WITH_COMPOWER
      powertrace_print("#P IKE <");
#endif
      if(negotiation_time == 0) {
        /* For responder*/
        i = i + 1;
        numOfmembers_reqDownload =  numOfmembers_reqDownload + 1;
        negotiation_time = clock_time();
      }
      if(total_group_download_time==0){
    	  total_group_download_time = clock_time();

      }

      ike_statem_incoming_data_handler();
#if WITH_COMPOWER
      powertrace_print("#P IKE >");
#endif
    } else if(ev == ike_negotiate_done) {
      printf("IKE Negotiation done event IKE service \n");
      negotiation_time = clock_time() - negotiation_time;
      printf("Negotiation, (%u), %lu ticks, (%u ticks/sec) \n", i, (uint32_t)(negotiation_time), CLOCK_SECOND);
      negotiation_time = 0;
      current_total_time = clock_time() - total_group_download_time;
      printf("Total Group Download time for %u requesting members, %lu ticks, (%u ticks/sec) \n", numOfmembers_reqDownload, (uint32_t)(current_total_time),CLOCK_SECOND);
    } else if(ev == rekey_event){
    	printf("====== Rekey Event ====== \n");
	rekey_counter++;

#if 1	//leave test
	gsak_entry_t *temp = (gsak_entry_t *)data;
	gike_rekeying_msg_leave(temp);
#else
    	gike_rekeying_msg_init((gsak_entry_t *)data);
#endif

    } else{
      IPSEC_PRINTF(IPSEC_IKE "IKEv2 Service: Unknown event\n");
    }
#if IPSEC_MEM_STATS
#ifdef CC2538_CHECK_STACK_USAGE
    IPSEC_PRINTF(IPSEC_IKE "Stack extended, at most, by 0x%x\n \n", get_cover_consumed());
#else
    IPSEC_PRINTF(IPSEC_IKE "Stack extended, at most, by %u B \n", get_cover_consumed(stackbuff));
#endif
#endif
  }

  PROCESS_END();
}

/** @} */
