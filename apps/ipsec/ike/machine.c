/**
 * \addtogroup ipsec
 * @{
 */
/*
 * Copyright (c) 2012, Vilhelm Jutvik.
 * 				2016, Argyro Lamproudi
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
 *    Helper functions for the state machines
 * \details
 *    Definitions for the Mealy State Machine implementing the behavior of IKEv2.
 *    Everything in this file pertains to RFC 5996 (hereafter referred to as "the RFC").
 *
 *    The machine is designed for memory efficiency, translating into an emphasis of code
 *    reuse and small memory buffers.
 *
 *    Code reuse is improved by only placing state transition code into the states. Transition-specific
 *    code with side effects and message generation are placed in the edges' functions
 *    (which can be reused over multiple different transitions).
 *
 *    As for the latter, instead of storing a copy (approx. 100 B - 1 kB) of the last transmitted message, should a retransmission
 *    be warranted the last transition is simply undone and then redone. This is accomplished by using the
 *    associated functions do_ and undo, respectively.
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se> - fixed retransmission timers
 *
 */

#include <string.h>
#include <stdlib.h>
#include "ipsec-malloc.h"
#include "common-ike.h"
#include "machine.h"

#include "gike-functions.h"
#include "payload.h"
#include "ike.h"
#include "list.h"
#include "sys/ctimer.h"
#include "uip.h"
#include "string.h"
#include "memb.h"
#include "g-ike-conf.h"


#if WITH_IPSEC
#include "sad.h"
#endif

#if IKE_WITH_RPL
#include "rpl/rpl-sad.h"
#endif

#if IKE_IPSEC_INFO
#include <stdio.h>
#if IPSEC_TIME_STATS
#include "sys/rtimer.h"
rtimer_clock_t exec_time = 0;
rtimer_clock_t total_time = 0;
#endif
#endif

process_event_t ike_negotiate_done1;

#if WITH_COMPOWER
#include "powertrace.h"
#endif

/**
 * IKEv2's behaviour is implemented as a mealy machine. These are its states:
 *
 *
 * Cost of using memory pointers (16 bit pointers):
 *   4 B * session_count   # References for current and past state (RAM)
 *   4 B * state_count     # With the assumption that each state references two other states, on average (ROM)
 *
 * Cost of using enums (8 bit enums, 16 bit pointers):
 *   4 B * session_count   # State id and state
 *   2 B * state_count     # With the assumption that each state references two other states, on average
 */
//process_event_t rekey_event;
#define SET_RETRANSTIMER(session) \
  IPSEC_PRINTF("STARTING retransmission timer for session %p\n", session); \
  ctimer_set(&session->retrans_timer, IKE_STATEM_TIMEOUT, &ike_statem_timeout_handler, (void *)session); \
  session->num_retransmit++;

/* Used by the responder to delete session information for half-open sessions */
#define SET_SESSION_FAILURE_TIMER(session) \
  ctimer_set(&session->retrans_timer, 5 * IKE_RETRANSMIT_MAX * IKE_STATEM_TIMEOUT, &ike_statem_timeout_handler, (void *)session); \

#define STOP_TIMER(session) \
  IPSEC_PRINTF("STOPPING retransmission timer and reseting retransmission counter for session %p\n", session); \
  ctimer_stop(&(session)->retrans_timer); \
  session->num_retransmit = 0;

#define SA_INDEX(arg) arg - 1


/* Initialize the session table */
LIST(sessions);
MEMB(sessions_memb, ike_statem_session_t, IKE_SESSION_NUM);

/*Allocate a memory block for gsa entry*/
LIST(gsak_entries);
MEMB(gsak_memb, gsak_entry_t, NUM_OF_GROUPS);


#ifndef USE_HEAP
MEMB(ephemeral_data_memb, ike_statem_ephemeral_info_t, IKE_HALF_OPEN_NUM);
#endif

/* Network stuff */
static const uint8_t *udp_buf = &uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
uint8_t *msg_buf;
static struct uip_udp_conn *my_conn;
const uip_ip6addr_t *my_ip_addr = &((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])->destipaddr;
const uip_ip6addr_t *peer_ip_addr = &((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])->srcipaddr;
static struct ctimer rekey_leave_timer;

extern uint16_t uip_slen;

/* State machine declaration */
/* IKE_STATEM_DECLARE_STATEFN(name, type) */
/* ike_statem_statefn_ret_t ike_statem_##name##_##type##(ike_statem_session_t *session) */

/* Function declarations for providing hints to code in the upper parts of this file */
void ike_statem_send(ike_statem_session_t *session, uint16_t len);
void ike_statem_timeout_handler(void *session);


/*---------------------------------------------------------------------------*/
/**
 * To be called in order to enter a _state_ (not execute a transition!)
 */
void
ike_statem_enterstate(ike_statem_session_t *session)
{
  /* Stop retransmission timer (if any has been set) for the initiator*/
  IPSEC_PRINTF(IPSEC_IKE "Session %p is entering state %p\n", (session), (session)->next_state_fn);
  if(IKE_STATEM_IS_INITIATOR(session)) {
    STOP_TIMER((session));
    /* Were we waiting for a reply? If so, then our last message must have gone through. Increase our message ID. */
  }
  if(session->transition_fn != NULL) {
    IKE_STATEM_INCRMYMSGID(session);
    session->transition_fn = NULL;
  }
printf("test\n");
  state_return_t rtvl = (*(session)->next_state_fn)(session);
  if(rtvl != STATE_SUCCESS) {

    IPSEC_PRINTF(IPSEC_IKE "Removing IKE session %p due to termination in state %p\n", session, (session)->next_state_fn);
    ike_statem_remove_session(session);
  } else {
    IKE_STATEM_INCRPEERMSGID(session);
  } return;
}
/**
 * Executes a state transition, moving from one state to another and sends a
 * an IKE message in the process. The session as referred to by the variable session is removed (and therefore deallocated)
 * upon transition failure.
 *
 * \param session The session concerned
 * \param retransmit If set to non-zero, the retransmission timer for the transition will be activated. 0 otherwise.
 *
 * \return the value returned by the transition
 */
transition_return_t
ike_statem_run_transition(ike_statem_session_t *session, uint8_t retransmit)
{
  IPSEC_PRINTF(IPSEC_IKE "Entering transition fn %p of IKE session %p\n", session->transition_fn, session); \

  transition_return_t len = (*(session)->transition_fn)(session);

  if(len == TRANSITION_FAILURE) {
    IPSEC_PRINTF(IPSEC_IKE_ERROR "An error occurred while in transition\n");
    ike_statem_remove_session(session);
    return len;
  }

  /* send udp pkt here */
  IPSEC_PRINTF(IPSEC_IKE "Sending data of length %u\n", len);
  ike_statem_send(session, len);
  if(retransmit) {
    SET_RETRANSTIMER(session);
  }
  return len;
}
/*---------------------------------------------------------------------------*/
void
ike_statem_init()
{
  list_init(sessions);
  memb_init(&sessions_memb);
  /* srand(clock_time()); */


  /* Set up the UDP port for incoming traffic */
  my_conn = udp_new(NULL, UIP_HTONS(IKE_UDP_PORT), NULL);
  udp_bind(my_conn, UIP_HTONS(IKE_UDP_PORT)); /* This will set lport to IKE_UDP_PORT */

  my_conn->rport = 0;
  uip_create_unspecified(&my_conn->ripaddr);

  msg_buf = uip_udp_buffer_dataptr();

  IPSEC_PRINTF(IPSEC_IKE "State machine initialized. Listening on UDP port %d.\n", uip_ntohs(my_conn->lport));
}
/*---------------------------------------------------------------------------*/
ike_statem_session_t *
ike_statem_session_init()
{
#if IKE_IPSEC_INFO
  printf("Initializing and allocating memory for new IKE session\n");
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW();
  total_time = 0;
#endif
#endif
  IPSEC_PRINTF(IPSEC_IKE "Allocating memory for IKE session struct\n");
  ike_statem_session_t *session;
  session = memb_alloc(&sessions_memb);
  if(session == NULL) {
    IPSEC_PRINTF("Session list full removing oldest session\n");
    ike_statem_session_t *delete;
    delete = list_chop(sessions);
    ike_statem_remove_session(delete);
    session = memb_alloc(&sessions_memb);
  }
  session->transition_fn = NULL;
  session->next_state_fn = NULL;

  IPSEC_PRINTF(IPSEC_IKE "Initiating IKE session %p\n", session);
  list_push(sessions, session);

  /* Set the SPIs. */
  session->peer_spi_high = 0U;
  session->peer_spi_low = 0U;
  IKE_STATEM_MYSPI_SET_NEXT(session->initiator_and_my_spi);

  session->my_msg_id = 0;
  session->peer_msg_id = 0;

  IPSEC_PRINTF(IPSEC_IKE "Allocating memory for IKE session ephemeral info struct\n");
  /* malloc() will do as this memory will soon be freed and thus won't clog up the heap for long. */
  session->ephemeral_info = NULL;
#ifdef USE_HEAP
  session->ephemeral_info = ipsec_malloc(sizeof(ike_statem_ephemeral_info_t));
#else
  session->ephemeral_info = memb_alloc(&ephemeral_data_memb);
#endif

  if(session->ephemeral_info == NULL) {
    IPSEC_PRINTF(IPSEC_IKE_ERROR "Could not allocate memory for ephemeral data structures\n");
    return NULL;
  }

  /* This random seed will be used for generating our nonce */
  /* session->ephemeral_info->my_nonce_seed = 0; // rand16(); Set to 0 to get the same. */
  random_ike(session->ephemeral_info->my_nounce, IKE_PAYLOAD_MYNONCE_LEN);
  /**
   * Generate the private key
   *
   * We're not interested in reusing the DH exponentials across sessions ("2.12.  Reuse of Diffie-Hellman Exponentials")
   * as the author finds the cost of storing them in memory exceeding the cost of the computation.
   */
  IPSEC_PRINTF(IPSEC_IKE "Generating private ECC key\n");
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  exec_time = RTIMER_NOW();
#endif
  ecc_generate_private_key(session->ephemeral_info->my_prv_key);
#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  printf("ECC private key generation, %lu us\n", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
  printf("Session creation total time, %lu us\n", (uint32_t)((uint64_t)total_time * 1000000 / RTIMER_SECOND));
#endif
#endif

  return session;
}
/*---------------------------------------------------------------------------*/
/**
 * Sets up a new session to handle an incoming request
 */
void
ike_statem_setup_responder_session()
{
  ike_statem_session_t *session = NULL;
  session = ike_statem_session_init();

  if(session == NULL) {
    return;
    /* We're the responder */
  }
  IKE_STATEM_MYSPI_SET_R(session->initiator_and_my_spi);

  memcpy(&session->peer, peer_ip_addr, sizeof(uip_ip6addr_t));
 // printf("packet peer address:\n");
       	//	   PRINT6ADDR(&session->peer);

  /* Transition to state initrespwait */
  session->next_state_fn = &ike_statem_state_parse_initreq;
  session->my_msg_id = 0;
  session->peer_msg_id = 0;

  /* Used for RPL and IEEE 802.15.4 key management */
  session->recieved_rpl_supported = 0;
  session->recieved_ieee_supported = 0;
  session->received_gike_supported = 0;
  session->sender_enabled = 0;
  session->incoming_entry = NULL;
  session->outgoing_entry = NULL;

#if IKE_WITH_IEEE
  memset(&session->peer_lladdr, 0, sizeof(uip_lladdr_t));
#endif

  SET_SESSION_FAILURE_TIMER(session);

  ike_statem_enterstate(session);
}
/*---------------------------------------------------------------------------*/
void
ike_statem_setup_initiator_session(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry)
{
  ike_statem_session_t *session = NULL;
  session = ike_statem_session_init();

  if(session == NULL) {
    return;
    /* Populate the session entry */
  }

  memcpy(&session->peer, &triggering_pkt_addr->peer_addr, sizeof(uip_ip6addr_t));
  printf("Triggering packet peer address:\n");
     		  // PRINT6ADDR(&triggering_pkt_addr->peer_addr);

  /* We're the initiator */
  IKE_STATEM_MYSPI_SET_I(session->initiator_and_my_spi);

  /* Transition to state initrespwait */
  session->transition_fn = &ike_statem_trans_initreq;
  session->next_state_fn = &ike_statem_state_initrespwait;

  /* Populate the ephemeral information with connection setup information */
  memcpy(&session->peer, &triggering_pkt_addr->peer_addr, sizeof(uip_ip6addr_t));

  memcpy(&session->ephemeral_info->spd_entry, commanding_entry, sizeof(spd_entry_t));
  memcpy(&session->ephemeral_info->my_ts_offer_addr_set, &commanding_entry->selector, sizeof(ipsec_addr_set_t));

  /* So address isn't overwritten*/
  memcpy(&session->ephemeral_info->spd_entry.selector.peer_addr_from,
         &commanding_entry->selector.peer_addr_from, sizeof(uip_ip6addr_t));
  memcpy(&session->ephemeral_info->spd_entry.selector.peer_addr_to,
         &commanding_entry->selector.peer_addr_to, sizeof(uip_ip6addr_t));
  session->ephemeral_info->my_ts_offer_addr_set.peer_addr_from = &session->ephemeral_info->peer_addr_from;
  session->ephemeral_info->my_ts_offer_addr_set.peer_addr_to = &session->ephemeral_info->peer_addr_to;

  session->my_msg_id = 0;
  session->peer_msg_id = 0;

  /* Initialize the retransmission counter */
  session->num_retransmit = 0;

  /* Used for RPL and IEEE 802.15.4 key management */
  session->recieved_rpl_supported = 0;
  session->recieved_ieee_supported = 0;
  session->received_gike_supported = 0;
  session->incoming_entry = NULL;
  session->outgoing_entry = NULL;

#if IKE_WITH_IEEE
  memset(&session->peer_lladdr, 0, sizeof(uip_lladdr_t));
#endif

  IKE_STATEM_TRANSITION(session);
}
/*---------------------------------------------------------------------------*/
void
ike_statem_remove_session(ike_statem_session_t *session)
{
  IPSEC_PRINTF(IPSEC_IKE "Removing session %p\n", session);
  STOP_TIMER(session);   /* It might be active, producing accidential transmissions */
  if(session->incoming_entry != NULL) {
#if WITH_IPSEC
    sad_remove_incoming_entry(session->incoming_entry);
#endif
#if IKE_WITH_RPL
    rpl_sad_remove_incoming_entry(session->incoming_entry);
#endif
#if IKE_WITH_IEEE
    ieee_sad_remove_incoming_entry(session->incoming_entry);
#endif
  }
  if(session->outgoing_entry != NULL) {
#if WITH_IPSEC
    sad_remove_outgoing_entry(session->outgoing_entry);
#endif
#if IKE_WITH_RPL
    rpl_sad_remove_outgoing_entry(session->outgoing_entry);
#endif
#if IKE_WITH_IEEE
    ieee_sad_remove_outgoing_entry(session->outgoing_entry);
#endif
  }
  if(session->ephemeral_info != NULL) {
    ike_statem_clean_session(session);
  }
  memb_free(&sessions_memb, session);
  list_remove(sessions, session);
}
/*---------------------------------------------------------------------------*/
void
ike_statem_clean_session(ike_statem_session_t *session)
{
  IPSEC_PRINTF(IPSEC_IKE "Freeing IKE session's emphemeral information\n");
  /* STOP_RETRANSTIMER(session); */
#ifdef USE_HEAP
  ipsec_free(session->ephemeral_info);
#else
  memb_free(&ephemeral_data_memb, session->ephemeral_info);
#endif
}
/**
 * Timeout handler for state transitions (i.e. UDP messages that go unanswered)
 */
/*---------------------------------------------------------------------------*/
void
ike_statem_timeout_handler(void *session)       /* Void argument since we're called by ctimer */
{
  ike_statem_session_t *ike_session = (ike_statem_session_t *)session;
#if IKE_IPSEC_INFO
  printf("TIMEOUT for session or retransmission for session %p\n", ike_session);
#endif
  if(IKE_STATEM_IS_INITIATOR(ike_session)) {
    if(ike_session->num_retransmit < IKE_RETRANSMIT_MAX) {
      IPSEC_PRINTF(IPSEC_IKE "Timeout for session %p. Reissuing last transition.\n", ike_session);
#if WITH_COMPOWER
      powertrace_print("#P IKE_Timeout <");
#endif
      ike_statem_run_transition(ike_session, 1);
#if WITH_COMPOWER
      powertrace_print("#P IKE_Timeout >");
#endif
    } else {
      IPSEC_PRINTF(IPSEC_ERROR "Maximum number of retransmissions reached for session %p. Removing all session information.\n", ike_session);

      /* Session Failure timer */
      if(ike_session->ephemeral_info != NULL) {
        ike_statem_clean_session(ike_session);
      }
      ike_statem_remove_session(ike_session);
    }
  } else {
    IPSEC_PRINTF(IPSEC_ERROR "Timeout for responder in session %p. Removing all session information.\n", ike_session);
    /* Session Failure timer */
    if(ike_session->ephemeral_info != NULL) {
      ike_statem_clean_session(ike_session);
    }
    ike_statem_remove_session(ike_session);
  }
}
/*---------------------------------------------------------------------------*/
ike_statem_session_t *
ike_statem_get_session_by_addr(uip_ip6addr_t *addr)
{
  ike_statem_session_t *session;

  for(session = list_head(sessions);
      session != NULL;
      session = list_item_next(session)) {
    uint8_t i;
    for(i = 0; i < sizeof(uip_ip6addr_t); ++i) {
      if(memcmp((const void *)&session->peer, (const void *)addr, sizeof(uip_ip6addr_t)) == 0) {
        return session;
      }
    }
  }

  return NULL;
}
/*---------------------------------------------------------------------------*/
ike_statem_session_t *
ike_statem_get_session_by_group_addr(uip_ip6addr_t *addr)
{
  ike_statem_session_t *session;

  for(session = list_head(sessions);
      session != NULL;
      session = list_item_next(session)) {
    uint8_t i;
    for(i = 0; i < sizeof(uip_ip6addr_t); ++i) {
      if(memcmp((const void *)&session->group_ip, (const void *)addr, sizeof(uip_ip6addr_t)) == 0) {
        return session;
      }
    }
  }

  return NULL;
}
/*---------------------------------------------------------------------------*/
void
ike_statem_incoming_data_handler()     /* uint32_t *start, uint16_t len) */
{
  /* Get the IKEv2 header */
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)udp_buf;
  gsak_entry_t *gsak_entry;
  ike_statem_session_t *session = NULL;
  /**
   * The message that we've received is sent with the purpose of establishing
   * a new session or request something in relation to an existing one.
   *
   * We only regard the lower 32 bits of the IKE SPIs because I think it'll be enough to
   * distinguish them
   */



  if(ike_hdr->sa_responder_spi_low == 0 && IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR & ike_hdr->flags) {
    /* The purpose of this request is to setup a new IKE session. */

    IPSEC_PRINTF(IPSEC_IKE "Handling incoming request for a new IKE session\n");
    ike_statem_setup_responder_session();
    return;
  }
  if(ike_hdr->exchange_type ==IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_GSA_REKEY){
	  IPSEC_PRINTF(IPSEC_IKE "GSA Rekey message to be processed ...\n");
  		  gsak_entry = find_gsak_entry(uip_ntohl(ike_hdr->sa_responder_spi_low));
				  if(gsak_entry==NULL){
					  IPSEC_PRINTF(IPSEC_IKE_ERROR "We didn't find the KEK GSA entry.\n");
					  return;
				  }else{
					  IPSEC_PRINTF(IPSEC_IKE "GSA ENTRY found %p \n",gsak_entry);
					  uint8_t  msg_id =(uint8_t)(uip_ntohl(ike_hdr->message_id));
				if(msg_id >= gsak_entry->msg_id){
					gsak_entry->msg_id = msg_id;

					parse_rekey_msg(udp_buf,gsak_entry);
				}else{
					IPSEC_PRINTF(IPSEC_IKE_ERROR "Dropping old GSA Rekey message.\n");
					 return;
				}
		}
  }else{
  /* So, the request is concerns an existing session. Find the session struct by matching the SPIs. */
  uint32_t my_spi = 0;
  if(IKE_PAYLOADFIELD_IKEHDR_FLAGS_INITIATOR & ike_hdr->flags) {
    /* The other party is the original initiator */
    my_spi = uip_ntohl(ike_hdr->sa_responder_spi_low);

  } else {
    /* The other party is the responder */
    my_spi = uip_ntohl(ike_hdr->sa_initiator_spi_low);

  } IPSEC_PRINTF(IPSEC_IKE "Handling incoming request concerning local IKE SPI %u\n", my_spi);


  for(session = list_head(sessions);
      session != NULL && !IKE_STATEM_MYSPI_GET_MYSPI(session) == my_spi;
      session = list_item_next(session)) {

    IPSEC_PRINTF("SPI in list: %u\n", IKE_STATEM_MYSPI_GET_MYSPI(session));
  }
  if(session != NULL) {
    /* We've found the session struct of the session that the message concerns */

	    /* Assert that the message ID is correct */
    if(ike_hdr->flags & IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONDER) {
      /* It's response to something we sent. Does it have the right message ID? */
      if(uip_ntohl(ike_hdr->message_id) != session->my_msg_id) {
        IPSEC_PRINTF(IPSEC_IKE_ERROR "Response message ID is out of order (%u). Dropping it. (expected %u)\n", uip_ntohl(ike_hdr->message_id), session->my_msg_id);
        return;
      }
    } else
    /* It's a request */
    if(uip_ntohl(ike_hdr->message_id) != session->peer_msg_id
       && uip_ntohl(ike_hdr->message_id) != (session->peer_msg_id - 1)) {
      IPSEC_PRINTF(IPSEC_IKE_ERROR "Request message ID is out of order (%u). Dropping it. (expected %u)\n", uip_ntohl(ike_hdr->message_id), session->peer_msg_id);
      return;
    }

    ike_statem_enterstate(session);
  } else {
    IPSEC_PRINTF(IPSEC_IKE_ERROR "We didn't find the session.\n");
    /**
     * Don't send any notification.
     * We're not sending any Notification regarding this dropped message.
     * See section 1.5 "Informational Messages outside of an IKE SA" for more information.
     */
  }
}//end of else
}
/*---------------------------------------------------------------------------*/
void
ike_statem_send(ike_statem_session_t *session, uint16_t len)
{

#if IPSEC_TIME_STATS
  rtimer_clock_t send_time;
  send_time = RTIMER_NOW();
#endif

  uip_udp_packet_sendto(my_conn, udp_buf, len, &session->peer, uip_htons(IKE_UDP_PORT));

#if IPSEC_TIME_STATS
  send_time = RTIMER_NOW() - send_time;
  printf("Transmission time of IKE message: %lu us, %u bytes\n", (uint32_t)((uint64_t)send_time * 1000000 / RTIMER_SECOND), len);
#endif
}

/*
 *----------------------------------> GROUP-IKEv2 <-------------------------------------------------
 * For this extension the following functions are included.
 * gike_statem_setup_member_session: function to set up a new session of a candidate member.
 *
 */
void set_rekey_event(void *gsak_entry){


	 process_post(&ike2_service, rekey_event, gsak_entry);
}
/*----------------------------------------------------------------------------------------------------*/
void gike_rekeying_msg_leave(gsak_entry_t *gsak_entry){
#if WITH_COMPOWER
      	powertrace_print("#P GSA_REKEY2 <");
#endif
	gsak_entry->rekey_case = 2;
	printf("GSA_REKEY CASE: %u \n", gsak_entry->rekey_case);

	gike_rekeying_msg_init_unicast(gsak_entry);

	gsak_entry->rekey_case = 3;
	IPSEC_PRINTF("STARTING rekey leave timer for gsak_entry %p\n", gsak_entry);
  	ctimer_set(&rekey_leave_timer, 0.5 * REKEY_TIMER * CLOCK_SECOND, gike_rekeying_msg_init, (void *)gsak_entry);
#if WITH_COMPOWER
     	powertrace_print("#P GSA_REKEY2 >");
#endif
}
/*----------------------------------------------------------------------------------------------------*/
void gike_rekeying_msg_init(gsak_entry_t *gsak_entry){
#if WITH_COMPOWER
uint8_t rekey_case_temp = gsak_entry->rekey_case;
if (rekey_case_temp == 0) {
      powertrace_print("#P GSA_REKEY0 <");
} else if (rekey_case_temp == 1) {
      powertrace_print("#P GSA_REKEY1 <");
} else if (rekey_case_temp == 3) {
      powertrace_print("#P GSA_REKEY3 <");
}
#endif

	printf("The gsak->group_id = ");
	printf("\n");
	uip_ipaddr_t ipaddr;

	payload_arg_t payload_arg = {
		.start = msg_buf,
		//.session = session
	};
	printf("Gike_rekeying_msg session for gsak entry %p\n", gsak_entry);
	/* Write the IKE header */
	ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)payload_arg.start;

	ike_hdr->sa_initiator_spi_high = 0U;;
	ike_hdr->sa_initiator_spi_low = 0U;
	ike_hdr->sa_responder_spi_high = 0U;
	ike_hdr->sa_responder_spi_low = uip_htonl(gsak_entry->spi);
	ike_hdr->version = IKE_PAYLOADFIELD_IKEHDR_VERSION_STRING;
	ike_hdr->exchange_type = IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_GSA_REKEY;
	ike_hdr->flags = IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE;
	ike_hdr->message_id = uip_htonl((uint32_t)gsak_entry->msg_id);
	payload_arg.prior_next_payload = &ike_hdr->next_payload;
	payload_arg.start += sizeof(ike_payload_ike_hdr_t);

	transition_return_t message = 0;
	// Join, Leave 2 or Periodic Rekeying
	message = gike_statem_send_rekey_msg(gsak_entry, &payload_arg, NULL);
	IPSEC_PRINTF(IPSEC_IKE "Sending data of length %u\n", message);
	uip_udp_packet_sendto(my_conn, udp_buf, message, &gsak_entry->group_id, uip_htons(IKE_UDP_PORT));
	IPSEC_PRINTF(IPSEC_IKE "GSA_REKEY LEAVE: Sending data of length %u\n", message);
	//clock_wait(6 * CLOCK_SECOND);
#if WITH_COMPOWER
if (rekey_case_temp == 0) {
      powertrace_print("#P GSA_REKEY0 >");
} else if (rekey_case_temp == 1) {
      powertrace_print("#P GSA_REKEY1 >");
} else if (rekey_case_temp == 3) {
      powertrace_print("#P GSA_REKEY3 >");
}
#endif
}
/*----------------------------------------------------------------------------------------------------*/
void gike_rekeying_msg_init_unicast(gsak_entry_t *gsak_entry){
	// Leave Rekeying
	uint8_t i;
	gsak_entry->msg_id++;
	gsak_entry->key_index++;

	// First messages
	for(i = 0; i < NUM_OF_CAN_MEMBERS; i++) {
		printf("The gsak->group_id = ");
		printf("\n");
		uip_ip6addr_t member_addr;

		payload_arg_t payload_arg = {
			.start = msg_buf,
			//.session = session
		};
		printf("Gike_rekeying_msg session for gsak entry %p\n", gsak_entry);
		/* Write the IKE header */
		ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)payload_arg.start;

		ike_hdr->sa_initiator_spi_high = 0U;;
		ike_hdr->sa_initiator_spi_low = 0U;
		ike_hdr->sa_responder_spi_high = 0U;
		ike_hdr->sa_responder_spi_low = uip_htonl(gsak_entry->spi);
		ike_hdr->version = IKE_PAYLOADFIELD_IKEHDR_VERSION_STRING;
		ike_hdr->exchange_type = IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_GSA_REKEY;
		ike_hdr->flags = IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE;
		ike_hdr->message_id = uip_htonl((uint32_t)gsak_entry->msg_id);
		payload_arg.prior_next_payload = &ike_hdr->next_payload;
		payload_arg.start += sizeof(ike_payload_ike_hdr_t);

		transition_return_t message = 0;
		// Leave 1 Rekeying
		message = gike_statem_send_rekey_msg(gsak_entry, &payload_arg, &gpad_table[i].pairwise_secret_key);
		IPSEC_PRINTF(IPSEC_IKE "Sending data of length %u\n", message);
		uiplib_ipaddrconv(gpad_table[i].group_member,&member_addr);
		uip_udp_packet_sendto(my_conn, udp_buf, message, &member_addr, uip_htons(IKE_UDP_PORT));
		IPSEC_PRINTF(IPSEC_IKE "GSA_REKEY LEAVE: Sending data of length %u\n", message);
		//clock_wait(1 * CLOCK_SECOND);
	}
	gsak_entry->rekey_case = 0;
}
/*----------------------------------------------------------------------------------------------------*/
void gsak_entries_init(){
	 list_init(gsak_entries);
	  memb_init(&gsak_memb);
	  IPSEC_PRINTF(IPSEC_IKE "Initiating Group Security Association Database. \n");

}

/*----------------------------------------------------------------------------------------------------*/
void
gike_statem_setup_member_session(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry, uip_ip6addr_t server_ip)
{
  ike_statem_session_t *session = NULL;

  session = ike_statem_session_init();
  //session->gsak_entry = NULL;
  if(session == NULL) {
    return;
    /* Populate the session entry */
  }
  /*Allocate the memory block to gsak_entry*/

  gsak_entries_init();


  memcpy(&session->peer, &server_ip, sizeof(uip_ip6addr_t));
  session->peer = server_ip;

  memcpy(&session->group_ip, &triggering_pkt_addr->peer_addr, sizeof(uip_ip6addr_t));
  session->group_ip = triggering_pkt_addr->peer_addr;

  /* We're the initiator */
  IKE_STATEM_MYSPI_SET_I(session->initiator_and_my_spi);

  /* Transition to state initrespwait */
  session->transition_fn = &gike_statem_trans_initreq;	//Transition to gike_statem_trans_initreq
  session->next_state_fn = &gike_statem_state_initrespwait;	//next state to gike_statem_state_initrespwait

  /* Populate the ephemeral information with connection setup information */

  memcpy(&session->ephemeral_info->spd_entry, commanding_entry, sizeof(spd_entry_t));
  memcpy(&session->ephemeral_info->my_ts_offer_addr_set, &commanding_entry->selector, sizeof(ipsec_addr_set_t));

  /* So address isn't overwritten*/
  memcpy(&session->ephemeral_info->spd_entry.selector.peer_addr_from,
         &commanding_entry->selector.peer_addr_from, sizeof(uip_ip6addr_t));
  memcpy(&session->ephemeral_info->spd_entry.selector.peer_addr_to,
         &commanding_entry->selector.peer_addr_to, sizeof(uip_ip6addr_t));
  session->ephemeral_info->my_ts_offer_addr_set.peer_addr_from = &session->ephemeral_info->peer_addr_from;
  session->ephemeral_info->my_ts_offer_addr_set.peer_addr_to = &session->ephemeral_info->peer_addr_to;

  session->my_msg_id = 0;
  session->peer_msg_id = 0;

  /* Initialize the retransmission counter */
  session->num_retransmit = 0;

  /* Used for RPL and IEEE 802.15.4 key management */
  session->recieved_rpl_supported = 0;
  session->recieved_ieee_supported = 0;
  session->received_gike_supported = 0;
  session->incoming_entry = NULL;
  session->outgoing_entry = NULL;

#if IKE_WITH_IEEE
  memset(&session->peer_lladdr, 0, sizeof(uip_lladdr_t));
#endif

  IKE_STATEM_TRANSITION(session);
}
/*--------------------------------------------------------------------*/
gsak_entry_t *
create_gsak_entry(uint32_t *spi){
	/*Allocate the memory block to gsak_entry*/
	gsak_entry_t *gsak_entry = NULL;


		    gsak_entry = memb_alloc(&gsak_memb);
		     if(gsak_entry== NULL) {
		       IPSEC_PRINTF("Gsak_entries full removing oldest entry\n");
		       gsak_entry_t *delete;
		       delete = list_chop(gsak_entries);
		       gsak_entry = memb_alloc(&gsak_memb);
		       }
		     list_push(gsak_entries, gsak_entry);
	printf("New gsak_entry is created %p. \n", gsak_entry);
	gsak_entry->rekey_case = 0;
	gsak_entry->msg_id = 0;
	gsak_entry->key_index = 0;
	gsak_entry->spi = spi;
	return gsak_entry;


}

/*--------------------------------------------------------------------*/
gsak_entry_t *
find_gsak_entry(uint32_t *spi){
	gsak_entry_t *selected_gsak_entry;
	for(selected_gsak_entry = list_head(gsak_entries); selected_gsak_entry != NULL; selected_gsak_entry = list_item_next(selected_gsak_entry)) {

		if(selected_gsak_entry->spi == spi) {

		      return selected_gsak_entry;
	}
		 printf("GSAK: No entry found. \n");
		 return NULL;
}
}
/*--------------------------------------------------------------------*/
gsak_entry_t *
find_gsak_entry_by_mcst_addr(uip_ip6addr_t *mcst_addr){
	gsak_entry_t *selected_gsak_entry;
	for(selected_gsak_entry = list_head(gsak_entries); selected_gsak_entry != NULL; selected_gsak_entry = list_item_next(selected_gsak_entry)) {
		if(memcmp((const void *)&selected_gsak_entry->group_id,(const void *)mcst_addr,sizeof(uip_ip6addr_t))==0) {

			return selected_gsak_entry;
	}
		 printf("GSAK: No entry found. \n");
		 return NULL;
}
}

/** @} */
