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
 *    State functions for the machine that responds to IKEv2 connections
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se>
 *
 */

#include "common-ike.h"
#include "spd-conf.h"
#include "ecc.h"
#include "ecdh.h"
#include "gike-functions.h"
#include "sys/ctimer.h"
#if IKE_IPSEC_INFO
#include <stdio.h>
#endif

process_event_t ike_negotiate_done;

/* Handler to cleanup session information*/
void ike_statem_cleanup_handler(void *session);

/* Used by the responder to know when he can cleanup  and  to delete session information for half-open sessions */
#define SET_SESSION_CLEANUP_TIMER(session) \
  ctimer_set(&session->retrans_timer, 2 * IKE_RETRANSMIT_MAX * IKE_STATEM_TIMEOUT, &ike_statem_cleanup_handler, (void *)session);

#define STOP_TIMER(session) \
  IPSEC_PRINTF("STOPPING failure timer for session %p\n", session); \
  ctimer_stop(&(session)->retrans_timer);

state_return_t
ike_statem_state_parse_initreq(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("--------\tIKE_SA_INIT\t--------\n");
  printf("IKE_SA_INIT request received for session %p\n", session);
#endif
  /* We expect to receive something like */
  /* HDR, SAi1, KEi, Ni  --> */
  IPSEC_PRINTF(IPSEC_IKE "ike_statem_state_respond_start: Entering\n");

  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)msg_buf;

  /* Store the peer's SPI (in network byte order) */
  session->peer_spi_high = ike_hdr->sa_initiator_spi_high;
  session->peer_spi_low = ike_hdr->sa_initiator_spi_low;

  if(ike_statem_parse_sa_init_msg(session, ike_hdr, session->ephemeral_info->ike_proposal_reply) == 0) {
    return STATE_FAILURE;
  }
  /*
   * Here we differentiate the case when Group Key Management with IKEv2
   * is invoked and we change the state machine flow from IKEv2 to Group IKEv2
   * for the responder. IN Group IKEv2 the responder is always the GCKS.
   */

  if(session->received_gike_supported){
	  session->transition_fn = &gike_statem_trans_initresp;
	  session->next_state_fn = &gike_statem_state_parse_gsauthreq;
	  //printf("PETUXE!!");
  }else{
	  session->transition_fn = &ike_statem_trans_initresp;
	  session->next_state_fn = &ike_statem_state_parse_authreq;
  }

  IKE_STATEM_TRANSITION(session);

  return STATE_SUCCESS;
}
/*---------------------------------------------------------------------------*/
transition_return_t
ike_statem_trans_initresp(ike_statem_session_t *session)
{
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };

  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)payload_arg.start;
  SET_IKE_HDR_AS_RESPONDER(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_SA_INIT, IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE);

  return ike_statem_send_sa_init_msg(session, &payload_arg, ike_hdr, session->ephemeral_info->ike_proposal_reply);
}
/*---------------------------------------------------------------------------*/
state_return_t
ike_statem_state_parse_authreq(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("--------\tIKE_AUTH\t--------\n");
  printf("IKE_AUTH request received for session %p\n", session);
#endif

  if(ike_statem_parse_auth_msg(session) == STATE_SUCCESS) {
    session->transition_fn = &ike_statem_trans_authresp;
    session->next_state_fn = &ike_statem_state_established_handler;

    IKE_STATEM_TRANSITION_NO_TIMEOUT(session);    /* We're about to send a new message */
    /* IKE_STATEM_INCRPEERMSGID(session);  // Since we've recognized the peer's message */

    /* FIX: We need to cleanup here, but how do we handle retransmissions of the above transition? */
    /* This is an unsolved problem as of now, but it can be fixed by allowing the session struct to */
    /* remain for some time and only remove it when we are certain that the peer has finished. */
    /* FIX(RMM): Now the responder only removes the session information after a certain time but
     * it could still happen that the IKE_AUTH response was lost so we are still not certain that the
     * IKE_AUTH exchange was successful */

    /* Stop failure timer or cleanup timer*/
    STOP_TIMER(session);
    SET_SESSION_CLEANUP_TIMER(session);

    ike_negotiate_done = process_alloc_event();

    process_post(PROCESS_BROADCAST, ike_negotiate_done, session);

    return STATE_SUCCESS;
  } else {
    return STATE_FAILURE;
  }
}
/*---------------------------------------------------------------------------*/
void
ike_statem_cleanup_handler(void *session)       /* Void argument since we're called by ctimer */
{
  ike_statem_session_t *ike_session = (ike_statem_session_t *)session;

  if(ike_session->ephemeral_info != NULL) {
    ike_statem_clean_session(ike_session);
  }
}
/*---------------------------------------------------------------------------*/
transition_return_t
ike_statem_trans_authresp(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("--------\tIKE_AUTH\t--------\n");
#endif

  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };

  /* Write the IKE header */
  SET_IKE_HDR_AS_RESPONDER(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_IKE_AUTH, IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE);

  return ike_statem_send_auth_msg(session, &payload_arg, session->ephemeral_info->my_child_spi, session->ephemeral_info->child_proposal_reply, &session->ephemeral_info->my_ts_offer_addr_set);
}
/** @} */
