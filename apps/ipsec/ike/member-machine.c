/*
 * member-machine.c
 *
 *  Created on: Jun 21, 2016
 *      Author: Argyro Lamproudi <argyro@student.chalmers.se>
 */
/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    State functions for the candidate member that invokes G-IKEv2.
 *
 *
 */

#include "../ike/gike-functions.h"
#include "sad.h"
#include "common-ike.h"
#include "auth.h"
#include "spd-conf.h"
#include "ecc.h"
#include "ecdh.h"
#include "ike.h"
#if IKE_IPSEC_INFO
#include <stdio.h>
#endif

process_event_t ike_negotiate_done;

transition_return_t gike_statem_trans_gsauthreq(ike_statem_session_t *session);
state_return_t gike_statem_state_gsauthrespwait(ike_statem_session_t *session);

/* Transmit the IKE_SA_INIT message: HDR, SAi1, KEi, Ni */
/* If cookie_payload in ephemeral_info is non-NULL the first payload in the message will be a COOKIE Notification. */
transition_return_t
gike_statem_trans_initreq(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("--------\tIKE_SA_INIT\t--------\n");
#endif
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };

  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)payload_arg.start;
  SET_IKE_HDR_AS_INITIATOR(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_SA_INIT, IKE_PAYLOADFIELD_IKEHDR_FLAGS_REQUEST);

  return ike_statem_send_sa_init_msg(session, &payload_arg, ike_hdr, (spd_proposal_tuple_t *)CURRENT_IKE_PROPOSAL);
}
/*---------------------------------------------------------------------------*/
/**
 *
 * INITRESPWAIT ---> INIT_SARESP received ---> GSA_AUTHREQ sent---> GSA_AUTHRESPWAIT
 *
 */
uint8_t
gike_statem_state_initrespwait(ike_statem_session_t *session)
{

#if IKE_IPSEC_INFO
  printf("IKE_SA_INIT response received for session %p\n", session);
#endif
  /* If everything went well, we should see something like */
  /* <--  HDR, SAr1, KEr, Nr, [CERTREQ] */

  /* Otherwise we expect a reply like */
  /* COOKIE or INVALID_KE_PAYLOAD */

  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)msg_buf;

  /* Store the peer's SPI (in network byte order) */
  session->peer_spi_high = ike_hdr->sa_responder_spi_high;
  session->peer_spi_low = ike_hdr->sa_responder_spi_low;



  if(ike_statem_parse_sa_init_msg(session, ike_hdr, session->ephemeral_info->ike_proposal_reply) == 0) {
    return 0;
    /* Jump */
    /* Transition to state autrespwait */
  }

  session->transition_fn = &gike_statem_trans_gsauthreq;
  session->next_state_fn = &gike_statem_state_gsauthrespwait;

  IKE_STATEM_TRANSITION(session);

  return 1;

  /* This ends the INIT exchange. Both parties have now negotiated the IKE SA's parameters and created a common DH secret. */
  /* We will now proceed with the AUTH exchange. */
}
/*---------------------------------------------------------------------------*/
/* Transmit the IKE_AUTH message: */
/*    HDR, SK {IDi, [CERT,] [CERTREQ,] */
/*      [IDr,] AUTH, SAi2, TSi, TSr} */
uint16_t
gike_statem_trans_gsauthreq(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("--------\tGSA_AUTH\t--------\n");
#endif
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };

  /* Write the IKE header */
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)payload_arg.start;
  SET_IKE_HDR_AS_INITIATOR(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_GSA_AUTH, IKE_PAYLOADFIELD_IKEHDR_FLAGS_REQUEST);


  return gike_statem_send_gsauth_msg(session, &payload_arg);
}
/*---------------------------------------------------------------------------*/
/**
 * AUTH response wait state
 */
state_return_t
gike_statem_state_gsauthrespwait(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("GSA_AUTH response received for session %p\n", session);
#endif
  /* If everything went well, we should see something like */
  /* <--  HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr} */
  if(gike_statem_parse_gsauth_msg(session) == STATE_SUCCESS) {

    /* Remove stuff that we don't need */
    ike_statem_clean_session(session);
    ike_statem_remove_session(session);
    /* Transition to state autrespwait */
    session->transition_fn = NULL;
    session->next_state_fn = &gike_statem_state_established_handler;

    ike_negotiate_done = process_alloc_event();

    process_post(PROCESS_BROADCAST, ike_negotiate_done, session);

    clock_time_t end_time = clock_time();
    printf("End time: %lu\n", (uint32_t)(end_time));

    return STATE_SUCCESS;
  }

  return STATE_FAILURE;
}
/** @} */
