/*
 * gcks-machine.c
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
 *    State functions for the Group Controller/Key Server responding to G-IKEv2 requests.
 *
 */

#include "../ike/gike-functions.h"
#include "common-ike.h"
#include "spd-conf.h"
#include "ecc.h"
#include "ecdh.h"
#include "sys/ctimer.h"
#if IKE_IPSEC_INFO
#include <stdio.h>
#endif

process_event_t ike_negotiate_done;
//process_event_t rekey_event;
/* Handler to cleanup session information*/
void ike_statem_cleanup_handler(void *session);

/* Used by the responder to know when he can cleanup  and  to delete session information for half-open sessions */
#define SET_SESSION_CLEANUP_TIMER(session) \
  ctimer_set(&session->retrans_timer, 2 * IKE_RETRANSMIT_MAX * IKE_STATEM_TIMEOUT, &ike_statem_cleanup_handler, (void *)session);

#define STOP_TIMER(session) \
  IPSEC_PRINTF("STOPPING failure timer for session %p\n", session); \
  ctimer_stop(&(session)->retrans_timer);


/*---------------------------------------------------------------------------*/
transition_return_t
gike_statem_trans_initresp(ike_statem_session_t *session)
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
gike_statem_state_parse_gsauthreq(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("--------\tGSA_AUTH\t--------\n");
  printf("GSA_AUTH request received for session %p\n", session);
#endif
  if(gike_statem_parse_gsauth_msg(session) == STATE_SUCCESS) {
    session->transition_fn = &gike_statem_trans_gsauthresp;
    session->next_state_fn = &gike_statem_state_established_handler;
    //session->next_state_fn = &gike_statem_state_rekey;

    IKE_STATEM_TRANSITION(session);
    //IKE_STATEM_TRANSITION_NO_TIMEOUT(session);    /* We're about to send a new message */
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

    ike_negotiate_done = process_alloc_event(); //check if we really nead this event in GCKS. I think we do not need it.

   process_post(PROCESS_BROADCAST, ike_negotiate_done, session);


    return STATE_SUCCESS;
  } else {
    return STATE_FAILURE;
  }
}

/*---------------------------------------------------------------------------*/
transition_return_t
gike_statem_trans_gsauthresp(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("--------\tGSA_AUTH\t--------\n");
#endif

  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };


  uint8_t n;
  gsak_entry_t *gsak_entry;
  n = session->sender_id;
  if (n+1 > 0){
      		uint32_t *kek_spi = gpad_table[n].kek_spi;
      		printf("MEMBER_TABLE row %d is %s \n",n,gpad_table[n].group_member);
      		printf("kek_spi = %u \n",kek_spi);
      		gsak_entry = find_gsak_entry(kek_spi);
      		if(gsak_entry==NULL){
      			printf("Proceed with sending GSA_AUTH message. \n");
      		}else{
      			printf("Initiating GSA REKEY message \n");
      			gsak_entry->rekey_case = 1;
#if WITH_COMPOWER
      powertrace_print("#P new GSA_REKEY <");
#endif
      			gike_rekeying_msg_init(gsak_entry);
      			STOP_REKEY_TIMER(gsak_entry);

#if WITH_COMPOWER
      powertrace_print("#P new GSA_REKEY >");
#endif
      		}
  }


  /* Write the IKE header */
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)payload_arg.start;
  SET_IKE_HDR_AS_RESPONDER(&payload_arg, IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_GSA_AUTH, IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE);

  return gike_statem_send_gsauth_msg(session, &payload_arg);


}

/** @} */


