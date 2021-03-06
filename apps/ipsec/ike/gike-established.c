/*
 * gike-established.c
 *
 *  Created on: Jul 4, 2016
 *      Author: Argyro Lamproudi <argyro@student.chalmers.se>
 */

#include "../ike/gike-functions.h"
#include "auth.h"
#include "spd-conf.h"
#include "ecc.h"
#include "ecdh.h"
#include "payload.h"
#include "ipsec-malloc.h"
#include "machine.h"

#if WITH_IPSEC
#include "sad.h"
#endif

#if IKE_WITH_RPL
#include "rpl/rpl-sad.h"
#endif

/* Network stuff */
static const uint8_t *udp_buf = &uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];


uint8_t
gike_statem_state_established_handler(ike_statem_session_t *session)
{
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)udp_buf;

  if(uip_ntohl(ike_hdr->message_id) == (session->peer_msg_id - 1)) {

    if(!IKE_STATEM_IS_INITIATOR(session)) {
      IPSEC_PRINTF("Retransmitting GSA_AUTH\n");
      /*PRINTIPSEC6ADDR(&session->peer);*/

      session->peer_msg_id = 0;
      session->my_msg_id = session->my_msg_id - 1;
      session->next_state_fn = &gike_statem_state_parse_gsauthreq;
      session->transition_fn = NULL;
      IPSEC_PRINTF("peer msg ID %u, my msg ID %u\n", session->peer_msg_id, session->my_msg_id);
      ike_statem_enterstate(session);
      session->my_msg_id = session->my_msg_id + 1;
      IPSEC_PRINTF("peer msg ID %u, my msg ID %u\n", session->peer_msg_id, session->my_msg_id);


    }
    return 1;
  }

  uint8_t *ptr = msg_buf + sizeof(ike_payload_ike_hdr_t);
  uint8_t *end = msg_buf + uip_datalen();
  ike_payload_type_t payload_type = ike_hdr->next_payload;

  while(ptr < end) {  /* Payload loop */
    const ike_payload_generic_hdr_t *genpayloadhdr = (const ike_payload_generic_hdr_t *)ptr;
    const uint8_t *payload_start = (uint8_t *)genpayloadhdr + sizeof(ike_payload_generic_hdr_t);
    switch(payload_type) {
    case IKE_PAYLOAD_SK:
      if((end -= ike_statem_unpack_sk(session, (ike_payload_generic_hdr_t *)genpayloadhdr)) == 0) {
        IPSEC_PRINTF(IPSEC_IKE_ERROR "SK payload: Integrity check of peer's message failed\n");
      } else {
        IPSEC_PRINTF("SK payload: Integrity check successful\n");
      } break;
    case IKE_PAYLOAD_D:
    {
      ike_payload_delete_t *delete = (ike_payload_delete_t *)payload_start;
      IPSEC_PRINTF("Delete payload - Protocol ID %u\n", delete->proto_id);

      /* If SPI_size = 0 we can delete the IKE SA*/
      if(delete->proto_id == SA_PROTO_IKE && delete->spi_size == 0) {
        IPSEC_PRINTF(IPSEC_IKE "Removing IKE session %p due to delete payload from peer\n", session);
        IPSEC_PRINTF(IPSEC_IKE "Removing IKE outgoing and incoming SAD entry\n");
        /* Remove IPSEC SAD entries */
#if WITH_IPSEC
        sad_remove_outgoing_entry(session->outgoing_entry);
        sad_remove_incoming_entry(session->incoming_entry);
#endif
        /* Remove RPL SAD entries */
#if IKE_WITH_RPL
        rpl_sad_remove_outgoing_entry(session->outgoing_entry);
        rpl_sad_remove_incoming_entry(session->incoming_entry);
#endif
        /* Remove RPL SAD entries */
#if IKE_WITH_IEEE
        ieee_sad_remove_outgoing_entry(session->outgoing_entry);
        ieee_sad_remove_incoming_entry(session->incoming_entry);
#endif

        ike_statem_remove_session(session);
        session = NULL;
        return 1;
      }
      break;
    }
    default:
      /**
       * Unknown / unexpected payload. Is the critical flag set?
       *
       * From p. 30:
       *
       * "If the critical flag is set
       * and the payload type is unrecognized, the message MUST be rejected
       * and the response to the IKE request containing that payload MUST
       * include a Notify payload UNSUPPORTED_CRITICAL_PAYLOAD, indicating an
       * unsupported critical payload was included.""
       */

      if(genpayloadhdr->clear) {
        IPSEC_PRINTF(IPSEC_IKE_ERROR "Encountered an unknown critical payload\n");
      } else {
        IPSEC_PRINTF(IPSEC_IKE "Ignoring unknown non-critical payload of type %u\n", payload_type);

        /* Info: Ignored unknown payload */
      }
    }
    ptr = (uint8_t *)genpayloadhdr + uip_ntohs(genpayloadhdr->len);
    payload_type = genpayloadhdr->next_payload;
  }

  IPSEC_PRINTF(IPSEC_IKE "Ignoring IKE message sent by peer\n");
  return 1;
}
/** @} */
