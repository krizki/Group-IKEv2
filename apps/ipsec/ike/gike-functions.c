/*
 * gike-functions.c
 *
 *  Created on: Jul 5, 2016
 *      Author: Argyro Lamproudi <argyro@student.chalmers.se>
 */

#include <lib/random.h>
#include <string.h>
#include <time.h>
#include "ecc.h"
#include "ecdh.h"
#include "transforms/integ.h"
#include "transforms/encr.h"
#include "machine.h"
#include "spd-conf.h"
#include "common-ike.h"
#include "auth.h"
#include "uip.h"
#include "ecc-sha1.h"
#include "sad.h"
#include "common-ipsec.h"

#include "cert/cert-conf.h"
#include "cert/cert-parser.h"
/*
 * Group IKEv2
 */
#include "g-ike-conf.h"
#include "gike-functions.h"

#if IPSEC_DEBUG
#include "uip-debug.h"
#define IKE_PRINTF(...) printf(__VA_ARGS__)
#define IKE_HEXDUMP(...) hexdump(__VA_ARGS__)
#define IKE_MEMPRINT(str, ptr, len) \
  do { \
    printf(str  " (len %u):\n", len); \
    memprint(ptr, len); \
  } while(0);
#define PRINTTSPAIR(ts_me_ptr, ts_peer_ptr) \
  do { \
    ipsec_addr_set_t addr_set; \
    uip_ip6addr_t peer; \
    addr_set.peer_addr_from = &peer; \
    addr_set.peer_addr_to = &peer; \
    ts_pair_to_addr_set(&addr_set, ts_me_ptr, ts_peer_ptr); \
    PRINTADDRSET(&addr_set); \
  } while(0)
#else
#define IKE_PRINTF(...)
#define IKE_HEXDUMP(...)
#define PRINTTSPAIR(ts_me_ptr, ts_peer_ptr)
#define IKE_MEMPRINT(...)
#define PRINT6ADDR(...)
#define PRINTLLADDR(...)
#endif

#if IKE_IPSEC_INFO
#include <stdio.h>
#if IPSEC_TIME_STATS
#include "sys/rtimer.h"
#endif
#endif

/*
 * Send GSA_AUTH Message
 */
transition_return_t
gike_statem_send_gsauth_msg(ike_statem_session_t *session, payload_arg_t *payload_arg){

	#if IKE_IPSEC_INFO
  printf("Generating GSA_AUTH message for session %p\n", session);
#if IPSEC_TIME_STATS
  rtimer_clock_t exec_time;
  rtimer_clock_t total_time;
  exec_time = RTIMER_NOW();
  total_time = 0;
#endif
#endif

  /* Write a template of the SK payload for later encryption */
    ike_payload_generic_hdr_t *sk_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
    ike_statem_prepare_sk(payload_arg);

  /*
   * ID payload. We use the e-mail address type of ID for the member and GCKS
   */
    ike_payload_generic_hdr_t *id_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
    if(IKE_STATEM_IS_INITIATOR(session)) {
      ike_statem_set_id_payload(payload_arg, IKE_PAYLOAD_IDi);
    } else {
      ike_statem_set_id_payload(payload_arg, IKE_PAYLOAD_IDr);
    } ike_id_payload_t *id_payload = (ike_id_payload_t *)((uint8_t *)id_genpayloadhdr + sizeof(ike_payload_generic_hdr_t));
/*
 * Group ID payload. We use the multicast address type of ID. The Group ID is sent
 *  upon GSA_AUTH request from candidate member.
 */
    if(IKE_STATEM_IS_INITIATOR(session)) {
    ike_payload_generic_hdr_t *idg_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
    ike_statem_set_group_id_payload(payload_arg, IKE_PAYLOAD_IDg,session);
    ike_id_payload_t *idg_payload = (ike_id_payload_t *)((uint8_t *)idg_genpayloadhdr + sizeof(ike_payload_generic_hdr_t));
/*
 * Send notification for requesting a sender_ids
 */
    ike_statem_write_notification(payload_arg, SA_PROTO_IKE, 0,
    		IKE_PAYLOAD_NOTIFY_REQUEST_FOR_GROUP_SENDER, NULL, 0);

    }


    /* Send cert request if we received a certificate request from the responder */
    if(session->ephemeral_info->cert_req_recieved == 1) {
      if(IKE_STATEM_IS_INITIATOR(session)) {
        /* Write Certificate Request here if pubkey auth */
        ike_payload_generic_hdr_t *cert_req_genpayloadhdr;
        SET_GENPAYLOADHDR(cert_req_genpayloadhdr, payload_arg, IKE_PAYLOAD_CERTREQ);

        /* Write the certificate request */
        ike_payload_cert_t *cert = (ike_payload_cert_t *)payload_arg->start;
        cert->cert_encoding = CERT_X509_SIGNATURE;

        /* Create the 20 octet SHA-1 hash of the DER encoded */
        uint8_t cert_authority[SHA1_CERT_HASH_LEN];

        /* Generate the cert_authority field of the cert request payload*/
        if(gen_cert_authority(cert_authority)) {
          memcpy(payload_arg->start + sizeof(ike_payload_cert_t), cert_authority, SHA1_CERT_HASH_LEN);
          IKE_MEMPRINT("Cert request payload: ", (uint8_t *)cert_req_genpayloadhdr, 25);

          /* calculate the length */
          payload_arg->start += sizeof(ike_payload_cert_t) + SHA1_CERT_HASH_LEN;
          cert_req_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)cert_req_genpayloadhdr);
        }
      }

  #if WITH_CONF_IKE_CERT_AUTH
      IKE_PRINTF("We received a certificate request, sending our certificate\n");

      /* Send our certificate */
      uint16_t cert_len = 0;

      uint8_t *certificate_hex = get_certificate_hex(&cert_len);

      IKE_PRINTF("Length of our certificate %u\n", cert_len);
      if(certificate_hex != NULL) {

        ike_payload_generic_hdr_t *cert_genpayloadhdr;
        SET_GENPAYLOADHDR(cert_genpayloadhdr, payload_arg, IKE_PAYLOAD_CERT);
        ike_payload_cert_t *cert_payload = (ike_payload_cert_t *)payload_arg->start;
        payload_arg->start += sizeof(ike_payload_cert_t);

        cert_payload->cert_encoding = CERT_X509_SIGNATURE;

        /* get the certificate and write it after the Certificate encoding field */
        memcpy(payload_arg->start, certificate_hex, cert_len);

        /* Update lengths */
        payload_arg->start += cert_len;
        cert_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)cert_genpayloadhdr);
      } else {
        IKE_PRINTF("Our Certificate is not defined: \n");
      }
  #endif
    } else {
      IKE_PRINTF("We did not receive a certificate request, NOT sending our certificate\n");
    }
  #if IKE_IPSEC_INFO
  #if IPSEC_TIME_STATS
    exec_time = RTIMER_NOW() - exec_time;
    total_time += exec_time;
    exec_time = RTIMER_NOW();
  #endif
  #endif

    /*
     * Write the AUTH payload (section 2.15)
     *
     * Details depends on the type of AUTH Method specified.
     */
    ike_payload_generic_hdr_t *auth_genpayloadhdr;
    SET_GENPAYLOADHDR(auth_genpayloadhdr, payload_arg, IKE_PAYLOAD_AUTH);
    ike_payload_auth_t *auth_payload = (ike_payload_auth_t *)payload_arg->start;
    payload_arg->start += sizeof(ike_payload_auth_t);

    uint8_t *signed_octets = payload_arg->start + SA_PRF_MAX_OUTPUT_LEN;

  #if IKE_IPSEC_INFO
  #if IPSEC_TIME_STATS
    /* Stopping timer to skip printouts for IKE_SA_INIT*/
    exec_time = RTIMER_NOW() - exec_time;
    total_time += exec_time;
  #endif
  #endif
    uint16_t signed_octets_len = ike_statem_get_authdata(session, 1, signed_octets, id_payload, uip_ntohs(id_genpayloadhdr->len) - sizeof(ike_payload_generic_hdr_t));
  #if IKE_IPSEC_INFO
  #if IPSEC_TIME_STATS
    exec_time = RTIMER_NOW();
  #endif
  #endif

  #if WITH_CONF_IKE_CERT_AUTH
    /* Sign the message with the certificate private key */
    uint16_t auth_len = 0;
    auth_payload->auth_type = IKE_AUTH_ECDSA_256_SHA_256;

    auth_ecdsa(NULL, 1, signed_octets, signed_octets_len, payload_arg->start, &auth_len);

    IKE_PRINTF("Signature length %u\n", auth_len);

    payload_arg->start += auth_len;
    auth_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)auth_genpayloadhdr);
  #else

    auth_payload->auth_type = IKE_AUTH_SHARED_KEY_MIC;

    /*
     * AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
     */
    prf_data_t auth_data = {
      .out = payload_arg->start,
      .data = signed_octets,
      .datalen = signed_octets_len
    };
    auth_psk(session->sa.prf, &auth_data);
    payload_arg->start += SA_PRF_OUTPUT_LEN(session);
    auth_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)auth_genpayloadhdr);  /* Length of the AUTH payload */
  #endif

  #if IKE_IPSEC_INFO
  #if IPSEC_TIME_STATS
    exec_time = RTIMER_NOW() - exec_time;
    total_time += exec_time;
    if(auth_payload->auth_type == IKE_AUTH_SHARED_KEY_MIC) {
      printf("AUTH payload with shared-key, ");
    } else {
      printf("AUTH payload with ECDSA-256, ");
    } printf("%lu us\n", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
    exec_time = RTIMER_NOW();
  #endif
  #endif

/* Only GC/KS utilize the following functions

 * Write GSAT payload

 * Write TEK KD payload
 * */
    if(!IKE_STATEM_IS_INITIATOR(session)) {
    	/* Write GSAK payload*/
    	uint8_t n;
    	gsak_entry_t *gsak_entry;
    	n = session->sender_id;


    	uint32_t *tek_spi = gpad_table[n].tek_spi;

    	sad_entry_t *outgoing_sad_entry;
    	sad_entry_t *incoming_sad_entry;
    	outgoing_sad_entry = find_sad_outgoing_entry(&session->group_ip);
    	incoming_sad_entry = find_sad_incoming_entry(&session->peer,&tek_spi);
    	if(session->incoming_entry != NULL && session->outgoing_entry != NULL) {
    	   sad_remove_outgoing_entry(session->outgoing_entry);
    	   sad_remove_incoming_entry(session->incoming_entry);
    	   }

    	if(incoming_sad_entry == NULL){
    		uint32_t sad_time = clock_time();
    		incoming_sad_entry = sad_create_incoming_entry(sad_time);
    		IKE_PRINTF("New INCOMING SAD is created. \n");
    		if(incoming_sad_entry == NULL) {
    		  IKE_PRINTF(IPSEC_IKE_ERROR "Couldn't create SAs\n");
    		  }

    	}
    	if(outgoing_sad_entry == NULL){
    		uint32_t sad_time = clock_time();
    		outgoing_sad_entry = sad_create_outgoing_entry(sad_time);
    		IKE_PRINTF("New OUTGOING SAD is created. \n");
    		if(outgoing_sad_entry == NULL) {
    		   IKE_PRINTF(IPSEC_IKE_ERROR "Couldn't create SAs\n");
    		   }
    	}



    	if (n+1 > 0){
    		uint32_t *kek_spi = gpad_table[n].kek_spi;

    		gsak_entry = find_gsak_entry(kek_spi);
    		if(gsak_entry == NULL){
    		gsak_entry = create_gsak_entry(kek_spi);}

    		gsak_entry->group_id = session->group_ip;


    		write_gsak_payload(payload_arg, kek_spi, gpad_table[n].kek, GSAK_LIFETIME, gsak_entry);
    		write_gsat_payload(payload_arg, incoming_sad_entry, outgoing_sad_entry, tek_spi,gpad_table[n].tek);

    		memcpy(&incoming_sad_entry->peer, &session->peer, sizeof(uip_ip6addr_t));
    		incoming_sad_entry->traffic_desc.peer_addr_from = &incoming_sad_entry->peer;
    		incoming_sad_entry->traffic_desc.peer_addr_to = &incoming_sad_entry->peer;
    		incoming_sad_entry->traffic_desc.nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL;
    		  /* No HTONS needed here as the maximum and miniumum unsigned ints are represented the same way */
    		  /* in network as well as host byte order. */
    		incoming_sad_entry->traffic_desc.my_port_from = 0;
    		incoming_sad_entry->traffic_desc.my_port_to = PORT_MAX;
    		incoming_sad_entry->traffic_desc.peer_port_from = 0;
    		incoming_sad_entry->traffic_desc.peer_port_to = PORT_MAX;

    		memcpy(&outgoing_sad_entry->peer, &session->group_ip, sizeof(uip_ip6addr_t));
    		outgoing_sad_entry->traffic_desc.peer_addr_from = &session->group_ip;
    		outgoing_sad_entry->traffic_desc.peer_addr_to = &session->group_ip;
    		outgoing_sad_entry->traffic_desc.nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL;
    		 /* No HTONS needed here as the maximum and miniumum unsigned ints are represented the same way */
    		    		  /* in network as well as host byte order. */
    		outgoing_sad_entry->traffic_desc.my_port_from = 0;
    		outgoing_sad_entry->traffic_desc.my_port_to = PORT_MAX;
    		outgoing_sad_entry->traffic_desc.peer_port_from = 0;
    		outgoing_sad_entry->traffic_desc.peer_port_to = PORT_MAX;
    		/** Write KEK KD payload*/
    		write_kd_payload(payload_arg, incoming_sad_entry, outgoing_sad_entry ,kek_spi,gpad_table[n], KEK_KD, gsak_entry);
    		write_kd_payload(payload_arg, incoming_sad_entry, outgoing_sad_entry ,tek_spi,gpad_table[n], TEK_KD, gsak_entry);
    		/*
    		 * Create SID payload. tha kanw mia for loop pou tha prospelattei to gpad_table
    		 * gia na vrei gia to sygkekrimeno group poia members exoume. Ayta ta members
    		 * tha prosthithentai sto payload.
    		 */
    		if(session->sender_enabled==1){
    			write_sid_payload(payload_arg, gsak_entry,session, tek_spi);
    		}
    		IKE_PRINTF("Setting rekey timer in gsak_entry %p \n", gsak_entry);
    		SET_REKEY_TIMER(gsak_entry);
    	}else{
    		IKE_PRINTF("CANDIDATE MEMBER ERROR: Do not exist in database! \n");
    	}

    }
    /* Protect the SK payload. Write trailing fields. */
      ike_statem_finalize_sk(payload_arg, sk_genpayloadhdr, payload_arg->start - (((uint8_t *)sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t)));

      printf("======= End of GSA_AUTH message =======\n");
      if(!IKE_STATEM_IS_INITIATOR(session)) {
            ike_statem_remove_session(session);
            }
  return uip_ntohl(((ike_payload_ike_hdr_t *)msg_buf)->len);   /* Return written length */
}


/*---------------------------------------------------------------------------------------------------------------------*/
/*
 * Function to parse GSA_AUTH message from both candidate member and GC/KS.
 */
state_return_t
gike_statem_parse_gsauth_msg(ike_statem_session_t *session){
#if IKE_IPSEC_INFO
  printf("Parsing and verifying GSA_AUTH ");
  if(IKE_STATEM_IS_INITIATOR(session)) {
    printf("response");
  } else {
    printf("request");
  } printf(" for session %p\n", session);
#if IPSEC_TIME_STATS
  rtimer_clock_t exec_time;
  rtimer_clock_t total_time;
  exec_time = RTIMER_NOW();
  total_time = 0;
#endif
#endif
/*
 * Initialization - Declarations
 */
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)msg_buf;
  ike_id_payload_t *id_data = NULL;
  uint8_t id_datalen;
  uint8_t id_member;

  ike_group_id_payload_t *group_id_payload = NULL;
  const char *group_id_data;
  uint8_t group_id_datalen;
  ike_payload_auth_t *auth_payload = NULL;
  uint8_t transport_mode_not_accepted = 0;
  /*------------- GSAs--------------- */
  sad_entry_t *outgoing_sad_entry;
  sad_entry_t *incoming_sad_entry;
  if(IKE_STATEM_IS_INITIATOR(session)) {
	  uint32_t sad_time = clock_time();


	  if(session->incoming_entry != NULL && session->outgoing_entry != NULL) {
	     sad_remove_outgoing_entry(session->outgoing_entry);
	     sad_remove_incoming_entry(session->incoming_entry);
	    }
	    outgoing_sad_entry = sad_create_outgoing_entry(sad_time);
	    incoming_sad_entry = sad_create_incoming_entry(sad_time);

	    if(outgoing_sad_entry == NULL || incoming_sad_entry == NULL) {
	      IKE_PRINTF(IPSEC_IKE_ERROR "Couldn't create SAs\n");
	      goto fail;
	     }
  }
    uint8_t *ptr = msg_buf + sizeof(ike_payload_ike_hdr_t);
    uint8_t *end = msg_buf + uip_datalen();
    notify_msg_type_t fail_notify_type = 0;


    ike_payload_type_t payload_type = ike_hdr->next_payload;


    uint8_t parsed_payload = 0;


    /* Certificate handling  */
    struct dtls_certificate_context_t peer_cert_ctx;
    peer_cert_ctx.TBSCertificate = NULL;

    /* We have not seen a certificate request payload */
    session->ephemeral_info->cert_req_recieved = 0;




    while(ptr < end) {  /* Payload loop */
        const ike_payload_generic_hdr_t *genpayloadhdr = (const ike_payload_generic_hdr_t *)ptr;
        const uint8_t *payload_start = (uint8_t *)genpayloadhdr + sizeof(ike_payload_generic_hdr_t);

        IKE_PRINTF("Next payload is %u, %u bytes remaining\n", payload_type, uip_datalen() - (ptr - msg_buf));
        switch(payload_type) {

        /*--UNpack the encrypted payload.*/
        case IKE_PAYLOAD_SK:
        #if IKE_IPSEC_INFO
        #if IPSEC_TIME_STATS
              exec_time = RTIMER_NOW() - exec_time;
              total_time += exec_time;
              exec_time = RTIMER_NOW();
        #endif
        #endif
              printf("end = %u \n", end);
              if((end -= ike_statem_unpack_sk(session, (ike_payload_generic_hdr_t *)genpayloadhdr)) == 0) {
                IKE_PRINTF(IPSEC_IKE_ERROR "SK payload: Integrity check of peer's message failed\n");
                fail_notify_type = IKE_PAYLOAD_NOTIFY_INVALID_SYNTAX;
                goto fail;
              	  } else {
                IKE_PRINTF("SK payload: Integrity check successful\n");
              }
#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
      exec_time = RTIMER_NOW() - exec_time;
      total_time += exec_time;
      printf("IKE_AUTH DECR and INTEG, dh=%u, integ_algo=%u, encr_algo=%u, prf_algo=%u, %lu us\n",
             session->sa.dh, session->sa.integ, session->sa.encr, session->sa.prf,
             (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
      exec_time = RTIMER_NOW();
#endif
#endif
      break;

          case IKE_PAYLOAD_N:
          {
            ike_payload_notify_t *notify = (ike_payload_notify_t *)payload_start;
            if(uip_ntohs(notify->notify_msg_type) == IKE_PAYLOAD_NOTIFY_USE_TRANSPORT_MODE) {
              transport_mode_not_accepted = 0;
            }
            if(ike_statem_handle_notify(notify, session)) {
            	printf("NOTIFY MESSAGE FAILURE.\n");
              goto fail;
            }
          }
          break;

          case IKE_PAYLOAD_IDi:
          case IKE_PAYLOAD_IDr:
            IKE_PRINTF("ID payload\n");
            id_data = (ike_id_payload_t *)payload_start;
            id_member = (uint8_t *)payload_start + sizeof(ike_id_payload_t);
            id_datalen = uip_ntohs(genpayloadhdr->len) - sizeof(ike_payload_generic_hdr_t);
            IKE_PRINTF("ID-Type %u, length %u\n", id_data->id_type, id_datalen);

            break;
          case IKE_PAYLOAD_IDg:
                IKE_PRINTF("Group ID payload\n");
                group_id_payload = (ike_group_id_payload_t *)payload_start;										// group id data type
                group_id_payload->group_id = *((uip_ip6addr_t *)payload_start);
                payload_start+=sizeof(group_id_payload->group_id);
                group_id_payload->id_type =*((uint8_t*)payload_start);
                payload_start+=sizeof(uint8_t);

                group_id_datalen = uip_ntohs(genpayloadhdr->len) - sizeof(ike_payload_generic_hdr_t);	// group id data len
                IKE_PRINTF("ID-Type %u, length %u\n", group_id_payload->id_type, group_id_datalen);
                uint8_t n;
                n = is_candidate_member_of_group(group_id_payload->group_id, session->peer, session);
                if( n > 0){
                	IKE_PRINTF("The candidate member is AUTHORIZED for GROUP ");PRINT6ADDR(&group_id_payload->group_id);IKE_PRINTF("\n");

                	session->sender_id = n-1;

                   	break;
                }else{
                	fail_notify_type = IKE_PAYLOAD_NOTIFY_MEMBER_AUTHORIZATION_FAILED;
                	goto fail;
                }
          case IKE_PAYLOAD_GSAK:

        	  parse_gsak_payload(payload_start,session);

        	  break;

          case IKE_PAYLOAD_GSAT:
        	  parse_gsat_payload(payload_start,incoming_sad_entry, outgoing_sad_entry);
        		memcpy(&incoming_sad_entry->peer, &session->peer, sizeof(uip_ip6addr_t));
        		incoming_sad_entry->traffic_desc.peer_addr_from = &session->peer;
        		incoming_sad_entry->traffic_desc.peer_addr_to = &session->peer;
        		incoming_sad_entry->traffic_desc.nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL;
        		  /* No HTONS needed here as the maximum and miniumum unsigned ints are represented the same way */
        		  /* in network as well as host byte order. */
        		incoming_sad_entry->traffic_desc.my_port_from = 0;
        		incoming_sad_entry->traffic_desc.my_port_to = PORT_MAX;
        		incoming_sad_entry->traffic_desc.peer_port_from = 0;
        		incoming_sad_entry->traffic_desc.peer_port_to = PORT_MAX;

        		memcpy(&outgoing_sad_entry->peer, &session->group_ip, sizeof(uip_ip6addr_t));
        		outgoing_sad_entry->traffic_desc.peer_addr_from = &session->group_ip;
        		outgoing_sad_entry->traffic_desc.peer_addr_to = &session->group_ip;
        		outgoing_sad_entry->traffic_desc.nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL;
        		/* No HTONS needed here as the maximum and miniumum unsigned ints are represented the same way */
        		/* in network as well as host byte order. */
        		outgoing_sad_entry->traffic_desc.my_port_from = 0;
        		outgoing_sad_entry->traffic_desc.my_port_to = PORT_MAX;
        		outgoing_sad_entry->traffic_desc.peer_port_from = 0;
        		outgoing_sad_entry->traffic_desc.peer_port_to = PORT_MAX;

        	  break;
          case IKE_PAYLOAD_KD:

        	  parse_kd_payload(payload_start, incoming_sad_entry, outgoing_sad_entry);
        	  break;
          case IKE_PAYLOAD_SID:
        	  /*
        	   * The client is only parsing this payload.
        	   */
        	  parse_sid_payload(payload_start, outgoing_sad_entry);

        	  break;
          case IKE_PAYLOAD_AUTH:
            IKE_MEMPRINT("auth payload", (uint8_t *)genpayloadhdr, uip_ntohs(genpayloadhdr->len));
            auth_payload = (ike_payload_auth_t *)((uint8_t *)genpayloadhdr + sizeof(ike_payload_generic_hdr_t));
            IKE_PRINTF("auth_payload: %p\n", auth_payload);
            switch(auth_payload->auth_type) {
            case IKE_AUTH_ECDSA_256_SHA_256:
              break;
            case IKE_AUTH_SHARED_KEY_MIC:
              break;
            default:
              IKE_PRINTF(IPSEC_IKE_ERROR "Peer using authentication type %u instead of certificate/pre-shared key authentication\n", auth_payload->auth_type);
              fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
              goto fail;
            }
            break;

            case IKE_PAYLOAD_CERT:
                  IKE_PRINTF(IPSEC_IKE "Certificate payload \n");

            #if IKE_IPSEC_INFO
            #if IPSEC_TIME_STATS
                  exec_time = RTIMER_NOW() - exec_time;
                  total_time += exec_time;
                  exec_time = RTIMER_NOW();
            #endif
            #endif
                  /* Process the certificate payload */
                  ike_payload_cert_t *cert_payload = (ike_payload_cert_t *)payload_start;

                  IKE_PRINTF("CERTIFICATE ENCODING %u\n", cert_payload->cert_encoding);

                  if(cert_payload->cert_encoding == CERT_X509_SIGNATURE) {

                    uint16_t cert_datalen = uip_ntohs(genpayloadhdr->len)
                      - sizeof(ike_payload_cert_t) - sizeof(ike_payload_generic_hdr_t);

                    IKE_PRINTF("CERTIFICATE PAYLOAD len %u \n", cert_datalen);

                    /* parse and verify the certificate and check if it is signed by our CA */
                    unsigned char *peer_cert = (unsigned char *)payload_start + sizeof(ike_payload_cert_t);

                    uint16_t cert_test = cert_parse(peer_cert, cert_datalen, &peer_cert_ctx);

                    if(cert_test) {
                      IKE_PRINTF("CERTIFICATE PARSE SUCCESSFUL\n");

                      uint8_t *public_key_signer = get_ca_public_key();

                      /* Verify that the certificate is signed by our CA*/
                      if(cert_verfiy_signature(&peer_cert_ctx, public_key_signer)) {
                        IKE_PRINTF("Peer has a certificate signed by our CA\n");
                        /* TODO perform other tests on the certificate like expiration */
                      } else {
                        IKE_PRINTF("Could not verify peer certificate\n");
                      }
                    } else {
                      IKE_PRINTF("CERTIFICATE PARSE FAILURE\n");
                    }
                  } else {
                    IKE_PRINTF("WRONG ENCODING OF CERTIFICATE We Only support X.509 Signature encoding\n");
                  }
#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
      exec_time = RTIMER_NOW() - exec_time;
      total_time += exec_time;
      printf("CERT payload parsing and verification, %lu us\n", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
      exec_time = RTIMER_NOW();
#endif
#endif
      break;
    case IKE_PAYLOAD_CERTREQ:
      IKE_PRINTF(IPSEC_IKE "Certificate request  payload \n");

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
      exec_time = RTIMER_NOW() - exec_time;
      total_time += exec_time;
      exec_time = RTIMER_NOW();
#endif
#endif
      ike_payload_cert_t *cert_req_payload = (ike_payload_cert_t *)payload_start;

      IKE_PRINTF("CERTIFICATE REQUEST ENCODING %u\n", cert_req_payload->cert_encoding);

      if(cert_req_payload->cert_encoding == CERT_X509_SIGNATURE) {

        uint16_t cert_req_datalen = uip_ntohs(genpayloadhdr->len)
          - sizeof(ike_payload_cert_t) - sizeof(ike_payload_generic_hdr_t);

        IKE_PRINTF("CERTIFICATE REQUEST PAYLOAD len %u \n", cert_req_datalen);

        uint8_t *peer_cert_authority = (uint8_t *)payload_start + sizeof(ike_payload_cert_t);

        /* Check if we have a certificate from this certificate authority if so we can send our certificate to */
        if(cert_req_datalen == SHA1_CERT_HASH_LEN) {
          IKE_PRINTF("RECIEVED CERTIFICATE REQUEST is the correct length\n");

          /* Create the 20 octet SHA-1 hash of the DER encoded public key
           * information element */
          uint8_t cert_authority_sha[SHA1_CERT_HASH_LEN];

          gen_cert_authority(cert_authority_sha);

          IKE_PRINTF("SHA1 hash of CA public_key info element\n");
          IKE_HEXDUMP(cert_authority_sha, SHA1_CERT_HASH_LEN);

          if(memcmp(cert_authority_sha, peer_cert_authority, SHA1_CERT_HASH_LEN) == 0) {
            session->ephemeral_info->cert_req_recieved = 1;
            IKE_PRINTF("The peer's certificate authority matches ours\n");
          } else {
            IKE_PRINTF("CERT ERROR we do not have a certificate issued by this certificate authority\n");
          }
        } else {
          IKE_PRINTF("We do not support more than 1 certificate authority\n");
        }
      } else {
        IKE_PRINTF("WRONG CERTIFICATE ENCODING: We only support X.509 Signature encoding\n");
      }
#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
      exec_time = RTIMER_NOW() - exec_time;
      total_time += exec_time;
      printf("CERTREQ payload parsing and verification, %lu us\n", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
      exec_time = RTIMER_NOW();
#endif
#endif
      break;
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
        IKE_PRINTF(IPSEC_IKE_ERROR "Encountered an unknown critical payload\n");
        fail_notify_type = IKE_PAYLOAD_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD;
        goto fail;
      } else {
        IKE_PRINTF(IPSEC_IKE "Ignoring unknown non-critical payload of type %u\n", payload_type);
        /* Info: Ignored unknown payload */
      	  	  }
        }
     ptr = (uint8_t *)genpayloadhdr + uip_ntohs(genpayloadhdr->len);
     payload_type = genpayloadhdr->next_payload;
 } /* End payload loop */

   if(payload_type != IKE_PAYLOAD_NO_NEXT ){
        IKE_PRINTF(IPSEC_IKE_ERROR "Could not parse peer message.\n");
        fail_notify_type = IKE_PAYLOAD_NOTIFY_INVALID_SYNTAX;
        goto fail;
      }

      /**
       * Assert that transport mode was accepted
       */
      if(transport_mode_not_accepted) {
        IKE_PRINTF(IPSEC_IKE_ERROR "Peer did not accept transport mode child SA\n");
        fail_notify_type = IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN;
        goto fail;
      }
      /**
       * Assert AUTH data
       */
      if(id_data == NULL || auth_payload == NULL) {
        IKE_PRINTF(IPSEC_IKE_ERROR "IDr or AUTH payload is missing\n");
        fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
        goto fail;
      }
      {
    #if IKE_IPSEC_INFO
    #if IPSEC_TIME_STATS
        exec_time = RTIMER_NOW() - exec_time;
        total_time += exec_time;
        exec_time = RTIMER_NOW();
    #endif
    #endif

        uint8_t responder_signed_octets[session->ephemeral_info->peer_first_msg_len + session->ephemeral_info->peernonce_len + SA_PRF_OUTPUT_LEN(session)];

    #if IKE_IPSEC_INFO
    #if IPSEC_TIME_STATS
        exec_time = RTIMER_NOW() - exec_time;
        total_time += exec_time;
    #endif
    #endif
        /* IKE_PRINTF("Responder_signed_octets len %u, first message_len %u, peer_nonce_len %u, PRF_output_len %u\n",sizeof(responder_signed_octets), session->ephemeral_info->peer_first_msg_len,session->ephemeral_info->peernonce_len, SA_PRF_OUTPUT_LEN(session)); */
        uint16_t responder_signed_octets_len = ike_statem_get_authdata(session, 0 /* Peer's signed octets */, responder_signed_octets, id_data, id_datalen);
    #if IKE_IPSEC_INFO
    #if IPSEC_TIME_STATS
        exec_time = RTIMER_NOW();
    #endif
    #endif
        /* TODO: USE CERT to verify that the payload is signed by the sender */
        /* */
        if((auth_payload->auth_type == IKE_AUTH_ECDSA_256_SHA_256)) {
          if(peer_cert_ctx.TBSCertificate != NULL) {
            IKE_PRINTF("Authenticating certificate signature\n");

            IKE_PRINTF("Peer's signed octets\n");
            IKE_HEXDUMP(responder_signed_octets, responder_signed_octets_len);

            IKE_PRINTF("PEER Certificate context exists\n");

            IKE_PRINTF("PEER's public key\n");
            IKE_HEXDUMP(peer_cert_ctx.subject_pub_key, peer_cert_ctx.subject_pub_key_len);

            if(peer_cert_ctx.subject_pub_key_len != 2 * (NUMWORDS * WORD_LEN_BYTES)) {
              IKE_PRINTF("PEER's public key is not the correct length we support ECDSA_256 %u\n", peer_cert_ctx.subject_pub_key_len);
              fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
              goto fail;
            }
            uint16_t auth_len = 2 * (NUMWORDS * WORD_LEN_BYTES);

            /* Verify signature */
            if(auth_ecdsa(&peer_cert_ctx, 0, responder_signed_octets, responder_signed_octets_len,
                          (uint8_t *)auth_payload + sizeof(ike_payload_auth_t), &auth_len)) {
              IKE_PRINTF(IPSEC_IKE "Peer successfully authenticated\n");
            } else {
              IKE_PRINTF(IPSEC_IKE_ERROR "AUTH data mismatch Certificate signature\n");
              fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
              goto fail;
            }
          } else {
            IKE_PRINTF(IPSEC_IKE_ERROR "We received no certificate from our peer\n");
            fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
            goto fail;
          }
    #if IKE_IPSEC_INFO
    #if IPSEC_TIME_STATS
          exec_time = RTIMER_NOW() - exec_time;
          total_time += exec_time;
          printf("Authentication of peer with certificate, %lu us\n", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
          exec_time = RTIMER_NOW();
    #endif
    #endif
        } else {
          /* Peer is not using certificate authentication*/
          uint8_t mac[SA_PRF_OUTPUT_LEN(session)];

          /**
           * AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
           */
          prf_data_t auth_data = {
            .out = mac,
            .data = responder_signed_octets,
            .datalen = responder_signed_octets_len
          };
          auth_psk(session->sa.prf, &auth_data);

          if(memcmp(mac, ((uint8_t *)auth_payload) + sizeof(ike_payload_auth_t), sizeof(mac))) {
            IKE_PRINTF(IPSEC_IKE_ERROR "AUTH data mismatch\n");
            fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
            goto fail;
          }
          IKE_PRINTF(IPSEC_IKE "Peer successfully authenticated\n");
    #if IKE_IPSEC_INFO
    #if IPSEC_TIME_STATS
          exec_time = RTIMER_NOW() - exec_time;
          total_time += exec_time;
          printf("Authentication of peer with shared-secret, %lu us\n", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
          exec_time = RTIMER_NOW();
    #endif
    #endif
        }
      }

      printf("PARSED THE GSA_AUTH SUCCESSFULLY!\n");
      return STATE_SUCCESS;

      fail:
      #if WITH_IPSEC
        sad_remove_outgoing_entry(outgoing_sad_entry);
        sad_remove_incoming_entry(incoming_sad_entry);
      #endif

      memory_fail:
        ike_statem_send_single_notify(session, fail_notify_type);
      #if IKE_IPSEC_INFO
        printf("Parsing of GSA_AUTH FAILURE\n");
      #endif
        return STATE_FAILURE;
}
/*---------------------------------------------------------------------------------------------------------------------*/
/*
 * Function to send GSA_REKEY message by GC/KS.
 */
transition_return_t
gike_statem_send_rekey_msg(gsak_entry_t *gsak_entry, payload_arg_t *payload_arg, uint8_t *pairwise_secret_key){

  printf("====== Generating GSA_REKEY message ====== \n");
#if IPSEC_TIME_STATS
  rtimer_clock_t exec_time;
  rtimer_clock_t total_time;
  exec_time = RTIMER_NOW();
  total_time = 0;
#endif
  	/*
   	 * Set rekey timer after sending this message.
   	 */
   	ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)(payload_arg->start - sizeof(ike_payload_ike_hdr_t));

	/*
	 * Increase the msg id since server sends new rekey_msg
	 */
	if(gsak_entry->rekey_case != 2) gsak_entry->msg_id++;

	if(gsak_entry->rekey_case == 0 || gsak_entry->rekey_case == 1){
		/*
		 * The key index is changing in every new rekey message. Therefore when
		 * it comes to GSA_AUTH resp from server to client, the server will sent
		 * the same keys as from the previous rekey message that was sent.
		 * This serves the purpose of updating all the group members with new keys
		 * before providing the keys to a new member.
		 */
		gsak_entry->key_index++;
	}

	if(gsak_entry->key_index >= 5){	//we only have a matrix of 5 keys, ie 0-4 index.
		gsak_entry->key_index = 0;
	}

	sad_entry_t *outgoing_sad_entry;
	outgoing_sad_entry = find_sad_outgoing_entry(&gsak_entry->group_id);

	/*
	 * Write Encryption Payload -
	 * 1.  Generate the IV
	 */
	 /* Write a template of the SK payload for later encryption */
	ike_payload_generic_hdr_t *sk_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
	group_ike_rekey_statem_prepare_sk(payload_arg, gsak_entry);

	uint8_t n;
	n = find_group_tek_gsa(gsak_entry->group_id);
	if(n == 0){
		IKE_PRINTF(IPSEC_IKE "Unexpected error ocurred while trying to find the group TEK GSA. \n");
	}else{
		uint8_t member_index = n-1;

		/*
		 * Write KEK GSA payload
		*/
		if(gsak_entry->rekey_case == 1 || gsak_entry->rekey_case == 2){
			write_gsak_payload(payload_arg, gpad_table[member_index].kek_spi, gpad_table[member_index].kek, GSAK_LIFETIME, gsak_entry);
		}

		/*
		 * Write TEK GSA payload
		 */
		if(gsak_entry->rekey_case != 2){
			write_gsat_payload(payload_arg, NULL, outgoing_sad_entry, NULL,gpad_table[member_index].tek);
		}

		/*
		 * Write KEK KD payload
		*/
		if(gsak_entry->rekey_case == 1 || gsak_entry->rekey_case == 2){
			write_kd_payload(payload_arg, NULL, outgoing_sad_entry ,gpad_table[member_index].kek_spi,gpad_table[member_index], KEK_KD, gsak_entry);
		}

		/*
		 * Write TEK KD payload
		*/
		if(gsak_entry->rekey_case != 2){
			write_kd_payload(payload_arg, NULL, outgoing_sad_entry ,NULL,gpad_table[member_index], TEK_KD, gsak_entry);
			populate_incoming_sad_entries(outgoing_sad_entry);
		}
	}

	/* Write AUTH Payload */
	if(gsak_entry->rekey_case == 2){
		/*
  		 * Inserting message ID for integrity check
   		*/

		/*
  		 * Before calculating the ICV value we need to set the final length
   		 * of the IKE message and the SK payload
   		*/
  		SET_NO_NEXT_PAYLOAD(payload_arg);
		group_ike_rekey_statem_finalize_sk(payload_arg, gsak_entry, sk_genpayloadhdr, payload_arg->start - (((uint8_t *)sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t)), pairwise_secret_key);
	} else {
#if SOURCE_AUTH
		// HDR, PAYLOAD, SIGNATURE
		IKE_PRINTF("=========== WRITING AUTH PAYLOAD =========== \n");

		// AUTH Header
		ike_payload_generic_hdr_t *auth_genpayloadhdr;
		SET_GENPAYLOADHDR(auth_genpayloadhdr, payload_arg, IKE_PAYLOAD_AUTH);

		// AUTH Payload
		ike_payload_auth_t *auth_payload = (ike_payload_auth_t *)payload_arg->start;
		auth_payload->auth_type = IKE_AUTH_ECDSA_256_SHA_256;
		payload_arg->start += sizeof(ike_payload_auth_t);
		uint8_t *signed_octets = (uint8_t *)sk_genpayloadhdr + sizeof(ike_payload_generic_hdr_t) + sa_encr_ivlen[gsak_entry->encr];
		uint16_t signed_octets_len = (uint8_t *)auth_payload + sizeof(ike_payload_auth_t) - signed_octets + sizeof(ike_payload_ike_hdr_t);
        	uint16_t auth_len  = 0;

        	// Estimating GSA_REKEY length
       		uint16_t data_len = payload_arg->start - ((uint8_t *)sk_genpayloadhdr + sizeof(ike_payload_generic_hdr_t)) + 2 * (NUMWORDS * WORD_LEN_BYTES);
        	uint8_t pad_field_len = 1;
    		uint8_t blocklen = 4; /* 32 bit alignment */
    		uint8_t pad = blocklen - (data_len + pad_field_len) % 4;
    		uint16_t sk_len = sizeof(ike_payload_generic_hdr_t) + data_len + pad + pad_field_len + sa_encr_icvlen[gsak_entry->encr];
#ifdef GIKE_INTEG
		sk_len += sa_integ_icvlength[gsak_entry->integ];
#endif
    		ike_hdr->len = uip_htonl(((uint8_t *)sk_genpayloadhdr) + sk_len - msg_buf);
		IKE_PRINTF("Estimated GSA_REKEY message length %lu %lu %lu\n", ike_hdr->len, data_len, sk_len);

		// Copying IKE Header as the data to be included and signed in the signature generation
		memcpy(payload_arg->start, ike_hdr, sizeof(ike_payload_ike_hdr_t));
		data_len = (uint8_t *)auth_payload + sizeof(ike_payload_auth_t) - signed_octets;
		IKE_PRINTF("IKE Header %u\n", sizeof(ike_payload_ike_hdr_t));
		IKE_HEXDUMP(ike_hdr, sizeof(ike_payload_ike_hdr_t));
		IKE_PRINTF("Data before signed and cleaned %u\n", signed_octets_len);
		IKE_HEXDUMP(signed_octets, signed_octets_len);

		// Set AUTH data length in AUTH header
		auth_genpayloadhdr->len = uip_htons(sizeof(ike_payload_generic_hdr_t) + sizeof(ike_payload_auth_t) + (2 * (NUMWORDS * WORD_LEN_BYTES)));

  		/*
  		 * Before calculating the ICV value we need to set the final length
   		 * of the IKE message and the SK payload
   		*/
  		SET_NO_NEXT_PAYLOAD(payload_arg);
		IKE_PRINTF("Data before signed after cleaned %u\n", signed_octets_len);
		IKE_HEXDUMP(signed_octets, signed_octets_len);

		auth_ecdsa(NULL, 1, signed_octets, signed_octets_len, payload_arg->start, &auth_len);
		IKE_PRINTF("Data after signed %u\n", (uint8_t *)(payload_arg->start - signed_octets) + auth_len);	
		IKE_HEXDUMP(signed_octets, (uint8_t *)(payload_arg->start - signed_octets) + auth_len);

		payload_arg->start += auth_len;
#endif
		
		// Encripting the message
		group_ike_rekey_statem_finalize_sk(payload_arg, gsak_entry, sk_genpayloadhdr, payload_arg->start - (((uint8_t *)sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t)), NULL);
	}

	// Set Rekey Case to 0
	if(gsak_entry->rekey_case != 2) gsak_entry->rekey_case = 0;

	IKE_PRINTF("GSAK entry for rekeying timer is %p \n", gsak_entry);
	SET_REKEY_TIMER(gsak_entry);

	IKE_PRINTF("SEND THE FOLLOWING MESSAGE of LENGTH %u\n", uip_ntohl(((ike_payload_ike_hdr_t *)msg_buf)->len));	
	IKE_HEXDUMP(msg_buf, uip_ntohl(((ike_payload_ike_hdr_t *)msg_buf)->len));
	printf("======= End of GSA_REKEY message =======\n");
	
	return uip_ntohl(((ike_payload_ike_hdr_t *)msg_buf)->len);
}
/*---------------------------------------------------------------------------------------------------------------------*/
void parse_rekey_msg(uint8_t *payload_start, gsak_entry_t *gsak_entry){

  printf("====== Parsing GSA_REKEY message ====== \n");
#if IPSEC_TIME_STATS
  rtimer_clock_t exec_time;
  rtimer_clock_t total_time;
  exec_time = RTIMER_NOW();
  total_time = 0;
#endif
  /*
   * Initialization
   * */
  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)msg_buf;
  sad_entry_t *outgoing_sad_entry;
  uint32_t msg_id = ike_hdr->message_id;

  notify_msg_type_t fail_notify_type = 0;
  uint8_t *ptr = msg_buf + sizeof(ike_payload_ike_hdr_t);
  uint8_t *end = msg_buf + uip_datalen();
  ike_payload_type_t payload_type = ike_hdr->next_payload;
  outgoing_sad_entry = find_sad_outgoing_entry(&gsak_entry->group_id);
  uint8_t *server_signed_octets = msg_buf + sizeof(ike_payload_ike_hdr_t) + sizeof(ike_payload_generic_hdr_t);
  uint16_t server_signed_octets_len;
  sa_prf_transform_type_t prf_algorithm;
  ike_payload_auth_t *auth_payload;
  uint8_t auth_out_len = sa_prf_output_len[IKE_PRF_DEFAULT];
  uint8_t mac[auth_out_len];
  uint16_t auth_len = 2 * (NUMWORDS * WORD_LEN_BYTES);
  uint8_t auth_temp[auth_len];
  uint8_t auth_type;

#if SOURCE_AUTH
  /* Certificate handling  */
  struct dtls_certificate_context_t server_cert_ctx;
  load_certificate(&server_cert_ctx);
#endif

  while(ptr < end) {  /* Payload loop */
  const ike_payload_generic_hdr_t *genpayloadhdr = (const ike_payload_generic_hdr_t *)ptr;
  const uint8_t *payload_start = (uint8_t *)genpayloadhdr + sizeof(ike_payload_generic_hdr_t);

          IKE_PRINTF("Next payload is %u, %u bytes remaining\n", payload_type, uip_datalen() - (ptr - msg_buf));
          switch(payload_type) {
          case IKE_PAYLOAD_SK_BR_NONLEAVE:
        	  printf("end = %u \n", end);
        	  if((end -= group_ike_rekey_statem_unpack_sk(gsak_entry, (ike_payload_generic_hdr_t *)genpayloadhdr, 0)) == 0) {
        	         printf(IPSEC_IKE_ERROR "[Rekey message - Periodic/Join] SK payload: Integrity check of peer's message failed\n");
        	         return;
        	       } else {
        	         printf("[Rekey message - Periodic/Join] SK payload: Integrity check successful\n");
        	       }
        	  break;
	  case IKE_PAYLOAD_SK_BR_LEAVE1:
        	  printf("end = %u \n", end);
        	  if((end -= group_ike_rekey_statem_unpack_sk(gsak_entry, (ike_payload_generic_hdr_t *)genpayloadhdr, 1)) == 0) {
        	         printf(IPSEC_IKE_ERROR "[Rekey message - Leave1] SK payload: Integrity check of peer's message failed\n");
        	         return;
        	       } else {
        	         printf("[Rekey message - Leave1] SK payload: Integrity check successful\n");
        	       }
        	  break;
	case IKE_PAYLOAD_SK_BR_LEAVE2:
        	  printf("end = %u \n", end);
        	  if((end -= group_ike_rekey_statem_unpack_sk(gsak_entry, (ike_payload_generic_hdr_t *)genpayloadhdr, 0)) == 0) {
        	         printf(IPSEC_IKE_ERROR "[Rekey message - Leave2] SK payload: Integrity check of peer's message failed\n");
        	         return;
        	       } else {
        	         printf("[Rekey message - Leave2] SK payload: Integrity check successful\n");
        	       }
        	  break;
          case IKE_PAYLOAD_N:
        	  break;
          case IKE_PAYLOAD_IDg:
        	  break;
          case IKE_PAYLOAD_GSAK:
        	  parse_gsak_payload(payload_start,NULL);
        	  break;
          case IKE_PAYLOAD_GSAT:
        	  parse_gsat_payload(payload_start,NULL, outgoing_sad_entry);
        	  break;
          case IKE_PAYLOAD_KD:
        	  parse_kd_payload(payload_start, NULL, outgoing_sad_entry);//only the incoming sad entry with peer the server.
        	  break;
#if SOURCE_AUTH
          case IKE_PAYLOAD_AUTH:
        	IKE_PRINTF(" =========== PARSING AUTH PAYLOAD =========== \n");
		// AUTH Payload
        	auth_payload = (ike_payload_auth_t *)payload_start;
        	auth_type = *((uint8_t *)payload_start);
		payload_start += sizeof(ike_payload_auth_t);

		// Check AUTH Type
		switch(auth_type) {
            		case IKE_AUTH_ECDSA_256_SHA_256:
              			break;
            		default:
      				if(auth_payload == NULL) {
        				IKE_PRINTF(IPSEC_IKE_ERROR "AUTH payload is missing\n");
        				fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
      			  	}
              		  	IKE_PRINTF(IPSEC_IKE_ERROR "Peer using authentication type %u instead of certificate authentication\n", auth_type);
              		  	fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
            	}
		
		// Generating the data to be signed
		memcpy(&auth_temp, payload_start, auth_len * sizeof(uint8_t));
		IKE_PRINTF("Received AUTH Data: %p %u\n", auth_temp, auth_len);
		IKE_HEXDUMP(auth_temp, auth_len);

  		server_signed_octets_len = (uint8_t *)auth_payload + sizeof(ike_payload_auth_t) - server_signed_octets + sizeof(ike_payload_ike_hdr_t);

		// Adding IKE header to the data to be signed
		memcpy(server_signed_octets + ((uint8_t *)auth_payload + sizeof(ike_payload_auth_t) - server_signed_octets), ike_hdr, sizeof(ike_payload_ike_hdr_t));
		IKE_PRINTF("Received IKE Header: %p\n", sizeof(ike_payload_ike_hdr_t));
		IKE_HEXDUMP(ike_hdr, sizeof(ike_payload_ike_hdr_t));
		IKE_PRINTF("Data to be signed: %p %u\n", server_signed_octets, server_signed_octets_len);
		IKE_HEXDUMP(server_signed_octets, server_signed_octets_len);
	
		// Verifying the signature
		if(auth_type  == IKE_AUTH_ECDSA_256_SHA_256) {
          		if(server_cert_ctx.TBSCertificate != NULL) {
            			IKE_PRINTF("Authenticating certificate signature\n");
            			IKE_PRINTF("GCK Certificate context exists\n");
				IKE_PRINTF("GCK's public key\n");
            			IKE_HEXDUMP(server_cert_ctx.subject_pub_key, server_cert_ctx.subject_pub_key_len);

				// Check GCK certificate
				if(server_cert_ctx.subject_pub_key_len != 2 * (NUMWORDS * WORD_LEN_BYTES)) {
              				IKE_PRINTF("GCK's public key is not the correct length we support ECDSA_256 %u\n", server_cert_ctx.subject_pub_key_len);
              				fail_notify_type = IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED;
            			}
			
        	        	if(auth_ecdsa(&server_cert_ctx, 0, server_signed_octets, server_signed_octets_len, auth_temp, &auth_len)){
        	        		IKE_PRINTF(IPSEC_IKE "GCK is successfully authenticated\n");
        	        	} else {
        	          		IKE_PRINTF(IPSEC_IKE_ERROR "AUTH data mismatch\n");
        	        	}
			}
		}
        	break;
#endif
          default:
        	  break;
          }


          ptr = (uint8_t *)genpayloadhdr + uip_ntohs(genpayloadhdr->len);
          payload_type = genpayloadhdr->next_payload;
  }
  populate_incoming_sad_entries(outgoing_sad_entry);
  printf("======= End of parsing GSA_REKEY message =======\n");
  return;
}
/*---------------------------------------------------------------------------*/
uint8_t
group_ike_rekey_statem_unpack_sk(gsak_entry_t *gsak_entry, ike_payload_generic_hdr_t *sk_genpayloadhdr, uint8_t isUsingPairwiseKey)
{
	uint8_t icv_length = sa_integ_icvlength[gsak_entry->integ];
	uint16_t integ_datalen = uip_ntohl(((ike_payload_ike_hdr_t *)msg_buf)->len) - icv_length;

	uint8_t trailing_bytes = 0;

	/* Find the ICV length if CCM is used */
	uint8_t encr_icv_length = sa_encr_icvlen[gsak_entry->encr];


	uint8_t expected_icv[((encr_icv_length) > 0 ? encr_icv_length : icv_length)];


	/* Integrity */
	if(gsak_entry->integ) {

		/* Length of data to be integrity protected: */
		/* IKE header + (anything in between) + SK header + IV + data + padding + padding length field */

		integ_data_t integ_data = {
			.type = gsak_entry->integ,
			.data = msg_buf,          /* The start of the data */
			.datalen = integ_datalen, /* Data to be integrity protected */
			.out = expected_icv,       /* Where the output will be written. IPSEC_ICVLEN bytes will be written. */
			.keymat = gsak_entry->integ_key
		};


		integ(&integ_data);                      /* This will write Encrypted Payloads, padding and pad length */

		if(memcmp(expected_icv, msg_buf + integ_datalen, icv_length) != 0) {
			IKE_PRINTF("Expected ICV does not match message\n");
			return 0;
		}

		trailing_bytes += icv_length;
	}

  	/* Confidentiality / Combined mode */
  	uint16_t datalen = uip_ntohs(sk_genpayloadhdr->len) - icv_length - sizeof(ike_payload_generic_hdr_t);


  	encr_data_t encr_data = {
    		.type = gsak_entry->encr,
    		.keylen = gsak_entry->key_len,
    		.encr_data = ((uint8_t *)sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t),
    		/* From the beginning of the IV to the pad length field */
    		.encr_datalen = datalen,
    		.ip_next_hdr = NULL,
		//.keymat = gsak_entry->encr_key
  	};

	if (isUsingPairwiseKey == 1) {
		encr_data.keymat = &gpad_table[1].pairwise_secret_key;
	} else {
		encr_data.keymat = gsak_entry->encr_key;	
	}

   	if(encr_icv_length) {
    		encr_data.integ_data = msg_buf;
    		encr_data.icv = expected_icv;

	}

  	espsk_unpack(&encr_data); /* Encrypt / combined mode */

	IKE_PRINTF("Encrypted Data: %p\n", encr_data.encr_data);
	IKE_HEXDUMP(encr_data.encr_data, encr_data.encr_datalen);
	IKE_PRINTF("Encryption Key: %p\n", encr_data.keymat);
	IKE_HEXDUMP(encr_data.keymat, gsak_entry->key_len);

  	if(encr_icv_length) {
    		if(memcmp(expected_icv, msg_buf + integ_datalen - encr_icv_length, encr_icv_length) != 0) {
      			IKE_PRINTF("Expected ICV does not match message after encryption\n");
      			return 0;
    		}
		if (isUsingPairwiseKey == 1) {
			if(gsak_entry->msg_id != msg_buf[sizeof(ike_payload_ike_hdr_t) + sizeof(ike_payload_generic_hdr_t) + encr_icv_length]) {
      				IKE_PRINTF("Expected message ID after encryption does not match message ID\n");
      				return 0;
    			}
		}
    		/* Move the data over the IV as the former's length might not be a multiple of four */
  	}
  	uint8_t *iv_start = (uint8_t *)sk_genpayloadhdr + sizeof(ike_payload_generic_hdr_t);

	if (isUsingPairwiseKey == 1) {
		memmove(iv_start, iv_start + sa_encr_ivlen[gsak_entry->encr] + 1, datalen-1);
	} else {
	  	memmove(iv_start, iv_start + sa_encr_ivlen[gsak_entry->encr], datalen);
	}
  	sk_genpayloadhdr->len = uip_htons(sizeof(ike_payload_generic_hdr_t));

  	/* Adjust trailing bytes */
  	/*                IV length                       + padding         + pad length field */
  	trailing_bytes += sa_encr_ivlen[gsak_entry->encr] + encr_data.padlen + 1;

  	trailing_bytes += encr_icv_length;

  	return trailing_bytes;
}
/*---------------------------------------------------------------------------*/
void
group_ike_rekey_statem_finalize_sk(payload_arg_t *payload_arg, gsak_entry_t *gsak_entry, ike_payload_generic_hdr_t *sk_genpayloadhdr, uint16_t data_len, uint8_t *pairwise_secret_key)
{
	IKE_PRINTF("msg_buf: %p\n", msg_buf);
	IKE_HEXDUMP(msg_buf, data_len);

	uint8_t encr_icvlen = sa_encr_icvlen[gsak_entry->encr];

	uint16_t sk_len = 0;
	uint32_t msg_len = 0;
	if(encr_icvlen) {
		/* have to set the size of the sk payload before calling the espsk_pack because
		 * it is used to calculate the ICV in authenticated encryption algorithms */
		uint8_t pad_field_len = 1;
		uint8_t blocklen = 4; /* 32 bit alignment */
		uint8_t pad = blocklen - (data_len + pad_field_len) % 4;

		sk_len = sizeof(ike_payload_generic_hdr_t) + data_len + pad + pad_field_len + encr_icvlen;

		sk_genpayloadhdr->len = uip_htons(sk_len);
		payload_arg->start = ((uint8_t *)sk_genpayloadhdr) + sk_len;

		msg_len = payload_arg->start - msg_buf;
		IKE_PRINTF("msg_len: %u\n", msg_len);

		((ike_payload_ike_hdr_t *)msg_buf)->len = uip_htonl(msg_len);
		IKE_PRINTF("sk_genpayloadhdr->len: %u data_len: %u\n", uip_ntohs(sk_genpayloadhdr->len), data_len);
	}

	/* Confidentiality / Combined mode */
		encr_data_t encr_data = {
			.type = gsak_entry->encr,
			.keylen = gsak_entry->key_len,
			.integ_data = msg_buf,                    /* Beginning of the ESP header (ESP) or the IKEv2 header (SK) */
			.encr_data = (uint8_t *)sk_genpayloadhdr + sizeof(ike_payload_generic_hdr_t),
			.encr_datalen = data_len,                 /* From the beginning of the IV to the IP next header field (ESP) or the padding field (SK). */
			.ip_next_hdr = NULL,
			//.keymat = gsak_entry->encr_key
		};
	if(gsak_entry->rekey_case == 2) {
		encr_data.keymat = pairwise_secret_key;
	} else {
		encr_data.keymat = gsak_entry->encr_key;
	}

	IKE_PRINTF("\n encr: %u\n", encr_data.type);
	IKE_MEMPRINT("encr_key", encr_data.keymat, encr_data.keylen);

	IKE_PRINTF("Raw Data: %p\n", encr_data.encr_data);
	IKE_HEXDUMP(encr_data.encr_data, encr_data.encr_datalen);

	espsk_pack(&encr_data); /* Encrypt / combined mode */

	IKE_PRINTF("Encrypted Data: %p\n", encr_data.encr_data);
	IKE_HEXDUMP(encr_data.encr_data, encr_data.encr_datalen);

	/* Integrity */
	if(gsak_entry->integ) {

		uint8_t icvlen = sa_integ_icvlength[gsak_entry->integ];

		/* sk_len = ike_payload_generic_hdr_t size + ICV and data + pad length + pad length field + IPSEC_ICVLEN */
		sk_len = sizeof(ike_payload_generic_hdr_t) + data_len + encr_data.padlen + 1 + icvlen + encr_icvlen;
		sk_genpayloadhdr->len = uip_htons(sk_len);
		payload_arg->start = ((uint8_t *)sk_genpayloadhdr) + sk_len;
		msg_len = payload_arg->start - msg_buf;
		// IKE_PRINTF("msg_len: %u\n", msg_len);
		((ike_payload_ike_hdr_t *)msg_buf)->len = uip_htonl(msg_len);
		IKE_PRINTF("sk_genpayloadhdr->len: %u data_len: %u\n", uip_ntohs(sk_genpayloadhdr->len), data_len);

		/* Length of data to be integrity protected: */
		/* IKE header + (anything in between) + SK header + IV + data + padding + padding length field */
		uint16_t integ_datalen = msg_len - icvlen;

		integ_data_t integ_data = {
			.type = gsak_entry->integ,
			.data = msg_buf,                        /* The start of the data */
			.datalen = integ_datalen,               /* Data to be integrity protected */
			.out = msg_buf + integ_datalen,          /* Where the output will be written. IPSEC_ICVLEN bytes will be written. */
			.keymat = gsak_entry->integ_key
		};



	IKE_MEMPRINT("integ keymat", integ_data.keymat, SA_INTEG_CURRENT_KEYMATLEN(payload_arg->session));
	integ(&integ_data);                      /* This will write Encrypted Payloads, padding and pad length */
  	}
}
/*---------------------------------------------------------------------------*/
void
group_ike_rekey_statem_prepare_sk(payload_arg_t *payload_arg, gsak_entry_t *gsak_entry){
	ike_payload_generic_hdr_t *sk_genpayloadhdr;

	switch(gsak_entry->rekey_case) {
        case 2:
		SET_GENPAYLOADHDR(sk_genpayloadhdr, payload_arg, IKE_PAYLOAD_SK_BR_LEAVE1);
		break;
	case 3:
		SET_GENPAYLOADHDR(sk_genpayloadhdr, payload_arg, IKE_PAYLOAD_SK_BR_LEAVE2);
		break;
	default:
		SET_GENPAYLOADHDR(sk_genpayloadhdr, payload_arg, IKE_PAYLOAD_SK_BR_NONLEAVE);
		break;
  	}

	/* Generate the IV */
	uint8_t n;
	for(n = 0; n < sa_encr_ivlen[gsak_entry->encr]; ++n) {
		payload_arg->start[n] = rand16();
	}
	payload_arg->start += n;

	if (gsak_entry->rekey_case == 2) {
		payload_arg->start[0] = gsak_entry->msg_id;
		payload_arg->start += sizeof(gsak_entry->msg_id);
	}
}
/*---------------------------------------------------------------------------*/
uint16_t gike_statem_get_server_authdata(gsak_entry_t *gsak_entry, uint8_t *out /*these are the signed octets*/, sad_entry_t *outgoing_sad){
	IKE_PRINTF("Getting ServerSignedOcteds. \n");
	uint8_t *ptr = out;

/*
 *  Last octet of TEK_KD: Take the last 8 bits of the TEK
 */
if(outgoing_sad->sa.integ == 0){

  uint8_t ServerRealMessage[SA_ENCR_MAX_KEYMATLEN];
  uint8_t i;

  for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++){
     ServerRealMessage[i] = outgoing_sad->sa.sk_e[i];
  }
  memcpy(ptr,&ServerRealMessage, SA_ENCR_MAX_KEYMATLEN);
  ptr +=SA_ENCR_MAX_KEYMATLEN;



}else{

  uint8_t ServerRealMessage[KEY_LENGTH];
  uint8_t i;

  for(i=0;i<KEY_LENGTH;i++){
     ServerRealMessage[i] = outgoing_sad->sa.sk_a[i];
  }
  memcpy(ptr,&ServerRealMessage, KEY_LENGTH);
  ptr += KEY_LENGTH;

}


uint8_t *id_data;
ike_id_payload_t *server_id_payload;
const char server_ipaddr[] = GCKS_HARDCODED_ADDRESS;
uint16_t id_payload_len = 0;



sa_prf_transform_type_t prf_algorithm;
/*
 * Create RestOfServerIDPayload
 * IDType | RESERVED | ServerIDData
 */
server_id_payload = (ike_id_payload_t *)id_data;
server_id_payload->id_type =IKE_ID_IPV6_ADDR;
server_id_payload->clear1 = 0U;

id_payload_len += sizeof(ike_id_payload_t);
id_data += sizeof(ike_id_payload_t);

memcpy(id_data ,(uint8_t *)server_ipaddr, sizeof(server_ipaddr));

id_payload_len += sizeof(server_ipaddr);
id_data += sizeof(server_ipaddr);

if(gsak_entry->auth_method == IKE_AUTH_SHARED_KEY_MIC){
	prf_algorithm = IKE_PRF_DEFAULT;
}

/*
 * prf(SK_pi, RestOfServerIDPayload) = MACedIDForServer
 */
prf_data_t prf_data =
{
  .out = ptr,
  .keylen = sa_prf_preferred_keymatlen[prf_algorithm], // SK_px is always of the PRF's preferred keymat length
  .data = id_data,
  .datalen = id_payload_len,
  .key = gsak_entry->auth_key
};

prf(prf_algorithm, &prf_data);
ptr += sa_prf_preferred_keymatlen[prf_algorithm];
IKE_MEMPRINT("*ServerSignedOctets", out, ptr-out);

return ptr - out;
}

/*---------------------------------------------------------------------------------------------------------------------*/
void parse_sid_payload(uint8_t *payload_start, sad_entry_t *outgoing_sad_entry){
	IKE_PRINTF("=========== PARSING SID PAYLOAD =========== \n");

	        	  	ike_sid_payload_t *sid_payload = NULL;
	        	  	sid_attributes_t *sid_attributes = NULL;
	        	  	uint8_t i = 0;
	        	  	uip_ip6addr_t multicast_group_id;
	        	  	uip_ip6addr_t member_addr;
			   	    uint8_t parsed_payload = 0;
			   	    sad_entry_t *incoming_sad_entry;

			   	     sid_payload = (ike_sid_payload_t*)payload_start;

			   	 	 sid_payload->spi = *((uint32_t*)payload_start);

	        	  	  IKE_PRINTF("SPI = %u \n", sid_payload->spi);
	        	  	  payload_start += sizeof(sid_payload->spi);
	        	  	  parsed_payload += sizeof(sid_payload->spi);

	        	  	  sid_payload->length = *((uint16_t*)payload_start);
	        	  	  IKE_PRINTF("length = %u \n", sid_payload->length);
	        	  	  payload_start += sizeof(sid_payload->length);
	        	  	  parsed_payload += sizeof(sid_payload->length);

	        	  	  sid_payload->num_of_senders = *((uint16_t*)payload_start);
	        	  	  IKE_PRINTF("length = %u \n", sid_payload->num_of_senders);
	        	  	  payload_start += sizeof(sid_payload->num_of_senders);
	        	  	  parsed_payload += sizeof(sid_payload->num_of_senders);
	        	  	  payload_start += (sizeof(ike_sid_payload_t) - parsed_payload);

	        	  	  for(i=0;i<sid_payload->num_of_senders;i++){
	      				sid_attributes = (sid_attributes_t*)payload_start;
	      				sid_attributes->sender_addr =*((uip_ip6addr_t*)payload_start) ;

	      				payload_start += sizeof(sid_attributes->sender_addr);
	      				parsed_payload += sizeof(sid_attributes->sender_addr);
	      				if(find_sad_incoming_entry(&sid_attributes->sender_addr, &sid_payload->spi) != NULL){
	      					IKE_PRINTF("There is an existing incoming sad entry for this member.");
	      				}else{
	      					uint32_t sad_time = clock_time();
	      					incoming_sad_entry = sad_create_incoming_entry(sad_time);
	      					incoming_sad_entry->spi = sid_payload->spi;
	      					memcpy(&incoming_sad_entry->peer, &sid_attributes->sender_addr, sizeof(uip_ip6addr_t));
	      					incoming_sad_entry->traffic_desc.peer_addr_from = &sid_attributes->sender_addr;
	      					incoming_sad_entry->traffic_desc.peer_addr_to = &sid_attributes->sender_addr;
	      					incoming_sad_entry->traffic_desc.nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL;
	      					        		  /* No HTONS needed here as the maximum and miniumum unsigned ints are represented the same way */
	      					        		  /* in network as well as host byte order. */
	      					incoming_sad_entry->traffic_desc.my_port_from = 0;
	      					incoming_sad_entry->traffic_desc.my_port_to = PORT_MAX;
	      					incoming_sad_entry->traffic_desc.peer_port_from = 0;
	      					incoming_sad_entry->traffic_desc.peer_port_to = PORT_MAX;
	      					IKE_PRINTF("Incoming sad is created for member: ");PRINT6ADDR(&incoming_sad_entry->peer);IKE_PRINTF("\n");

	      				}
	        	  	  }
	        	  	  populate_incoming_sad_entries(outgoing_sad_entry);
	        	  	  if(sid_payload->length==parsed_payload){
	        	  		  IKE_PRINTF("======= SID PAYLOAD WAS SUCCESSFULLY PARSED =======\n");
	        	  	  }else{
	        	  		  IKE_PRINTF("Error occurred PARSING SID PAYLOAD \n");
	        	  	  }

}
/*---------------------------------------------------------------------------------------------------------------------*/
void write_sid_payload(payload_arg_t *payload_arg, gsak_entry_t *gsak_entry,ike_statem_session_t *session, uint32_t *spi /*tek spi*/){
	/*Set Generic Header Payload */
	IKE_PRINTF("=========== WRITING SID PAYLOAD =========== \n");
	ike_payload_generic_hdr_t *sid_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
	SET_GENPAYLOADHDR(sid_genpayloadhdr, payload_arg, IKE_PAYLOAD_SID);
	ike_sid_payload_t *sid_payload = NULL;
	sid_attributes_t *sid_attributes = NULL;
	uint8_t i = 0;
	uint8_t num_of_sid_attributes = 0;
	uint16_t total_length = 0;
	uip_ip6addr_t multicast_group_id;
	uip_ip6addr_t member_addr;

	sid_payload = (ike_sid_payload_t *)payload_arg->start;
	if(spi){
	sid_payload->spi = UIP_HTONL(spi);

	IKE_PRINTF("SPI = %u \n", sid_payload->spi);
			}

	sid_payload->length = total_length;

	IKE_PRINTF("length = %u \n", sid_payload->length);

	sid_payload->num_of_senders = num_of_sid_attributes;

	IKE_PRINTF("numb_of_attributes = %u \n", sid_payload->num_of_senders);
	total_length += sizeof(ike_sid_payload_t);
	payload_arg->start += sizeof(ike_sid_payload_t);

	for(i = 0; i < NUM_OF_MEMBERS; ++i) {
		uiplib_ipaddrconv(gpad_table[i].group_id,&multicast_group_id);

		uiplib_ipaddrconv(gpad_table[i].group_member,&member_addr);
		if(memcmp((const void *)&multicast_group_id, (const void *)&gsak_entry->group_id,sizeof(uip_ip6addr_t))==0){
			if(memcmp((const void *)&member_addr, (const void *)&session->peer,sizeof(uip_ip6addr_t))!=0){
				sid_attributes = (sid_attributes_t*)payload_arg->start;
				sid_attributes->sender_addr = member_addr;
				total_length += sizeof(sid_attributes_t);
				payload_arg->start += sizeof(sid_attributes_t);
				num_of_sid_attributes++;
			}
		}

	}
sid_payload->length = total_length;
sid_payload->num_of_senders = num_of_sid_attributes;


sid_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)sid_genpayloadhdr);
printf("SID total payload length is %u \n", sid_genpayloadhdr->len);
IKE_PRINTF("=========== END OF SID PAYLOAD =========== \n");
//End of SID payload
}

/*---------------------------------------------------------------------------------------------------------------------*/
void parse_gsat_payload(uint8_t *payload_start, sad_entry_t *incoming_sad, sad_entry_t *outgoing_sad){
	 ike_payload_gsat_t *gsat_payload = NULL;
	 gsa_attributes_t *tek_attributes = NULL;
	 uint8_t i;
	 ike_payload_attribute_t *attrib = NULL;
	 uint8_t parsed_payload = 0;
	 IKE_PRINTF(" =========== PARSING TEK GSA PAYLOAD =========== \n");
	 gsat_payload = (ike_payload_gsat_t *)payload_start;

	 gsat_payload->spi = *((uint32_t*)payload_start);

	 if(incoming_sad != NULL){// we need to find which incoming entry needs to be updated.

		 incoming_sad->spi = gsat_payload->spi;
	 }
	 outgoing_sad->spi = gsat_payload->spi;



	 IKE_PRINTF("SPI = %u \n", gsat_payload->spi);
	 payload_start += sizeof(gsat_payload->spi);
	 parsed_payload += sizeof(gsat_payload->spi);

	 gsat_payload->len =*((uint16_t*)payload_start);

	 IKE_PRINTF("length = %u \n", gsat_payload->len);
	 payload_start += sizeof(gsat_payload->len);
	 parsed_payload += sizeof(gsat_payload->len);

	 gsat_payload->protocol =*((sa_ipsec_proto_type_t*)payload_start);

	 if(incoming_sad != NULL){
	 incoming_sad->sa.proto = gsat_payload->protocol;
	 }
	 outgoing_sad->sa.proto = gsat_payload->protocol;
	 IKE_PRINTF("protocol = %u \n", gsat_payload->protocol);
	 payload_start += sizeof(gsat_payload->protocol);
	 parsed_payload += sizeof(gsat_payload->protocol);

	 gsat_payload->spi_size =*((uint8_t*)payload_start);

	 IKE_PRINTF("spi_size = %d \n", gsat_payload->spi_size);
	 payload_start += sizeof(gsat_payload->spi_size);
	 parsed_payload += sizeof(gsat_payload->spi_size);

	 gsat_payload->numb_of_attributes =*((uint8_t*)payload_start);

	 IKE_PRINTF("numb_of_attributes = %d \n", gsat_payload->numb_of_attributes);
	 payload_start += sizeof(gsat_payload->numb_of_attributes);
	 parsed_payload += sizeof(gsat_payload->numb_of_attributes);
	 payload_start += sizeof(ike_payload_gsat_t)-parsed_payload;

	  for(i=1; i <= gsat_payload->numb_of_attributes; i++){

		tek_attributes = (gsa_attributes_t*)payload_start;
		tek_attributes->last_more = *((uint8_t *)payload_start);
		payload_start += sizeof(tek_attributes->last_more);
		parsed_payload += sizeof(tek_attributes->last_more);

		tek_attributes->attribute_type = *((kek_gsa_ctrl_t *)payload_start);
		payload_start += sizeof(tek_attributes->attribute_type);
		parsed_payload += sizeof(tek_attributes->attribute_type);

		tek_attributes->attribute_value = *((uint8_t *)payload_start);
		payload_start += sizeof(tek_attributes->attribute_value);
		parsed_payload += sizeof(tek_attributes->attribute_value);

		 IKE_PRINTF("last_more = %u , kek_attribute_type = %u, value=%u \n", tek_attributes->last_more,tek_attributes->attribute_type, tek_attributes->attribute_value);

		 if(tek_attributes->attribute_type == GSA_CTRL_TYPE_ENCR){

			 if(incoming_sad != NULL){
			 incoming_sad->sa.encr = tek_attributes->attribute_value;
			 }
			 outgoing_sad->sa.encr = tek_attributes->attribute_value;
			 attrib = (ike_payload_attribute_t*)payload_start;
			 attrib->af_attribute_type = *((uint16_t *)payload_start);
			 payload_start += sizeof(attrib->af_attribute_type);
			 parsed_payload += sizeof(attrib->af_attribute_type);


			 attrib->attribute_value = *((uint16_t *)payload_start); /* Divide offer->value by 8 to make it into bits */
			 payload_start += sizeof(attrib->attribute_value);
			 if(incoming_sad != NULL){
			 incoming_sad->sa.encr_keylen = uip_ntohs(attrib->attribute_value) >> 3;
			 }
			 outgoing_sad->sa.encr_keylen = uip_ntohs(attrib->attribute_value) >> 3;
			IKE_PRINTF("incoming enc_keylen = %u and outgoing enc_keylen = %u \n ", incoming_sad->sa.encr_keylen, outgoing_sad->sa.encr_keylen);
			IKE_PRINTF("The key attribute = %u with value %u \n", attrib->af_attribute_type, attrib->attribute_value);

		  }

		 if(tek_attributes->attribute_type == GSA_CTRL_TYPE_INTEG){
			 if(incoming_sad != NULL){
			 incoming_sad->sa.integ = tek_attributes->attribute_value;
			 }
			 outgoing_sad->sa.integ = tek_attributes->attribute_value;

		  }


	  }

}
/*----------------------------------------------------------------------------------------------------*/
// Remember to change the declaration in gike-functions.h
void write_gsat_payload(payload_arg_t *payload_arg, sad_entry_t *incoming_entry, sad_entry_t *outgoing_entry, uint32_t *spi,const spd_proposal_tuple_t *tek){
	/*Set Generic Header Payload */
		IKE_PRINTF("=========== WRITING TEK GSA PAYLOAD =========== \n");
		ike_payload_generic_hdr_t *gsat_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
		SET_GENPAYLOADHDR(gsat_genpayloadhdr, payload_arg, IKE_PAYLOAD_GSAT);
		ike_payload_gsat_t *gsat_payload = NULL;
		gsa_attributes_t *tek_attributes = NULL;
		ike_payload_attribute_t *attrib = NULL;
		uint8_t n = 0;
		uint8_t number_of_tek_attributes = 0;
		uint16_t total_length = 0;

		gsat_payload = (ike_payload_gsat_t *)payload_arg->start;
		if(spi!=NULL){
			gsat_payload->spi = UIP_HTONL(spi);
			IKE_PRINTF("SPI = %u \n", gsat_payload->spi);
			if(incoming_entry != NULL){
			incoming_entry->spi = UIP_HTONL(spi);
			IKE_PRINTF("incoming_entry->SPI = %u \n", incoming_entry->spi);
			}
			outgoing_entry->spi = UIP_HTONL(spi);
			IKE_PRINTF("outgoing_entry->SPI = %u \n", outgoing_entry->spi);
		}else{
			gsat_payload->spi = outgoing_entry->spi;
			IKE_PRINTF("SPI = %u \n", gsat_payload->spi);
		}
		gsat_payload->len = total_length;
		IKE_PRINTF("Length = %d \n", gsat_payload->len);
		if(spi){
				gsat_payload->spi_size = 8;

				IKE_PRINTF("SPI_size = %u \n", gsat_payload->spi_size);
		}
		if(tek[0].value == SA_PROTO_ESP){
		gsat_payload->protocol = tek[0].value;
		IKE_PRINTF("IPSEC PROTOCOL = %u \n", gsat_payload->protocol);
		}else{
			IKE_PRINTF(IPSEC_IKE "The type of protocol is not defined. \n");
		}

		gsat_payload->numb_of_attributes = number_of_tek_attributes;

		IKE_PRINTF("numb_of_attributes = %u \n", gsat_payload->numb_of_attributes);

		total_length += sizeof(ike_payload_gsak_t);
		payload_arg->start += sizeof(ike_payload_gsat_t);

		do{
						switch(tek[n].type){
						case GSA_CTRL_NEW_PROPOSAL:

							if(tek[n].value != SA_PROTO_ESP){
								IKE_PRINTF(IPSEC_IKE "Inappropriate type of GSA. \n");
							}else{
								if(incoming_entry != NULL){
								incoming_entry->sa.proto = SA_PROTO_ESP;
								IKE_PRINTF("incoming_entry->sa.proto = %u \n", incoming_entry->sa.proto);
								}
								outgoing_entry->sa.proto = SA_PROTO_ESP;
								IKE_PRINTF("outgoing_entry->sa.proto = %u \n", outgoing_entry->sa.proto);
							}
							break;

						case GSA_CTRL_TYPE_ENCR:
							tek_attributes = (gsa_attributes_t*)payload_arg->start;
							tek_attributes->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
							tek_attributes->attribute_type = tek[n].type;
							tek_attributes->attribute_value = tek[n].value;
							if(incoming_entry != NULL){
							incoming_entry->sa.encr = tek[n].value;
							IKE_PRINTF("incoming_entry->sa.encr = %u \n", incoming_entry->sa.encr);
							}
							outgoing_entry->sa.encr = tek[n].value;
							IKE_PRINTF("outgoing_entry->sa.encr = %u \n", outgoing_entry->sa.encr);
							payload_arg->start += sizeof(gsa_attributes_t);
							total_length += sizeof(gsa_attributes_t);

							number_of_tek_attributes++;
							IKE_PRINTF("last more = %d, kek_attribute_type = %d with value %d \n",tek_attributes->last_more, tek_attributes->attribute_type , tek_attributes->attribute_value);

							uint8_t j = n + 1;
							      while(tek[j].type == SA_CTRL_ATTRIBUTE_KEY_LEN) {
							        /* The only attribute defined in RFC 5996 is Key Length (p. 84) */
							        ike_payload_attribute_t *attrib = (ike_payload_attribute_t *)payload_arg->start;
							        attrib->af_attribute_type = IKE_PAYLOADFIELD_ATTRIB_VAL;
							        attrib->attribute_value = uip_htons(tek[j].value << 3); /* Multiply offer->value by 8 to make it into bits */
							        IKE_PRINTF("the attrib->af_attribute_type = %u ,the attrib->attribute_value = %u\n", attrib->af_attribute_type, attrib->attribute_value);
							        if(incoming_entry != NULL){
							        incoming_entry->sa.encr_keylen = tek[j].value;
									IKE_PRINTF("incoming_entry->sa.encr_keylen = %u \n", incoming_entry->sa.encr_keylen);
							        }
									outgoing_entry->sa.encr_keylen = tek[j].value;
									IKE_PRINTF("outgoing_entry->sa.encr_keylen = %u \n", outgoing_entry->sa.encr_keylen);
							        total_length += sizeof(ike_payload_attribute_t);
							        payload_arg->start += sizeof(ike_payload_attribute_t);
							        j++;
							        n++;
							      }

							break;
						case GSA_CTRL_TYPE_INTEG:
							tek_attributes = (gsa_attributes_t*)payload_arg->start;
							tek_attributes->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
							tek_attributes->attribute_type = tek[n].type;
							tek_attributes->attribute_value = tek[n].value;
							 if(incoming_entry != NULL){
							incoming_entry->sa.integ = tek[n].value;
							IKE_PRINTF("incoming_entry->sa.integ = %u \n", incoming_entry->sa.integ);
							 }
							outgoing_entry->sa.integ = tek[n].value;
							IKE_PRINTF("outgoing_entry->sa.integ = %u \n", outgoing_entry->sa.integ);
							payload_arg->start += sizeof(gsa_attributes_t);
							total_length += sizeof(gsa_attributes_t);
							number_of_tek_attributes++;
							IKE_PRINTF("last more = %d, kek_attribute_type = %d with value %d \n",tek_attributes->last_more, tek_attributes->attribute_type , tek_attributes->attribute_value);



							break;

						}

					}while(tek[n++].type != GSA_CTRL_END_OF_OFFER);
		gsat_payload->numb_of_attributes = number_of_tek_attributes;
		IKE_PRINTF("Numb_of_attributes = %d \n", gsat_payload->numb_of_attributes);
		gsat_payload->len = total_length;
		IKE_PRINTF("Length = %d \n", gsat_payload->len);
		gsat_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)gsat_genpayloadhdr);
		printf("TEK GSA total payload length is %u \n", gsat_genpayloadhdr->len);


}
/*---------------------------------------------------------------------------------------------------------------------*/
// Remember to change the declaration in gike-functions.h
void write_gsak_payload(payload_arg_t *payload_arg,uint32_t *spi,const spd_proposal_tuple_t *kek, uint16_t *lifetime,gsak_entry_t *gsak_entry){

	/*
	 * In this implementation only one KEK GSA is considered to be sent by the GC/KS.
	 * The function is creating a KEK GSA payload with the prerequisite that only one KEK GSA can be sent
	 * and that only  key length attribute is specified, for the encryption algorithm.
	 */

	/*Set Generic Header Payload */
	IKE_PRINTF("=========== WRITING KEK GSA PAYLOAD =========== \n");

	ike_payload_generic_hdr_t *gsak_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
	SET_GENPAYLOADHDR(gsak_genpayloadhdr, payload_arg, IKE_PAYLOAD_GSAK);
	ike_payload_gsak_t *gsak_payload = NULL;
	gsa_attributes_t *kek_attributes = NULL;
	ike_payload_attribute_t *attrib = NULL;
	uint8_t n = 0;
	uint8_t number_of_kek_attributes = 0;
	uint16_t total_length = 0;

	gsak_payload = (ike_payload_gsak_t *)payload_arg->start;



	if(spi){
		gsak_payload->spi = UIP_HTONL(spi);

		IKE_PRINTF("SPI = %u \n", gsak_payload->spi);
		}

		gsak_payload->length = total_length;

		IKE_PRINTF("length = %u \n", gsak_payload->length);

		gsak_payload->lifetime = lifetime;

		IKE_PRINTF("lifetime = %u \n", gsak_payload->lifetime);

		gsak_payload->clear = 0U;

		IKE_PRINTF("clear = %u \n", gsak_payload->clear);

	if(spi){
		gsak_payload->spi_size = 4;

		IKE_PRINTF("SPI_size = %u \n", gsak_payload->spi_size);
		}

		gsak_payload->msg_id = gsak_entry->msg_id;
		IKE_PRINTF("msg_id = %u \n", gsak_payload->msg_id);

		gsak_payload->numb_of_attributes = number_of_kek_attributes;

		IKE_PRINTF("numb_of_attributes = %u \n", gsak_payload->numb_of_attributes);

		total_length += sizeof(ike_payload_gsak_t);
		payload_arg->start += sizeof(ike_payload_gsak_t);

		do{
				switch(kek[n].type){
				case GSA_CTRL_NEW_PROPOSAL:
					if(kek[n].value != SA_PROTO_IKE){
						IKE_PRINTF(IPSEC_IKE "Inappropriate type of GSA.");
					}
					break;
				case GSA_CTRL_TYPE_MNG_ALGORITHM:
				case GSA_CTRL_TYPE_ENCR:
				case GSA_CTRL_TYPE_INTEG:
				case GSA_CTRL_TYPE_AUTH_METHOD:

					kek_attributes = (gsa_attributes_t*)payload_arg->start;
					kek_attributes->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
					kek_attributes->attribute_type = kek[n].type;
					kek_attributes->attribute_value = kek[n].value;
					payload_arg->start += sizeof(gsa_attributes_t);
					total_length += sizeof(gsa_attributes_t);
					number_of_kek_attributes++;
					IKE_PRINTF("last more = %d, kek_attribute_type = %d with value %d \n",kek_attributes->last_more, kek_attributes->attribute_type, kek_attributes->attribute_value);
					if(kek[n].type == GSA_CTRL_TYPE_MNG_ALGORITHM){
						gsak_entry->mng = kek[n].value;
						IKE_PRINTF("type = %d with gsak_entry->mng = %d \n", kek_attributes->attribute_type, gsak_entry->mng);
					}else if(kek[n].type == GSA_CTRL_TYPE_ENCR){
						gsak_entry->encr = kek[n].value;
						IKE_PRINTF("type = %d with gsak_entry->encr = %d \n", kek_attributes->attribute_type, gsak_entry->encr);
					}else if(kek[n].type == GSA_CTRL_TYPE_INTEG){
						gsak_entry->integ = kek[n].value;
						IKE_PRINTF("type = %d with gsak_entry->integ = %d \n", kek_attributes->attribute_type, gsak_entry->integ);
					}else if(kek[n].type == GSA_CTRL_TYPE_AUTH_METHOD){
						gsak_entry->auth_method = kek[n].value;
						IKE_PRINTF("type = %d with gsak_entry->auth_method = %d \n", kek_attributes->attribute_type, gsak_entry->auth_method);
					}


					uint8_t j = n + 1;
					      while(kek[j].type == SA_CTRL_ATTRIBUTE_KEY_LEN) {
					        /* The only attribute defined in RFC 5996 is Key Length (p. 84) */
					        ike_payload_attribute_t *attrib = (ike_payload_attribute_t *)payload_arg->start;
					        attrib->af_attribute_type = IKE_PAYLOADFIELD_ATTRIB_VAL;
					        attrib->attribute_value = uip_htons(kek[j].value << 3 ); /* Multiply offer->value by 8 to make it into bits */
					        IKE_PRINTF("the attrib->af_attribute_type = %u ,the attrib->attribute_value = %u\n", attrib->af_attribute_type, attrib->attribute_value);
					        gsak_entry->key_len = kek[j].value;
					        IKE_PRINTF("the attrib->af_attribute_type = %u ,gsak_entry->key_len = %u\n", attrib->af_attribute_type, gsak_entry->key_len);
					        total_length += sizeof(ike_payload_attribute_t);
					        payload_arg->start += sizeof(ike_payload_attribute_t);
					        j++;
					        n++;
					      }
					break;

				}

			}while(kek[n++].type != GSA_CTRL_END_OF_OFFER);
		gsak_payload->length = total_length;
		gsak_payload->numb_of_attributes = number_of_kek_attributes;


	gsak_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)gsak_genpayloadhdr);
	printf("KEK GSA total payload length is %u \n", gsak_genpayloadhdr->len);



}
/*---------------------------------------------------------------------------------------------------------------------*/

void parse_kd_payload(uint8_t *payload_start, sad_entry_t *incoming_entry, sad_entry_t *outgoing_entry){

	IKE_PRINTF("=========== PARSING KEY DOWNLOAD PAYLOAD ===========\n");
	ike_key_payload_t *key_download_payload;
	key_attributes_t *key_attributes;
	uint8_t parsed_payload = 0;

	key_download_payload = (ike_key_payload_t*)payload_start;

	        	  key_download_payload->spi = *((uint32_t*)payload_start);
	        	  IKE_PRINTF("SPI, kd_download->spi = %u \n", key_download_payload->spi);


	        	  payload_start += sizeof(key_download_payload->spi);
	        	  parsed_payload += sizeof(key_download_payload->spi);

	        	  key_download_payload->length =*((uint8_t*)payload_start);

	        	  IKE_PRINTF("length = %d \n", key_download_payload->length);
	        	  payload_start += sizeof(key_download_payload->length);
	        	  parsed_payload += sizeof(key_download_payload->length);

	        	  key_download_payload->num_of_keys =*((uint8_t*)payload_start);

	        	  IKE_PRINTF("num_of_keys = %d \n", key_download_payload->num_of_keys);
	        	  payload_start += sizeof(key_download_payload->num_of_keys);
	        	  parsed_payload += sizeof(key_download_payload->num_of_keys);
	        	  payload_start += sizeof(ike_key_payload_t)- parsed_payload;

	        	  uint8_t i;
	        	  int j;
	        	  for(i=0; i <= key_download_payload->num_of_keys-1; i++){

	        		  key_attributes = (key_attributes_t*)payload_start;
	        		  key_attributes->attribute_type = *((key_type_t *)payload_start);
	        		  IKE_PRINTF("attribute_type = %d \n", key_attributes->attribute_type);
	        	  	  payload_start += sizeof(key_attributes->attribute_type);

	        	  	  key_attributes->attribute_value[0] = *((uint8_t *)payload_start);
	        	  	  payload_start += sizeof(key_attributes->attribute_value);

	        	  	  if(key_attributes->attribute_type == KEK_ENCR_KEY){
	        	  		  gsak_entry_t *gsak_entry = find_gsak_entry(uip_ntohl(key_download_payload->spi));
	        	  		  if(gsak_entry == NULL){
	        	  			 printf("KEK GSA entry does not exist. \n");
	        	  			}else{
	        	  			 printf("GSAK ENTRY WITH SPI = %u IS NOW UPDATING. \n", uip_ntohl(key_download_payload->spi));
   			        	  }

	        	  		  for(j=0;j<SA_ENCR_MAX_KEYMATLEN;j++){
	        	  		  gsak_entry->encr_key[j] = key_attributes->attribute_value[j];
	        	  		  }
	        	  		IKE_PRINTF("The received KEK encr_key = ");
	        	  		  for(j=0;j<SA_ENCR_MAX_KEYMATLEN ; j++){
	        	  			IKE_PRINTF("%02x",key_attributes->attribute_value[j] );
	        	  		  }
	        	  		IKE_PRINTF("\n");

	        	  		IKE_PRINTF("The gsak_entry->encr_key = ");
	        	  			 for(j=0;j<SA_ENCR_MAX_KEYMATLEN ; j++){
	        	  				IKE_PRINTF("%02x",gsak_entry->encr_key[j] );
	        	  			    }
	        	  			IKE_PRINTF("\n");

	        	  	  }else if(key_attributes->attribute_type == KEK_INTEGRITY_KEY){
	        	  		gsak_entry_t *gsak_entry = find_gsak_entry(uip_ntohl(key_download_payload->spi));
	        	  			if(gsak_entry == NULL){
	        	  			printf("KEK GSA entry does not exist. \n");
	        	  			}else{
	        	  			printf("GSAK ENTRY WITH SPI = %u IS NOW UPDATING. \n", uip_ntohl(key_download_payload->spi));
	        	  			}
	        	  		  for(j=0;j<KEY_LENGTH;j++){
							gsak_entry->integ_key[j] = key_attributes->attribute_value[j];
						   }
	        	  		IKE_PRINTF("The received KEK integ_key = ");
	        	  		  for(j=0;j<KEY_LENGTH ; j++){
	        	  			IKE_PRINTF("%02x",key_attributes->attribute_value[j] );
	        	  		  }
	        	  		IKE_PRINTF("\n");

	        	  		IKE_PRINTF("The gsak_entry->integ_key = ");
	        	  		 for(j=0;j<KEY_LENGTH ; j++){
	        	  			IKE_PRINTF("%02x",gsak_entry->integ_key[j] );
	        	  		      }
	        	  		IKE_PRINTF("\n");
	        	  	  }else if(key_attributes->attribute_type == KEK_AUTH_KEY){
		        	  		gsak_entry_t *gsak_entry = find_gsak_entry(uip_ntohl(key_download_payload->spi));
		        	  			if(gsak_entry == NULL){
		        	  			printf("KEK GSA entry does not exist. \n");
		        	  			}else{
		        	  			printf("GSAK ENTRY WITH SPI = %u IS NOW UPDATING. \n", uip_ntohl(key_download_payload->spi));
		        	  			}
		        	  		  for(j=0;j<SA_PRF_MAX_OUTPUT_LEN;j++){
								gsak_entry->auth_key[j] = key_attributes->attribute_value[j];
							   }
		        	  		IKE_PRINTF("The received Server KEK Auth key = ");
		        	  		  for(j=0;j<SA_PRF_MAX_OUTPUT_LEN ; j++){
		        	  			IKE_PRINTF("%02x",key_attributes->attribute_value[j] );
		        	  		  }
		        	  		IKE_PRINTF("\n");

		        	  		IKE_PRINTF("The gsak_entry->auth_key = ");
		        	  		 for(j=0;j<SA_PRF_MAX_OUTPUT_LEN ; j++){
		        	  			IKE_PRINTF("%02x",gsak_entry->auth_key[j] );
		        	  		      }
		        	  		IKE_PRINTF("\n");
	        	  	  }else if(key_attributes->attribute_type == TEK_ENCR_KEY){
	        	  		IKE_PRINTF("The received TEK encr_key = ");
	        	  		  for(j=0;j<SA_ENCR_MAX_KEYMATLEN ; j++){
	        	  			IKE_PRINTF("%02x",key_attributes->attribute_value[j] );
	        	  		  }
	        	  		IKE_PRINTF("\n");
	        	  		// Find which incoming entry needs to be updated.
	        	  		if(incoming_entry != NULL){
	        	  			for(j=0;j<SA_ENCR_MAX_KEYMATLEN;j++){
	        	  				incoming_entry->sa.sk_e[j] = key_attributes->attribute_value[j];
	        	  				}
	        	  			IKE_PRINTF("The incoming_sad encr_key = ");
		        	  		  for(j=0;j<SA_ENCR_MAX_KEYMATLEN ; j++){
		        	  			IKE_PRINTF("%02x",incoming_entry->sa.sk_e[j] );
		        	  		  }
		        	  		IKE_PRINTF("\n");
	        	  		}else{
	        	  			IKE_PRINTF(IPSEC_IKE "Incoming SAD not yet populated with encr key material. \n");
	        	  		}


	        	  		// Find which outgoing entry needs to be updated with this key.
	        	  		if(outgoing_entry != NULL){
	        	  			  for(j=0;j<SA_ENCR_MAX_KEYMATLEN;j++){
	        	  			  outgoing_entry->sa.sk_e[j] = key_attributes->attribute_value[j];
	        	  			  }
	        	  			IKE_PRINTF("The outgoing_sad encr_key = ");
		        	  		  for(j=0;j<SA_ENCR_MAX_KEYMATLEN ; j++){
		        	  			IKE_PRINTF("%02x",outgoing_entry->sa.sk_e[j] );
		        	  		   }
		        	  		IKE_PRINTF("\n");
	        	  		}else{
	        	  			IKE_PRINTF(IPSEC_IKE "OUTGOING SAD ERROR OCCURED IN ENCR KD parsing. \n");
	        	  		}


	        	  	  }else if(key_attributes->attribute_type == TEK_INTEGRITY_KEY){
	        	  		IKE_PRINTF("The received TEK integ_key = ");
	        	  		  for(j=0;j<KEY_LENGTH ; j++){
	        	  			IKE_PRINTF("%02x",key_attributes->attribute_value[j] );
	        	  		  }
	        	  		IKE_PRINTF("\n");
	        	  		  //Find which incoming sad entry should be updated with this key.
		        	  		if(incoming_entry != NULL){// we need to find which incoming entry needs to be updated.
		        	  			for(j=0;j<KEY_LENGTH;j++){
		        	  				incoming_entry->sa.sk_a[j] = key_attributes->attribute_value[j];
		        	  			}
		        	  			IKE_PRINTF("The incoming_sad integ_key = ");
		  	          	  		  for(j=0;j<KEY_LENGTH ; j++){
		  	          	  		IKE_PRINTF("%02x",incoming_entry->sa.sk_a[j] );
		  	          	  		  }
		  	          	  	IKE_PRINTF("\n");

		        	  			 }else{
		        	  				IKE_PRINTF(IPSEC_IKE "Incoming SAD not yet populated with integ key material. \n");
		        	  			 }
	        	  		  //Find for which ougoing sad entry is this key
		        	  		if(outgoing_entry != NULL){// we need to find which incoming entry needs to be updated.
		        	  			  for(j=0;j<KEY_LENGTH;j++){
		        	  			  outgoing_entry->sa.sk_a[j] = key_attributes->attribute_value[j];
		        	  			  }
		        	  			IKE_PRINTF("The ougoing_sad integ_key = ");
			          	  		  for(j=0;j<KEY_LENGTH ; j++){
			          	  			IKE_PRINTF("%02x",outgoing_entry->sa.sk_a[j] );
			          	  		   }
			          	  		IKE_PRINTF("\n");
		        	  		}else{
		        	  			IKE_PRINTF(IPSEC_IKE "OUTGOING SAD ERROR OCCURED IN INTEG KD parsing. \n");
		        	  		}




	        	  	  }


	        	  }

}
/*---------------------------------------------------------------------------------------------------------------------*/
void write_kd_payload(payload_arg_t *payload_arg, sad_entry_t *incoming_entry, sad_entry_t *outgoing_entry ,uint32_t *spi,
				member_param_t member_entry, key_download_types_t *kd_type, gsak_entry_t *gsak){
	IKE_PRINTF("=========== Writing KEY DOWNLOAD PAYLOAD ===========\n");
	ike_payload_generic_hdr_t *kd_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
	SET_GENPAYLOADHDR(kd_genpayloadhdr, payload_arg, IKE_PAYLOAD_KD);

	uint8_t n = 0;
	ike_key_payload_t *key_packet;
	key_attributes_t *key_packet_attributes;
	uint16_t length = 0; /* length of the key packet with the packet header */
	uint8_t num_of_keys = 0;

/*
 * It is better to randomize the key selection in rekeying process
 */


	key_packet = (ike_key_payload_t *)payload_arg->start;

	if(spi!=NULL){
		key_packet->spi = UIP_HTONL(spi);

		IKE_PRINTF("SPI = %u \n", key_packet->spi);
		}else{
			key_packet->spi = outgoing_entry->spi;
			IKE_PRINTF("SPI = %u \n", key_packet->spi);
		}
	key_packet->length = length;

	IKE_PRINTF("length = %u \n", key_packet->length);


	key_packet->num_of_keys = num_of_keys;

	IKE_PRINTF("numb_of_keys = %u \n", key_packet->num_of_keys);

	length += sizeof(ike_key_payload_t);
	payload_arg->start += sizeof(ike_key_payload_t);


	uint8_t i;
	uint8_t j;
if(kd_type == KEK_KD){
	//k indicates the number of keys that need to be written in the kd payload
	 //in case we had more than one key of same type to be sent
		key_packet_attributes = (key_attributes_t*)payload_arg->start;
		key_packet_attributes->attribute_type = KEK_ENCR_KEY;


		uint8_t (*pointer)[MAX_KEYS][SA_ENCR_MAX_KEYMATLEN];
		pointer = &kek_encr_keys;
		for(j=0;j<MAX_KEYS;j++){//rows

			for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++){//columns

					if(j == gsak->key_index){//1st key. I have to modify this when LKH is implemented.
						key_packet_attributes->attribute_value[i] = (*pointer)[j][i];
						if(gsak->rekey_case == 0){
						gsak->encr_key[i] = (*pointer)[j][i];
						}
					}

			}

		}
		/*
		 * Print out the encryption key that is added to the payload.
		 */
		IKE_PRINTF("The encryption key is: ");
		for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++) IKE_PRINTF("%02x ", key_packet_attributes->attribute_value[i]);
		IKE_PRINTF("\n");
		IKE_PRINTF("gsak->encr_key: ");
		for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++) IKE_PRINTF("%02x ", gsak->encr_key[i]);
		IKE_PRINTF("\n");

		payload_arg->start += sizeof(key_attributes_t);
		length += sizeof(key_attributes_t);
		num_of_keys++;


		#ifdef GIKE_INTEG
		key_packet_attributes = (key_attributes_t*)payload_arg->start;
		key_packet_attributes->attribute_type = KEK_INTEGRITY_KEY;
		uint8_t (*ptr)[MAX_KEYS][KEY_LENGTH];
		ptr = &kek_integ_keys;
		for(j=0; j<MAX_KEYS; j++){//rows

			for(i=0;i<KEY_LENGTH;i++){//columns

					if(j == gsak->key_index){//1st key. I have to modify this when LKH is implemented.
						key_packet_attributes->attribute_value[i] = (*ptr)[j][i];
						if(gsak->rekey_case == 0){
						gsak->integ_key[i] = (*ptr)[j][i];
						}
					}


			}
		}

		IKE_PRINTF("The integrity key is: ");
		for(i=0;i<KEY_LENGTH;i++) IKE_PRINTF("%02x ", key_packet_attributes->attribute_value[i]);
		IKE_PRINTF("\n");
		IKE_PRINTF("gsak->integ_key is: ");
		for(i=0;i<KEY_LENGTH;i++) IKE_PRINTF("%02x ", gsak->integ_key[i]);
		IKE_PRINTF("\n");

		payload_arg->start += sizeof(key_attributes_t);
		length += sizeof(key_attributes_t);
		num_of_keys++;
		IKE_PRINTF("key packet length is %u \n", length);
		IKE_PRINTF("numb_of_keys is %u \n", num_of_keys);

		#endif


	key_packet_attributes = (key_attributes_t*)payload_arg->start;
	key_packet_attributes->attribute_type = KEK_AUTH_KEY;


			uint8_t (*ptr3)[MAX_KEYS][SA_PRF_MAX_OUTPUT_LEN];
			ptr3 = &kek_auth_keys;
			for(j=0;j<MAX_KEYS;j++){//rows

				for(i=0;i<SA_PRF_MAX_OUTPUT_LEN;i++){//columns

						if(j == gsak->key_index){//1st key. I have to modify this when LKH is implemented.
							key_packet_attributes->attribute_value[i] = (*ptr3)[j][i];
							if(gsak->rekey_case == 0){
							gsak->auth_key[i] = (*ptr3)[j][i];
							}
						}

				}

			}
			/*
			 * Print out the encryption key that is added to the payload.
			 */
			IKE_PRINTF("KEK authentication key is: ");
			for(i=0;i<SA_PRF_MAX_OUTPUT_LEN;i++) IKE_PRINTF("%02x ", key_packet_attributes->attribute_value[i]);
			IKE_PRINTF("\n");
			IKE_PRINTF("gsak->auth_key: ");
			for(i=0;i<SA_PRF_MAX_OUTPUT_LEN;i++) IKE_PRINTF("%02x ", gsak->auth_key[i]);
			IKE_PRINTF("\n");

			payload_arg->start += sizeof(key_attributes_t);
			length += sizeof(key_attributes_t);
			num_of_keys++;

			key_packet->length = length;
			key_packet->num_of_keys = num_of_keys;
			IKE_PRINTF("key packet length is %u \n", length);
			IKE_PRINTF("numb_of_keys is %u \n", num_of_keys);

}else if(kd_type == TEK_KD){

	key_packet_attributes = (key_attributes_t*)payload_arg->start;
	key_packet_attributes->attribute_type = TEK_ENCR_KEY;

				uint8_t (*ptr1)[MAX_KEYS][SA_ENCR_MAX_KEYMATLEN];
				ptr1 = &tek_encr_keys;
					for(j=0;j<MAX_KEYS;j++){//rows

						for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++){//columns
								if(j==gsak->key_index){
										key_packet_attributes->attribute_value[i] = (*ptr1)[j][i];
										if(incoming_entry!=NULL){
										incoming_entry->sa.sk_e[i] = (*ptr1)[j][i];
										}
										outgoing_entry->sa.sk_e[i] = (*ptr1)[j][i];
								}
							}
					}

				IKE_PRINTF("The tek encryption key is: ");
				for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++) IKE_PRINTF("%02x ", key_packet_attributes->attribute_value[i]);
				IKE_PRINTF("\n");

				if(incoming_entry!=NULL){
				IKE_PRINTF("The sad_incoming_entry encryption key is: ");
				for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++) IKE_PRINTF("%02x ", incoming_entry->sa.sk_e[i]);
				IKE_PRINTF("\n");
				}

				IKE_PRINTF("The sad_outgoing_entry encryption key is: ");
				for(i=0;i<SA_ENCR_MAX_KEYMATLEN;i++) IKE_PRINTF("%02x ", outgoing_entry->sa.sk_e[i]);
				IKE_PRINTF("\n");

				payload_arg->start += sizeof(key_attributes_t);
				length += sizeof(key_attributes_t);
				num_of_keys++;


	#ifdef ESP_INTEG
	key_packet_attributes = (key_attributes_t*)payload_arg->start;
	key_packet_attributes->attribute_type = TEK_INTEGRITY_KEY;
	uint8_t (*ptr2)[2][KEY_LENGTH];
	ptr2 = &tek_integ_keys;
	for(j=0;j<MAX_KEYS;j++){//rows

		for(i=0;i<KEY_LENGTH;i++){//columns


				if(j==gsak->key_index){
					key_packet_attributes->attribute_value[i] = (*ptr2)[j][i];
					if(incoming_entry!=NULL){
					incoming_entry->sa.sk_a[i] = (*ptr2)[j][i];
					}
					outgoing_entry->sa.sk_a[i] = (*ptr2)[j][i];
				}
			}
	}

	IKE_PRINTF("The TEK integrity key is: ");
	for(i=0;i<KEY_LENGTH;i++) IKE_PRINTF("%02x ", key_packet_attributes->attribute_value[i]);
	IKE_PRINTF("\n");

	IKE_PRINTF("The sad_incoming_entry integrity key is: ");
	for(i=0;i<KEY_LENGTH;i++) IKE_PRINTF("%02x ", incoming_entry->sa.sk_a[i]);
	IKE_PRINTF("\n");

	IKE_PRINTF("The sad_outgoing_entry integrity key is: ");
	for(i=0;i<KEY_LENGTH;i++) IKE_PRINTF("%02x ", outgoing_entry->sa.sk_a[i]);
	IKE_PRINTF("\n");

				payload_arg->start += sizeof(key_attributes_t);
				length += sizeof(key_attributes_t);
				num_of_keys++;


	#endif

			key_packet->length = length;
			key_packet->num_of_keys = num_of_keys;
			IKE_PRINTF("key packet length is %u \n", key_packet->length);
			IKE_PRINTF("numb_of_keys is %u \n", key_packet->num_of_keys);

	// Copying the new KEK Encryption Key for Leave Case
	if(gsak->rekey_case == 3){
		uint8_t (*pointer)[MAX_KEYS][SA_ENCR_MAX_KEYMATLEN];
		pointer = &kek_encr_keys;
		for(j=0; j<MAX_KEYS; j++){//rows
			for(i=0; i<SA_ENCR_MAX_KEYMATLEN; i++){//columns
				if(j == gsak->key_index){//1st key. I have to modify this when LKH is implemented.
					gsak->encr_key[i] = (*pointer)[j][i];
				}
			}
		}
#ifdef GIKE_INTEG
		uint8_t (*ptr)[MAX_KEYS][KEY_LENGTH];
		ptr = &kek_integ_keys;
		for(j=0; j<MAX_KEYS; j++){//rows
			for(i=0; i<KEY_LENGTH; i++){//columns
				if(j == gsak->key_index){//1st key. I have to modify this when LKH is implemented.
					gsak->integ_key[i] = (*ptr)[j][i];
				}
			}
		}
#endif
		uint8_t (*ptr3)[MAX_KEYS][SA_PRF_MAX_OUTPUT_LEN];
		ptr3 = &kek_auth_keys;
		for(j=0; j<MAX_KEYS; j++){//rows
			for(i=0;i<SA_PRF_MAX_OUTPUT_LEN;i++){//columns
				if(j == gsak->key_index){//1st key. I have to modify this when LKH is implemented.
					gsak->auth_key[i] = (*ptr3)[j][i];
				}
			}
		}
	}
}else if(kd_type == LKH_KD){

}


		kd_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)kd_genpayloadhdr);
		IKE_PRINTF("KEY DOWNLOAD total payload length is %u \n", kd_genpayloadhdr->len);

}
/*---------------------------------------------------------------------------------------------------------------------*/
void parse_gsak_payload(uint8_t *payload_start,ike_statem_session_t *session){
	IKE_PRINTF("=========== PARSING KEK GSA PAYLOAD =========== \n");
		ike_payload_gsak_t *gsak_payload = NULL;
	    uint8_t parsed_payload = 0;
	    uint8_t i;
	    ike_payload_attribute_t *attrib = NULL;
	    gsa_attributes_t *kek_attributes = NULL;
	    gsak_entry_t *gsak_entry;

	  gsak_payload = (ike_payload_gsak_t*)payload_start;

	  gsak_payload->spi = *((uint32_t*)payload_start);

	  IKE_PRINTF("SPI = %d \n", gsak_payload->spi);
	  payload_start += sizeof(gsak_payload->spi);
	  parsed_payload += sizeof(gsak_payload->spi);
	  gsak_entry = find_gsak_entry(uip_ntohl(gsak_payload->spi));
	  if(gsak_entry == NULL){
	  gsak_entry = create_gsak_entry(uip_ntohl(gsak_payload->spi));
	  }
	  if(session!=NULL){//This is for the rekeying update process, where the session is erased and not used in client
	  gsak_entry->group_id = session->group_ip;
	  }

	  IKE_PRINTF("SPI, gsak_entry->spi = %u \n", gsak_entry->spi);

	  gsak_payload->length =*((uint16_t*)payload_start);

	  IKE_PRINTF("length = %d \n", gsak_payload->length);
	  payload_start += sizeof(gsak_payload->length);
	  parsed_payload += sizeof(gsak_payload->length);

	  gsak_payload->lifetime = *((uint16_t*)payload_start);		//1

	  IKE_PRINTF("lifetime = %d \n", gsak_payload->lifetime);
	  payload_start += sizeof(gsak_payload->lifetime);
	  parsed_payload += sizeof(gsak_payload->lifetime);

	  gsak_payload->clear =*((uint8_t*)payload_start);

	  IKE_PRINTF("clear = %d \n", gsak_payload->clear);
	  payload_start += sizeof(gsak_payload->clear);
	  parsed_payload += sizeof(gsak_payload->clear);

	  gsak_payload->spi_size = *((uint8_t*)payload_start);

	  IKE_PRINTF("SPI_SIZE = %u \n", gsak_payload->spi_size);
	  payload_start += sizeof(gsak_payload->spi_size);
	  parsed_payload += sizeof(gsak_payload->spi_size);

	  gsak_payload->msg_id = *((uint8_t*)payload_start);
	  IKE_PRINTF("msg_id = %u \n", gsak_payload->msg_id);
	  payload_start += sizeof(gsak_payload->msg_id);
	  parsed_payload += sizeof(gsak_payload->msg_id);
	  gsak_entry->msg_id = gsak_payload->msg_id;
	  IKE_PRINTF("gsak->msg_id = %u \n", gsak_entry->msg_id);

	  gsak_payload->numb_of_attributes = *((uint8_t*)payload_start);

	  IKE_PRINTF("numb_of_attributes = %d \n", gsak_payload->numb_of_attributes);
	  payload_start += sizeof(gsak_payload->numb_of_attributes);
	  parsed_payload += sizeof(gsak_payload->numb_of_attributes);
	  payload_start += (sizeof(ike_payload_gsak_t) - parsed_payload);



	  for(i=1; i <= gsak_payload->numb_of_attributes; i++){

		 kek_attributes = (gsa_attributes_t*)payload_start;
		 kek_attributes->last_more = *((uint8_t *)payload_start);
		 payload_start += sizeof(kek_attributes->last_more);

		 kek_attributes->attribute_type = *((kek_gsa_ctrl_t *)payload_start);
		 payload_start += sizeof(kek_attributes->attribute_type);

		 kek_attributes->attribute_value = *((uint8_t *)payload_start);
		 payload_start += sizeof(kek_attributes->attribute_value);
		 IKE_PRINTF("last_more = %u , kek_attribute_type = %u, value=%u \n", kek_attributes->last_more,kek_attributes->attribute_type, kek_attributes->attribute_value);

		 if(kek_attributes->attribute_type == GSA_CTRL_TYPE_ENCR){
			gsak_entry->encr = kek_attributes->attribute_value;
		 	IKE_PRINTF("Encryption, gsak_entry->encr = %u \n", gsak_entry->encr);
		  }

		 if(kek_attributes->attribute_type == GSA_CTRL_TYPE_INTEG){
			 gsak_entry->integ = kek_attributes->attribute_value;
			IKE_PRINTF("Integrity, gsak_entry->integ = %u \n", gsak_entry->integ);
		  }

		 if(kek_attributes->attribute_type == GSA_CTRL_TYPE_AUTH_METHOD){
			 gsak_entry->auth_method = kek_attributes->attribute_value;
			 IKE_PRINTF("Auth_method, gsak_entry->auth_method = %u \n", gsak_entry->auth_method);
		 }
		 if(kek_attributes->attribute_type == GSA_CTRL_TYPE_MNG_ALGORITHM){
			 gsak_entry->mng = kek_attributes->attribute_value;
			 IKE_PRINTF("Mng_algorithm, gsak_entry->mng = %u \n", gsak_entry->mng);
		  }
		  if(kek_attributes->attribute_type == GSA_CTRL_TYPE_ENCR){
			 attrib = (ike_payload_attribute_t*)payload_start;
			 attrib->af_attribute_type = *((uint16_t *)payload_start);
			 payload_start += sizeof(attrib->af_attribute_type);

			 attrib->attribute_value = *((uint16_t *)payload_start); /* Divide offer->value by 8 to make it into bits */
			 payload_start += sizeof(attrib->attribute_value);
			 IKE_PRINTF("The key attribute = %u with value %u \n", attrib->af_attribute_type, attrib->attribute_value);
			 gsak_entry->key_len = uip_ntohs(attrib->attribute_value) >> 3;
			 IKE_PRINTF("Key_len, gsak_entry->key_len = %u \n", gsak_entry->key_len);
		 }


	  }


}
/*---------------------------------------------------------------------------------------------------------------------*/
/*
 * Find the index of the corresponding entry for the specific group_address in the member table
 */
uint8_t
find_group_tek_gsa(uip_ip6addr_t group_address){
	uint8_t n;
	uip_ip6addr_t multicast_group_id;
	for(n=0;n<NUM_OF_MEMBERS;n++){
		uiplib_ipaddrconv(gpad_table[n].group_id,&multicast_group_id);

		if(memcmp(&multicast_group_id, &group_address,sizeof(uip_ip6addr_t))==0){
			return n+1;
		}
	}
	return 0;
}
/*---------------------------------------------------------------------------------------------------------------------*/

uint8_t
is_candidate_member_of_group(uip_ip6addr_t candidate_multicast_group_id, uip_ip6addr_t member_addr,ike_statem_session_t *session){
	/*
	 * received_group_id is the received IDg
	 * member_addr is session->peer_addr which corresponds to the candidate member ip addr.
	 */


	uip_ip6addr_t multicast_group_id;
	uip_ip6addr_t member_id;


	uint8_t n;
	for(n = 0; n < NUM_OF_MEMBERS; ++n) {

		uiplib_ipaddrconv(gpad_table[n].group_id,&multicast_group_id);
		uiplib_ipaddrconv(gpad_table[n].group_member,&member_id);


		if(memcmp(&multicast_group_id, &candidate_multicast_group_id,sizeof(uip_ip6addr_t))==0){
			if(memcmp(&member_id,&member_addr,sizeof(uip_ip6addr_t))==0){
				memcpy(&session->group_ip, &candidate_multicast_group_id, sizeof(uip_ip6addr_t));
				return n+1; //first element of array is 0
			}
		}

	}

	IKE_PRINTF(IPSEC_IKE "Non-existing group in GC/KS or the candidate member is not authorized to the secure group. \n");
	return 0;
}
/*---------------------------------------------------------------------------------------------------------------------*/
void
ike_statem_set_group_id_payload(payload_arg_t *payload_arg, ike_payload_type_t payload_type, ike_statem_session_t *session){
  ike_payload_generic_hdr_t *id_genpayloadhdr;
  SET_GENPAYLOADHDR(id_genpayloadhdr, payload_arg, payload_type);

  ike_group_id_payload_t *id_payload = (ike_group_id_payload_t *)payload_arg->start;
  /* Clear the RESERVED area */
  id_payload->group_id = session->group_ip;
  id_payload->id_type = IKE_ID_IPV6_ADDR;
  id_payload->clear1 = 0;
  id_payload->clear2 = 0;

  payload_arg->start +=sizeof(ike_group_id_payload_t);
  id_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)id_genpayloadhdr);
}
