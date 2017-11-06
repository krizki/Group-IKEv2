/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    Common functionality for IKEv2. Mostly helpers for the state machine.
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se> - fixes and added functionality
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
 * Pertains to Contiki's implementation of RFC 7296 (IKEv2)
 */
#include <lib/random.h>
#include <string.h>
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

#include "cert/cert-conf.h"
#include "cert/cert-parser.h"

/*
 * Group Key Management
 */
#include "g-ike-conf.h"

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

/**
 * Used by RPL SAs
 */
#if IKE_WITH_RPL
#include "rpl/rpl-sad.h"
#include "rpl/rpl-sa.h"
#include "rpl/rpl-ike-conf.h"
#endif

#if IKE_WITH_IEEE
#include "ieee-802-15-4/ieee-802-15-4-sad.h"
#include "ieee-802-15-4/ieee-802-15-4-sa.h"
#include "ieee-802-15-4/ieee-802-15-4-conf.h"
#include "ieee-802-15-4/ieee-802-15-4-traffic-selector.h"
#include "net/mac/frame802154.h"
#include "net/ipv6/uip-ds6-route.h"
#include "../ipv6/uip-ds6-nbr.h"
#endif

#if IKE_IPSEC_INFO
#include <stdio.h>
#if IPSEC_TIME_STATS
#include "sys/rtimer.h"
#endif
#endif

/**
 * Functions common to all state machines
 */

/*---------------------------------------------------------------------------*/
void
ike_statem_write_notification(payload_arg_t *payload_arg,
                              sa_ipsec_proto_type_t proto_id,
                              uint32_t spi,
                              notify_msg_type_t type,
                              uint8_t *notify_payload,
                              uint8_t notify_payload_len)
{
  uint8_t *beginning = payload_arg->start;

  ike_payload_generic_hdr_t *notify_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
  SET_GENPAYLOADHDR(notify_genpayloadhdr, payload_arg, IKE_PAYLOAD_N);

  ike_payload_notify_t *notifyhdr = (ike_payload_notify_t *)payload_arg->start;
  notifyhdr->proto_id = proto_id;
  notifyhdr->notify_msg_type = uip_ntohs(type);
  payload_arg->start += sizeof(ike_payload_notify_t);
  if(spi != 0) {
    notifyhdr->spi_size = 4;
    *payload_arg->start = spi;
    payload_arg->start += 4;
  } else {
    notifyhdr->spi_size = 0;
    /* Write the notify payload, if any */
  } if(notify_payload != NULL) {
    memcpy(payload_arg->start, notify_payload, notify_payload_len);
    payload_arg->start += notify_payload_len;
  }

  notify_genpayloadhdr->len = uip_htons(payload_arg->start - beginning);
}
/*---------------------------------------------------------------------------*/
void
ike_statem_write_tsitsr(payload_arg_t *payload_arg, const ipsec_addr_set_t *ts_addr_set)
{
  uint8_t *ptr = payload_arg->start;

  /**
   * Initiator's traffic selectors (i.e. describing the source of the traffic)
   *
   * In blatant violation of the RFC the PFP flags are hardcoded. PFP is only used on
   * the address selector, other parameters are fetched from the matching SPD entry.
   */
  /* */
  /* PFP is hardcoded. PFP(SRCADDR) PFP(DSTADDR), other parameters are taken from SPD entry */

  /* TSi payload */
  ike_payload_generic_hdr_t *tsi_genpayloadhdr;
  uint16_t tsir_size = sizeof(ike_payload_generic_hdr_t) + sizeof(ike_payload_ts_t) + 1 * sizeof(ike_ts_t);
  SET_GENPAYLOADHDR(tsi_genpayloadhdr, payload_arg, IKE_PAYLOAD_TSi);
  tsi_genpayloadhdr->len = uip_htons(tsir_size);
  ike_payload_ts_t *tsi_payload = (ike_payload_ts_t *)payload_arg->start;
  SET_TSPAYLOAD(tsi_payload, 1);
  payload_arg->start += sizeof(ike_payload_ts_t);

  /* Initiator's first traffic selector (triggering packet's params) */
  ike_ts_t *tsi1 = (ike_ts_t *)payload_arg->start;
  payload_arg->start += sizeof(ike_ts_t);

  /* TSr payload */
  ike_payload_generic_hdr_t *tsr_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
  SET_GENPAYLOADHDR(tsr_genpayloadhdr, payload_arg, IKE_PAYLOAD_TSr);
  tsr_genpayloadhdr->len = uip_htons(tsir_size);
  ike_payload_ts_t *tsr_payload = (ike_payload_ts_t *)payload_arg->start;
  SET_TSPAYLOAD(tsr_payload, 1);
  payload_arg->start += sizeof(ike_payload_ts_t);

  /* Responder's first traffic selector */
  ike_ts_t *tsr1 = (ike_ts_t *)payload_arg->start;
  payload_arg->start += sizeof(ike_ts_t);

  if(IKE_STATEM_IS_INITIATOR(payload_arg->session)) {
    instanciate_spd_entry(ts_addr_set, &payload_arg->session->peer, tsi1, tsr1);
  } else {
    instanciate_spd_entry(ts_addr_set, &payload_arg->session->peer, tsr1, tsi1);
  }
  IKE_PRINTF("WRITING TRAFFIC SELECTORS:\n");
  PRINTADDRSET(ts_addr_set);

  IKE_MEMPRINT("\ntsi_genpayloadhdr", (uint8_t *)tsi_genpayloadhdr, uip_ntohs(tsi_genpayloadhdr->len));

  IKE_MEMPRINT("tsr_genpayloadhdr", (uint8_t *)tsr_genpayloadhdr, uip_ntohs(tsr_genpayloadhdr->len));
  IKE_PRINTF("len: %u\n", payload_arg->start - ptr);
}
/*---------------------------------------------------------------------------*/
#if IKE_WITH_IEEE
void
ike_statem_write_ieee_tsitsr(payload_arg_t *payload_arg, const ipsec_addr_set_t *ts_addr_set)
{
  uint8_t *ptr = payload_arg->start;

  /**
   * Initiator's traffic selectors (i.e. describing the source of the traffic)
   */
  /* TSi payload */
  ike_payload_generic_hdr_t *tsi_genpayloadhdr;
  uint16_t tsir_size = sizeof(ike_payload_generic_hdr_t) + sizeof(ike_payload_ts_t) + 1 * sizeof(ike_ieee_ts_t);
  SET_GENPAYLOADHDR(tsi_genpayloadhdr, payload_arg, IKE_PAYLOAD_TSi);
  tsi_genpayloadhdr->len = uip_htons(tsir_size);
  ike_payload_ts_t *tsi_payload = (ike_payload_ts_t *)payload_arg->start;
  SET_TSPAYLOAD(tsi_payload, 1);
  payload_arg->start += sizeof(ike_payload_ts_t);

  /* Initiator's first traffic selector (triggering packet's params) */
  ike_ieee_ts_t *tsi1 = (ike_ieee_ts_t *)payload_arg->start;
  payload_arg->start += sizeof(ike_ieee_ts_t);

  /* TSr payload */
  ike_payload_generic_hdr_t *tsr_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
  SET_GENPAYLOADHDR(tsr_genpayloadhdr, payload_arg, IKE_PAYLOAD_TSr);
  tsr_genpayloadhdr->len = uip_htons(tsir_size);
  ike_payload_ts_t *tsr_payload = (ike_payload_ts_t *)payload_arg->start;
  SET_TSPAYLOAD(tsr_payload, 1);
  payload_arg->start += sizeof(ike_payload_ts_t);

  /* Responder's first traffic selector */
  ike_ieee_ts_t *tsr1 = (ike_ieee_ts_t *)payload_arg->start;
  payload_arg->start += sizeof(ike_ieee_ts_t);

  ike_ieee_ts_t *ts_me, *ts_peer;
  if(IKE_STATEM_IS_INITIATOR(payload_arg->session)) {

    ts_me = tsi1;
    ts_peer = tsr1;
  } else {
    ts_me = tsr1;
    ts_peer = tsi1;
  }

  /**
   * Set common stuff
   */
  ts_peer->ts_type = ts_me->ts_type = IKE_PAYLOADFIELD_TS_802_15_4_ADDR;
  ts_peer->selector_len = ts_me->selector_len = uip_htons(sizeof(ike_ieee_ts_t));

  /* uip_ipaddr_t *peer_global_address = &payload_arg->session->peer; */
  uip_ds6_nbr_t *nbr;
  uint8_t best;
  uip_ipaddr_t *peer_link_local = NULL;
  best = 0;

  uint8_t zeros[sizeof(uip_lladdr_t)];
  memset(zeros, 0, sizeof(uip_lladdr_t));

  uip_lladdr_t *peer_lladdr = NULL;
  uip_lladdr_t *my_lladdr = &uip_lladdr;

  IKE_PRINTF("Address Global: \n");
  PRINT6ADDR(&payload_arg->session->peer);
  IKE_PRINTF("\n");

  /* Find the link layer address of the peer */
  if(memcmp(&payload_arg->session->peer_lladdr, zeros, sizeof(uip_lladdr_t)) == 0) {
    for(nbr = nbr_table_head(ds6_neighbors); nbr != NULL; nbr = nbr_table_next(ds6_neighbors, nbr)) {
      IKE_PRINTF("Address: \n");
      PRINT6ADDR(&nbr->ipaddr);
      PRINTLLADDR(uip_ds6_nbr_lladdr_from_ipaddr(&nbr->ipaddr));
      IKE_PRINTF("\n");

      /* Find the best match in the neighbourhood table */
      uint8_t j, k, x_or;
      uint8_t n = 0;

      for(j = 15; j > 0; j--) {
        if(payload_arg->session->peer.u8[j] == nbr->ipaddr.u8[j]) {
          n += 8;
        } else {
          x_or = payload_arg->session->peer.u8[j] ^ nbr->ipaddr.u8[j];
          for(k = 0; k < 8; k++) {
            if((x_or & 0x80) == 0) {
              n++;
              x_or <<= 1;
            } else {
              break;
            }
          }
          break;
        }
      }

      if(n >= best) {
        best = n;
        peer_link_local = &nbr->ipaddr;
      }
    }
    IKE_PRINTF("Address Link-local: \n");
    PRINT6ADDR(peer_link_local);
    IKE_PRINTF("\n");

    peer_lladdr = uip_ds6_nbr_lladdr_from_ipaddr(peer_link_local);
    memcpy(&payload_arg->session->peer_lladdr, peer_lladdr, sizeof(uip_lladdr_t));
  } else {
    peer_lladdr = &payload_arg->session->peer_lladdr;
  }
  IKE_PRINTF("Peer lladdr\n");
  PRINTLLADDR(peer_lladdr);
  IKE_PRINTF("\nMy lladdr\n");
  PRINTLLADDR(my_lladdr);
  IKE_PRINTF("\n");

  /**
   * Address and port numbers
   */
  memcpy(&ts_peer->start_addr, peer_lladdr, sizeof(uip_lladdr_t));
  memcpy(&ts_peer->end_addr, peer_lladdr, sizeof(uip_lladdr_t));
  memcpy(&ts_me->start_addr, my_lladdr, sizeof(uip_lladdr_t));
  memcpy(&ts_me->end_addr, my_lladdr, sizeof(uip_lladdr_t));

  IKE_PRINTF("WRITING TRAFFIC SELECTORS:\n");

  IKE_MEMPRINT("\ntsi_genpayloadhdr", (uint8_t *)tsi_genpayloadhdr, uip_ntohs(tsi_genpayloadhdr->len));

  IKE_MEMPRINT("tsr_genpayloadhdr", (uint8_t *)tsr_genpayloadhdr, uip_ntohs(tsr_genpayloadhdr->len));
  IKE_PRINTF("len: %u\n", payload_arg->start - ptr);
}
#endif
/*---------------------------------------------------------------------------*/
void
ike_statem_send_single_notify(ike_statem_session_t *session, notify_msg_type_t type)
{
  payload_arg_t payload_arg = {
    .start = msg_buf,
    .session = session
  };

  /* Don't do anything if type is 0 */
  if(!type) {
    return;
  }
  IKE_PRINTF(IPSEC_IKE "Sending single notification to peer of type %u\n", type);

  ike_payload_ike_hdr_t *old_ike_hdr = (ike_payload_ike_hdr_t *)msg_buf;
  uint8_t protect = old_ike_hdr->exchange_type == IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_IKE_AUTH || old_ike_hdr->exchange_type == IKE_PAYLOADFIELD_IKEHDR_EXCHTYPE_CREATE_CHILD_SA;

  SET_IKE_HDR_AS_RESPONDER(&payload_arg, old_ike_hdr->exchange_type, IKE_PAYLOADFIELD_IKEHDR_FLAGS_RESPONSE);

  ike_payload_generic_hdr_t *sk_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg.start;
  if(protect) {
    /* Write a template of the SK payload for later encryption */
    ike_statem_prepare_sk(&payload_arg);
    /*
     * Write notification requesting the peer to create transport mode SAs
     */
  }
  ike_statem_write_notification(&payload_arg, SA_PROTO_IKE, 0, type, NULL, 0);

  if(protect) {
    /* Protect the SK payload. Write trailing fields. */
    ike_statem_finalize_sk(&payload_arg, sk_genpayloadhdr, payload_arg.start - (((uint8_t *)sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t)));
    /* Send! */
  }
  ike_statem_send(session, uip_ntohl(((ike_payload_ike_hdr_t *)msg_buf)->len));

  return;
}
/*---------------------------------------------------------------------------*/
transition_return_t
ike_statem_send_sa_init_msg(ike_statem_session_t *session, payload_arg_t *payload_arg, ike_payload_ike_hdr_t *ike_hdr, spd_proposal_tuple_t *offer)
{
#if IKE_IPSEC_INFO
  printf("Generating IKE_SA_INIT ");
  if(IKE_STATEM_IS_INITIATOR(session)) {
    printf("request");
  } else {
    printf("response");
  } 
  printf(" for session %p\n", session);

#if IPSEC_TIME_STATS
  rtimer_clock_t exec_time;
  rtimer_clock_t total_time;
  total_time = 0;
#endif
#endif

  /* Should we include a COOKIE Notification? (see section 2.6) */
  /**
   * Disabled as for now -Ville
     IKE_STATEM_ASSERT_COOKIE(&payload_arg);
   **/

#if IKE_IPSEC_INFO
  printf("IKE_SA_INIT: SA ");
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW();
#endif
#endif

  /* Write the SA payload */
  /* From p. 79: */
  /*    "SPI Size (1 octet) - For an initial IKE SA negotiation, this field MUST be zero; */
  /*    the SPI is obtained from the outer header." */
  /* */
  /* (Note: We're casting to spd_proposal_tuple * in order to get rid of the const type qualifier of CURRENT_IKE_PROPOSAL) */
  ike_statem_write_sa_payload(payload_arg, offer, 0);

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  printf(",%lu us", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
#endif
  printf(", KE ");
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW();
#endif
#endif

  /* Start KE payload */
  ike_payload_generic_hdr_t *ke_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
  SET_GENPAYLOADHDR(ke_genpayloadhdr, payload_arg, IKE_PAYLOAD_KE);

  ike_payload_ke_t *ke = (ike_payload_ke_t *)payload_arg->start;
  ke->dh_group_num = uip_htons(SA_IKE_MODP_GROUP);
  ke->clear = 0;

  /* Write key exchange data (varlen) */
  /* (Note: We cast the first arg of ecdh_enc...() in the firm belief that payload_arg->start is at a 4 byte alignment) */
  IKE_PRINTF(IPSEC_IKE "Computes and encodes public ECC Diffie Hellman key\n");
  payload_arg->start = ecdh_encode_public_key((uint32_t *)(payload_arg->start + sizeof(ike_payload_ke_t)), session->ephemeral_info->my_prv_key);
  ke_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)ke_genpayloadhdr);
  /* End KE payload */

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  printf(",%lu us", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
#endif
  printf(", N ");
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW();
#endif
#endif

  /* Start nonce payload */
  ike_payload_generic_hdr_t *ninr_genpayloadhdr;
  SET_GENPAYLOADHDR(ninr_genpayloadhdr, payload_arg, IKE_PAYLOAD_NiNr);

  /* Write nonce */
  memcpy(payload_arg->start, &session->ephemeral_info->my_nounce, IKE_PAYLOAD_MYNONCE_LEN);
  IKE_MEMPRINT("My nonce", payload_arg->start, IKE_PAYLOAD_MYNONCE_LEN);
  payload_arg->start += IKE_PAYLOAD_MYNONCE_LEN;
  ninr_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)ninr_genpayloadhdr);
  /* End nonce payload */

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  printf(",%lu us", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
#endif
#endif

#if WITH_CONF_IKE_CERT_AUTH
  if(!IKE_STATEM_IS_INITIATOR(session)) {

#if IKE_IPSEC_INFO
    printf(", CERTREQ ");
#if IPSEC_TIME_STATS
    exec_time = RTIMER_NOW();
#endif
#endif

    /* CERTIFICATE CODE */
    /* Write Certificate Request here if pubkey auth */
    ike_payload_generic_hdr_t *cert_req_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
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
#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
    exec_time = RTIMER_NOW() - exec_time;
    total_time += exec_time;
    printf(",%lu us", (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
#endif
#endif
  }
#endif /* WITH_CONF_IKE_CERT_AUTH */

#if IKE_WITH_RPL
  /* We only send notify message if support RPL */
  if(IKE_STATEM_IS_INITIATOR(session)) {
    /* Only the initiator can initiate RPL key negotiation */
    IKE_PRINTF("Initiator initiating RPL key negotiation\n");

    ike_statem_write_notification(payload_arg, SA_PROTO_RPL, 0,
                                  IKE_PAYLOAD_NOTIFY_RPL_SUPPORTED, NULL, 0);
  } else {
    /* The Responder only send notify message if he has received one */
    if(session->recieved_rpl_supported) {
      IKE_PRINTF("Responder sending back a RPL supported notify payload\n");
      ike_statem_write_notification(payload_arg, SA_PROTO_RPL, 0,
                                    IKE_PAYLOAD_NOTIFY_RPL_SUPPORTED, NULL, 0);
    }
  }
#endif

#if IKE_WITH_IEEE
  /* We only send notify message if support IEEE key management */
  if(IKE_STATEM_IS_INITIATOR(session)) {
    /* Only the initiator can initiate the key negotiation */
    IKE_PRINTF("Initiator initiating IEEE 802.15.4 key negotiation\n");

    ike_statem_write_notification(payload_arg, SA_PROTO_IEEE_802_15_4, 0,
                                  IKE_PAYLOAD_NOTIFY_IEEE_802_15_4_SUPPORTED, NULL, 0);
  } else {
    /* The Responder only send notify message if has received one */
    if(session->recieved_ieee_supported) {
      IKE_PRINTF("Responder sending back a IEEE 802.15.4 supported notify payload\n");
      ike_statem_write_notification(payload_arg, SA_PROTO_IEEE_802_15_4, 0,
                                    IKE_PAYLOAD_NOTIFY_IEEE_802_15_4_SUPPORTED, NULL, 0);
    }
  }
#endif

#if WITH_GROUP_IKE
  /* We only send notify message if the candidate member initializes Group Key Management with IKEv2.  */
  if(IKE_STATEM_IS_INITIATOR(session)) {
    /* Only the candidate member can initiate Group Key Management */
    IKE_PRINTF("Candidate member initiating Group Key Management with IKEv2.\n");

    ike_statem_write_notification(payload_arg, SA_PROTO_IKE, 0,
    		IKE_PAYLOAD_NOTIFY_INITIALIZE_GROUP_KEY_MANAGEMENT, NULL, 0);
  }

#endif

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  printf(", Total, %lu us", (uint32_t)((uint64_t)total_time * 1000000 / RTIMER_SECOND));
#endif
  printf("\n");
#endif

  /* Wrap up the IKE header and exit state */
  ((ike_payload_ike_hdr_t *)msg_buf)->len = uip_htonl(payload_arg->start - msg_buf);
  SET_NO_NEXT_PAYLOAD(payload_arg);

  return payload_arg->start - msg_buf;
}
/*---------------------------------------------------------------------------*/
state_return_t
ike_statem_parse_auth_msg(ike_statem_session_t *session)
{
#if IKE_IPSEC_INFO
  printf("Parsing and verifying IKE_AUTH ");
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

  ike_payload_ike_hdr_t *ike_hdr = (ike_payload_ike_hdr_t *)msg_buf;
  ike_id_payload_t *id_data = NULL;
  uint8_t id_datalen;
  ike_payload_auth_t *auth_payload = NULL;
  uint8_t transport_mode_not_accepted = 0;

  /* Traffic selector */
  ike_payload_ts_t *tsr_payload = NULL;
  ike_payload_ts_t *tsi_payload = NULL;
#if !(IKE_WITH_IEEE)
  ike_ts_t *tsi = NULL, *tsr = NULL;
#else
  ike_ieee_ts_t *tsi = NULL, *tsr = NULL;
#endif
  int16_t ts_count = -1;

  /* Child SAs */
  uint32_t sad_time = clock_time();
#if WITH_IPSEC
  sad_entry_t *outgoing_sad_entry;
  sad_entry_t *incoming_sad_entry;
  if(session->incoming_entry != NULL && session->outgoing_entry != NULL) {
    sad_remove_outgoing_entry(session->outgoing_entry);
    sad_remove_incoming_entry(session->incoming_entry);
  }
  outgoing_sad_entry = sad_create_outgoing_entry(sad_time);
  incoming_sad_entry = sad_create_incoming_entry(sad_time);
#endif
#if IKE_WITH_RPL
  rpl_sad_entry_t *outgoing_sad_entry = NULL;
  rpl_sad_entry_t *incoming_sad_entry = NULL;
  if(session->incoming_entry != NULL && session->outgoing_entry != NULL) {
    rpl_sad_remove_outgoing_entry(session->outgoing_entry);
    rpl_sad_remove_incoming_entry(session->incoming_entry);
  }
  outgoing_sad_entry = rpl_sad_create_outgoing_entry(sad_time);
  incoming_sad_entry = rpl_sad_create_incoming_entry(sad_time);
#endif
#if IKE_WITH_IEEE
  ieee_sad_entry_t *outgoing_sad_entry = NULL;
  ieee_sad_entry_t *incoming_sad_entry = NULL;
  if(session->incoming_entry != NULL && session->outgoing_entry != NULL) {
    ieee_sad_remove_outgoing_entry(session->outgoing_entry);
    ieee_sad_remove_incoming_entry(session->incoming_entry);
  }
  outgoing_sad_entry = ieee_sad_create_outgoing_entry(sad_time);
  incoming_sad_entry = ieee_sad_create_incoming_entry(sad_time);
#endif

  if(outgoing_sad_entry == NULL || incoming_sad_entry == NULL) {
    IKE_PRINTF(IPSEC_IKE_ERROR "Couldn't create SAs\n");
    goto memory_fail;
  }

  uint8_t *ptr = msg_buf + sizeof(ike_payload_ike_hdr_t);
  uint8_t *end = msg_buf + uip_datalen();
  notify_msg_type_t fail_notify_type = 0;
  ike_payload_generic_hdr_t *sa_payload = NULL;
  ike_payload_type_t payload_type = ike_hdr->next_payload;

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
    case IKE_PAYLOAD_SK:
#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
      exec_time = RTIMER_NOW() - exec_time;
      total_time += exec_time;
      exec_time = RTIMER_NOW();
#endif
#endif
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
        goto fail;
      }
    }
    break;

    case IKE_PAYLOAD_IDi:
    case IKE_PAYLOAD_IDr:
      IKE_PRINTF("ID payload\n");
      id_data = (ike_id_payload_t *)payload_start;
      id_datalen = uip_ntohs(genpayloadhdr->len) - sizeof(ike_payload_generic_hdr_t);
      IKE_PRINTF("ID-Type %u, length %u\n", id_data->id_type, id_datalen);
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

    case IKE_PAYLOAD_SA:
      /**
       * Assert that the responder's child offer is a subset of that of ours
       */
      sa_payload = (ike_payload_generic_hdr_t *)genpayloadhdr;
      break;

    case IKE_PAYLOAD_TSi:
      tsi_payload = (ike_payload_ts_t *)payload_start;
#if !(IKE_WITH_IEEE)
      tsi = (ike_ts_t *)(payload_start + sizeof(ike_payload_ts_t));
      IKE_PRINTF("Traffic selector TSi\n");
      IKE_HEXDUMP((uint8_t *)tsi_payload, sizeof(ike_payload_ts_t) + sizeof(ike_ts_t));
#else
      tsi = (ike_ieee_ts_t *)(payload_start + sizeof(ike_payload_ts_t));
      IKE_PRINTF("Traffic selector TSi\n");
      IKE_HEXDUMP((uint8_t *)tsi_payload, sizeof(ike_payload_ts_t) + sizeof(ike_ieee_ts_t));
#endif
      if(ts_count == -1 || tsi_payload->number_of_ts < ts_count) {
        ts_count = tsi_payload->number_of_ts;
      }
      break;
    case IKE_PAYLOAD_TSr:
      tsr_payload = (ike_payload_ts_t *)payload_start;
#if !(IKE_WITH_IEEE)
      tsr = (ike_ts_t *)(payload_start + sizeof(ike_payload_ts_t));
      IKE_PRINTF("Traffic selector TSr\n");
      IKE_HEXDUMP((uint8_t *)tsr_payload, sizeof(ike_payload_ts_t) + sizeof(ike_ts_t));
#else
      tsr = (ike_ieee_ts_t *)(payload_start + sizeof(ike_payload_ts_t));
      IKE_PRINTF("Traffic selector TSr\n");
      IKE_HEXDUMP((uint8_t *)tsr_payload, sizeof(ike_payload_ts_t) + sizeof(ike_ieee_ts_t));
#endif
      if(ts_count == -1 || tsr_payload->number_of_ts < ts_count) {
        ts_count = tsr_payload->number_of_ts;
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

  if(payload_type != IKE_PAYLOAD_NO_NEXT || sa_payload == NULL) {
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

#if !IKE_WITH_IEEE
  ike_ts_t *ts_me = NULL;
  ike_ts_t *ts_peer = NULL;
#else
  ike_ieee_ts_t *ts_me = NULL;
  ike_ieee_ts_t *ts_peer = NULL;
#endif
  /**
   * Assert that traffic descriptors are acceptable and find matching SPD entry (responder)
   */
  int16_t ts = -1;
  if(IKE_STATEM_IS_INITIATOR(session)) {
    /* If we're the initiator, the responder's TS offer must be a subset of our original offer derived from the SPD entry */
#if !IKE_WITH_IEEE
    if(ts_count == 1 && selector_is_superset_of_tspair(&session->ephemeral_info->spd_entry.selector, &tsi[0], &tsr[0])) {
      ts = 0; /* The peer's traffic selector matched our original offer. Continue. */
    }
#else
    if(ts_count == 1) {
      ts = 0;
    }
#endif
  } else {
    /* We're the responder. Find the SPD entry that matches the initiator's TS offer */
    for(ts = ts_count - 1; ts >= 0; --ts) {
#if WITH_IPSEC
      spd_entry_t *spd_entry = spd_get_entry_by_tspair(&tsr[ts] /* me */, &tsi[ts] /* peer */, SA_PROTO_ESP);
      if(spd_entry != NULL && spd_entry->proc_action == SPD_ACTION_PROTECT) {
        /* Found an SPD entry that requires protection for this traffic */
        /** FIX: memcpy for retransmisions of IKE_AUTH*/

        /* session->ephemeral_info->spd_entry = spd_entry; */
        memcpy(&session->ephemeral_info->spd_entry, spd_entry, sizeof(spd_entry_t));
        session->ephemeral_info->my_ts_offer_addr_set.peer_addr_from = session->ephemeral_info->my_ts_offer_addr_set.peer_addr_to = &session->peer;
        ts_pair_to_addr_set(&session->ephemeral_info->my_ts_offer_addr_set, &tsr[ts], &tsi[ts]);
        break;
      }
#endif
      /* TODO: Special RPL/802.15.4 handling */
      if(session->recieved_ieee_supported || session->recieved_rpl_supported) {
#if IKE_WITH_RPL
        spd_entry_t *spd_entry = spd_get_entry_by_tspair(&tsr[ts] /* me */, &tsi[ts] /* peer */, SA_PROTO_RPL);
        if(spd_entry != NULL && spd_entry->proc_action == SPD_ACTION_PROTECT) {
          /* Found an SPD entry that requires protection for this traffic */
          /* session->ephemeral_info->spd_entry = spd_entry; */
          memcpy(&session->ephemeral_info->spd_entry, spd_entry, sizeof(spd_entry_t));

          session->ephemeral_info->my_ts_offer_addr_set.peer_addr_from = session->ephemeral_info->my_ts_offer_addr_set.peer_addr_to = &session->peer;
          ts_pair_to_addr_set(&session->ephemeral_info->my_ts_offer_addr_set, &tsr[ts], &tsi[ts]);
          break;
        }
#endif
#if IKE_WITH_IEEE
        ike_ts_t ip_ts_me, ip_ts_peer;

        /* Create a fake IPv6 traffic selector*/
        ip_ts_me.proto = ip_ts_peer.proto = SPD_SELECTOR_NL_ANY_PROTOCOL;
        ip_ts_me.start_port = ip_ts_peer.start_port = 0;
        ip_ts_me.end_port = ip_ts_peer.end_port = PORT_MAX;
        ip_ts_me.ts_type = ip_ts_peer.ts_type = IKE_PAYLOADFIELD_TS_IPV6_ADDR_RANGE;

        memcpy(&ip_ts_me.start_addr, my_ip_addr, sizeof(uip_ip6addr_t));
        memcpy(&ip_ts_peer.start_addr, my_ip_addr, sizeof(uip_ip6addr_t));
        memcpy(&ip_ts_me.end_addr, &session->peer, sizeof(uip_ip6addr_t));
        memcpy(&ip_ts_me.end_addr, &session->peer, sizeof(uip_ip6addr_t));

        spd_entry_t *spd_entry = spd_get_entry_by_tspair(&ip_ts_me /* me */, &ip_ts_peer /* peer */, SA_PROTO_IEEE_802_15_4);
        if(spd_entry != NULL && spd_entry->proc_action == SPD_ACTION_PROTECT) {
          /* Found an SPD entry that requires protection for this traffic */
          memcpy(&session->ephemeral_info->spd_entry, spd_entry, sizeof(spd_entry_t));

          memcpy(&session->peer_lladdr, &tsi[ts].start_addr, sizeof(uip_lladdr_t));

          session->ephemeral_info->my_ts_offer_ieee_addr_set.peer_lladdr_from = session->ephemeral_info->my_ts_offer_ieee_addr_set.peer_lladdr_to = &session->peer_lladdr;

          /* Verify that my lladdr is used in the traffic selector */
          if(memcmp(&tsr[ts].start_addr, &uip_lladdr, sizeof(uip_lladdr_t)) == 0) {
            IKE_PRINTF("TSR has my LLADDR\n");
            break;
          } else {
            IKE_PRINTF(IPSEC_ERROR "TSR does not have my LLADDR\n");
            IKE_PRINTF("My LLADDR: ");
            PRINTLLADDR(&uip_lladdr);
            IKE_PRINTF("\nLLADDR in TSR: ");
            PRINTLLADDR(&tsr[ts].start_addr);
            IKE_PRINTF("\n");
          }
        }
#endif
      }
    }
  }
  if(ts < 0) {
    IKE_PRINTF(IPSEC_IKE_ERROR "Peer's Traffic Selectors are unacceptable\n");
    fail_notify_type = IKE_PAYLOAD_NOTIFY_TS_UNACCEPTABLE;
    goto fail;
  }

  IKE_PRINTF("After Traffic selector validation\n");

  /**
   * Now that we've found the right SPD entry, we know what Child SA offer to use
   */

  /* Parse RPL IEEE 802.15.4 sp*/
  if(session->recieved_rpl_supported) {
#if IKE_WITH_RPL
    if(ike_statem_parse_rpl_sa_payload(session->ephemeral_info->spd_entry.offer,
                                       sa_payload, outgoing_sad_entry, SA_PROTO_RPL,
                                       session->ephemeral_info->child_proposal_reply)) {
      IKE_PRINTF(IPSEC_IKE_ERROR "The peer's child RPL SA offer was unacceptable\n");
      fail_notify_type = IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN;
      goto fail;
    }
#endif
  } else if(session->recieved_ieee_supported) {
#if IKE_WITH_IEEE
    if(ike_statem_parse_ieee_sa_payload(session->ephemeral_info->spd_entry.offer,
                                        sa_payload, outgoing_sad_entry, SA_PROTO_IEEE_802_15_4,
                                        session->ephemeral_info->child_proposal_reply)) {
      IKE_PRINTF(IPSEC_IKE_ERROR "The peer's child IEEE 802.15.4 SA offer was unacceptable\n");
      fail_notify_type = IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN;
      goto fail;
    }
#endif
  } else {
#if WITH_IPSEC
    if(ike_statem_parse_sa_payload(session->ephemeral_info->spd_entry.offer,
                                   sa_payload,
                                   0,
                                   NULL,
                                   outgoing_sad_entry,
                                   session->ephemeral_info->child_proposal_reply)) {
      IKE_PRINTF(IPSEC_IKE_ERROR "The peer's child SA offer was unacceptable\n");
      fail_notify_type = IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN;
      goto fail;
    }
#endif
  }

#if WITH_IPSEC
  /* Set incoming SAD entry */
  session->ephemeral_info->peer_child_spi = outgoing_sad_entry->spi;  /* For use in the next response */
  incoming_sad_entry->spi = session->ephemeral_info->my_child_spi;
  IKE_PRINTF("peer_child_spi (outgoing) %u, my_child_spi (incoming) %u\n", outgoing_sad_entry->spi, incoming_sad_entry->spi);
#endif
  incoming_sad_entry->sa.proto = outgoing_sad_entry->sa.proto;
  incoming_sad_entry->sa.encr = outgoing_sad_entry->sa.encr;
  incoming_sad_entry->sa.encr_keylen = outgoing_sad_entry->sa.encr_keylen;
  incoming_sad_entry->sa.integ = outgoing_sad_entry->sa.integ;
#if IKE_WITH_RPL
  incoming_sad_entry->LVL = outgoing_sad_entry->LVL;
#endif
#if IKE_WITH_IEEE
  incoming_sad_entry->LVL = outgoing_sad_entry->LVL;
#endif

  IKE_PRINTF(IPSEC_IKE "The peer's proposal was accepted\n");
  /**
   * Set traffic descriptors for SAD entries
   */
  /* Fn: ts_pair_to_addr_set, addr_set_is_a_subset_of_addr_set, (addr_set_to_ts_pair in the future) */
  /* FIX: Security: Check that the TSs we receive from the peer are a subset of our offer */

  if(ts_me == NULL || ts_peer == NULL) {
    if(IKE_STATEM_IS_INITIATOR(session)) {
      ts_me = &tsi[ts];
      ts_peer = &tsr[ts];
    } else {
      ts_me = &tsr[ts];
      ts_peer = &tsi[ts];
    }
  }

#if !IKE_WITH_IEEE
  memcpy(&outgoing_sad_entry->peer, &session->peer, sizeof(uip_ip6addr_t));
  memcpy(&incoming_sad_entry->peer, &session->peer, sizeof(uip_ip6addr_t));

  outgoing_sad_entry->traffic_desc.peer_addr_from = outgoing_sad_entry->traffic_desc.peer_addr_to = &outgoing_sad_entry->peer;
  incoming_sad_entry->traffic_desc.peer_addr_from = incoming_sad_entry->traffic_desc.peer_addr_to = &incoming_sad_entry->peer;

  ts_pair_to_addr_set(&outgoing_sad_entry->traffic_desc, ts_me, ts_peer);
  ts_pair_to_addr_set(&incoming_sad_entry->traffic_desc, ts_me, ts_peer);

  IKE_PRINTF("SELECTED TRAFFIC SELECTORS index %hd:\n", ts);
  PRINTTSPAIR(ts_me, ts_peer);

  memcpy(&session->ephemeral_info->my_ts, ts_me, sizeof(ike_ts_t));
  memcpy(&session->ephemeral_info->peer_ts, ts_peer, sizeof(ike_ts_t));

#else
  memcpy(&outgoing_sad_entry->peer, &session->peer_lladdr, sizeof(uip_lladdr_t));
  memcpy(&incoming_sad_entry->peer, &session->peer_lladdr, sizeof(uip_lladdr_t));

  outgoing_sad_entry->traffic_desc.peer_lladdr_from = outgoing_sad_entry->traffic_desc.peer_lladdr_to = &outgoing_sad_entry->peer;
  incoming_sad_entry->traffic_desc.peer_lladdr_from = incoming_sad_entry->traffic_desc.peer_lladdr_to = &incoming_sad_entry->peer;

  IKE_PRINTF("SELECTED TRAFFIC SELECTORS index %hd:\n", ts);
  SAD_PRINTIEEEADDRSET(&outgoing_sad_entry->traffic_desc);

#endif

  session->incoming_entry = incoming_sad_entry;
  session->outgoing_entry = outgoing_sad_entry;

  /**
   * Get Child SA keying material as outlined in section 2.17
   *
   *     KEYMAT = prf+(SK_d, Ni | Nr)
   *
   */
  ike_statem_get_child_keymat(session, &incoming_sad_entry->sa, &outgoing_sad_entry->sa);

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  printf("Parsing and verification of IKE_AUTH SUCCESSFUL total time, %lu us\n", (uint32_t)((uint64_t)total_time * 1000000 / RTIMER_SECOND));
#endif
#endif

  IKE_PRINTF("===== Registered SAD entries =====\n");
#if WITH_IPSEC
  IKE_PRINTF("===== Outgoing IPsec Child SA =====\n");
  PRINTSADENTRY(outgoing_sad_entry);
  IKE_PRINTF("===== Incoming IPsec Child SA =====\n");
  PRINTSADENTRY(incoming_sad_entry);
#endif
#if IKE_WITH_RPL
  IKE_PRINTF("===== Outgoing RPL Child SA =====\n");
  PRINTRPLSADENTRY(outgoing_sad_entry);
  IKE_PRINTF("===== Incoming RPL Child SA =====\n");
  PRINTRPLSADENTRY(incoming_sad_entry);
#endif
#if IKE_WITH_IEEE
  IKE_PRINTF("===== Outgoing RPL Child SA =====\n");
  PRINTIEEESADENTRY(outgoing_sad_entry);
  IKE_PRINTF("===== Incoming RPL Child SA =====\n");
  PRINTIEEESADENTRY(incoming_sad_entry);
#endif
  IKE_PRINTF("========================================\n");

  return STATE_SUCCESS;

fail:
#if WITH_IPSEC
  sad_remove_outgoing_entry(outgoing_sad_entry);
  sad_remove_incoming_entry(incoming_sad_entry);
#endif
#if IKE_WITH_RPL
  rpl_sad_remove_outgoing_entry(outgoing_sad_entry);
  rpl_sad_remove_incoming_entry(incoming_sad_entry);
#endif
#if IKE_WITH_IEEE
  ieee_sad_remove_outgoing_entry(outgoing_sad_entry);
  ieee_sad_remove_incoming_entry(incoming_sad_entry);
#endif
memory_fail:
  ike_statem_send_single_notify(session, fail_notify_type);
#if IKE_IPSEC_INFO
  printf("Parsing of IKE_AUTH FAILURE\n");
#endif
  return STATE_FAILURE;
}
/*---------------------------------------------------------------------------*/
transition_return_t
ike_statem_send_auth_msg(ike_statem_session_t *session, payload_arg_t *payload_arg,
                         uint32_t child_sa_spi, const spd_proposal_tuple_t *sai2_offer,
                         const ipsec_addr_set_t *ts_instance_addr_set)
{
#if IKE_IPSEC_INFO
  printf("Generating IKE_AUTH message for session %p\n", session);
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
   * ID payload. We use the e-mail address type of ID
   */
  ike_payload_generic_hdr_t *id_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
  if(IKE_STATEM_IS_INITIATOR(session)) {
    ike_statem_set_id_payload(payload_arg, IKE_PAYLOAD_IDi);
  } else {
    ike_statem_set_id_payload(payload_arg, IKE_PAYLOAD_IDr);
  } ike_id_payload_t *id_payload = (ike_id_payload_t *)((uint8_t *)id_genpayloadhdr + sizeof(ike_payload_generic_hdr_t));

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

  /*
   * Write notification requesting the The peer's proposal was acceptedto create transport mode SAs
   */
  ike_statem_write_notification(payload_arg, SA_PROTO_IKE, 0, IKE_PAYLOAD_NOTIFY_USE_TRANSPORT_MODE, NULL, 0);

  /*
   * Write SAi2 (offer for the child SA)
   */
  ike_statem_write_sa_payload(payload_arg, sai2_offer, child_sa_spi);

  /*
   * The TS payload is decided by the triggering packet's header and the policy that applies to it
   *
   * Read more at "2.9.  Traffic Selector Negotiation" p. 40
   */
#if !IKE_WITH_IEEE
  IKE_PRINTF("Peer port 7890: %u\n", ts_instance_addr_set->peer_port_from);
  ike_statem_write_tsitsr(payload_arg, ts_instance_addr_set);
#else
  ike_statem_write_ieee_tsitsr(payload_arg, ts_instance_addr_set);
  memcpy(&session->peer_lladdr, &payload_arg->session->peer_lladdr, sizeof(uip_lladdr_t));
#endif

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  exec_time = RTIMER_NOW();
#endif
#endif

  /* Protect the SK payload. Write trailing fields. */
  ike_statem_finalize_sk(payload_arg, sk_genpayloadhdr, payload_arg->start - (((uint8_t *)sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t)));

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  printf("IKE_AUTH ENCR and INTEG, dh=%u, integ_algo=%u, encr_algo=%u, prf_algo=%u, %lu us\n",
         session->sa.dh, session->sa.integ, session->sa.encr, session->sa.prf,
         (uint32_t)((uint64_t)exec_time * 1000000 / RTIMER_SECOND));
  total_time += exec_time;
  printf("Generation of IKE_AUTH SUCCESSFUL total time(without IKE_SA_INIT and signed octets generation ), %lu us\n", (uint32_t)((uint64_t)total_time * 1000000 / RTIMER_SECOND));
#endif
#endif

  return uip_ntohl(((ike_payload_ike_hdr_t *)msg_buf)->len);   /* Return written length */
}
/*---------------------------------------------------------------------------*/
state_return_t
ike_statem_parse_sa_init_msg(ike_statem_session_t *session, ike_payload_ike_hdr_t *ike_hdr, spd_proposal_tuple_t *accepted_offer)
{
#if IKE_IPSEC_INFO
  printf("Generating IKE_SA_INIT message for session %p\n", session);
#if IPSEC_TIME_STATS
  rtimer_clock_t exec_time;
  rtimer_clock_t total_time;
  exec_time = RTIMER_NOW();
  total_time = 0;
#endif
#endif
  /* session->cookie_payload = NULL; // Reset the cookie data (if it has been used) */

  /* Store a copy of this first message from the peer for later use */
  /* in the autentication calculations. */
  COPY_FIRST_MSG(session, ike_hdr);

  /* We process the payloads one by one */
  uint8_t *peer_pub_key = NULL;
  uint16_t ke_dh_group = 0;  /* 0 is NONE according to IANA's IKE registry */
  uint8_t *ptr = msg_buf + sizeof(ike_payload_ike_hdr_t);
  uint8_t *end = msg_buf + uip_datalen();
  ike_payload_type_t payload_type = ike_hdr->next_payload;
  while(ptr < end) {  /* Payload loop */
    const ike_payload_generic_hdr_t *genpayloadhdr = (const ike_payload_generic_hdr_t *)ptr;
    const uint8_t *payload_start = (uint8_t *)genpayloadhdr + sizeof(ike_payload_generic_hdr_t);
    const uint8_t *payload_end = (uint8_t *)genpayloadhdr + uip_ntohs(genpayloadhdr->len);
    ike_payload_ke_t *ke_payload;
    ike_payload_cert_t *cert_req_payload;

    IKE_PRINTF("Next payload is %d\n", payload_type);
    switch(payload_type) {
      /*
         FIX: Cookies disabled as for now
         case IKE_PAYLOAD_N:
         ike_payload_notify_t *n_payload = (ike_payload_notify_t *) payload_start;
         // Now what starts with the letter C?
         if (n_payload->notify_msg_type == IKE_PAYLOAD_NOTIFY_COOKIE) {
         // C is for cookie, that's good enough for me
       */
      /**
       * Although the RFC doesn't explicitly state that the COOKIE -notification
       * is a solitary payload, I believe the discussion at p. 31 implies this.
       *
       * Re-transmit the IKE_SA_INIT message with the COOKIE notification as the first payload.
       */
      /*
         session->cookie_payload_ptr = genpayloadhdr; // genpayloadhdr points to the cookie data
         IKE_STATEM_TRANSITION(session);
         }
       */
    //  break;

    case IKE_PAYLOAD_SA:
      /* We expect this SA offer to a subset of ours */

      /* Loop over the responder's offer and that of ours in order to verify that the former */
      /* is indeed a subset of ours. */
      if(ike_statem_parse_sa_payload((spd_proposal_tuple_t *)CURRENT_IKE_PROPOSAL,
                                     (ike_payload_generic_hdr_t *)genpayloadhdr,
                                     ke_dh_group,
                                     &session->sa,
                                     NULL,
                                     accepted_offer)) {
        IKE_PRINTF(IPSEC_IKE "The peer's offer was unacceptable\n");
        return 0;
      }

      IKE_PRINTF(IPSEC_IKE "Peer proposal accepted\n");
      break;

    case IKE_PAYLOAD_NiNr:
      /* This is the responder's nonce */
      session->ephemeral_info->peernonce_len = payload_end - payload_start;
      memcpy(&session->ephemeral_info->peernonce, payload_start, session->ephemeral_info->peernonce_len);
      IKE_PRINTF(IPSEC_IKE "Parsed %u B long nonce from the peer\n", session->ephemeral_info->peernonce_len);
      IKE_MEMPRINT("Peer's nonce", session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
      break;

    case IKE_PAYLOAD_KE:
      /* This is the responder's public key */
      ke_payload = (ike_payload_ke_t *)payload_start;

      /**
       * Our approach to selecting the DH group in the SA proposal is a bit sketchy: We grab the first one that
       * fits with our offer. This will probably work in most cases, but not all:

           "The Diffie-Hellman Group Num identifies the Diffie-Hellman group in
           which the Key Exchange Data was computed (see Section 3.3.2).  This
           Diffie-Hellman Group Num MUST match a Diffie-Hellman group specified
           in a proposal in the SA payload that is sent in the same message, and
           SHOULD match the Diffie-Hellman group in the first group in the first
           proposal, if such exists."
                                                                        (p. 87)

          It might be so that the SA payload is positioned after the KE payload, and in that case we will adopt
          the group referred to in the KE payload as the responder's choice for the SA.

          (Yes, payloads might be positioned in any order, consider the following from page 30:

           "Although new payload types may be added in the future and may appear
           interleaved with the fields defined in this specification,
           implementations SHOULD send the payloads defined in this
           specification in the order shown in the figures in Sections 1 and 2;
           implementations MUST NOT reject as invalid a message with those
           payloads in any other order."

          )
       *
       */

      if(session->sa.dh == SA_UNASSIGNED_TYPE) {
        /* DH group not assigned because we've not yet processed the SA payload */
        /* Store a not of this for later SA processing. */
        ke_dh_group = uip_ntohs(ke_payload->dh_group_num);
        IKE_PRINTF(IPSEC_IKE "KE payload: Using group DH no. %u\n", ke_dh_group);
      } else {
        /* DH group has been assigned since we've already processed the SA */
        if(session->sa.dh != uip_ntohs(ke_payload->dh_group_num)) {
          IKE_PRINTF(IPSEC_IKE_ERROR "DH group of the accepted proposal doesn't match that of the KE's.\n");
          return 0;
        }
        IKE_PRINTF(IPSEC_IKE "KE payload: Using DH group no. %u\n", session->sa.dh);
      }

      /* Store the address to the beginning of the peer's public key */
      peer_pub_key = ((uint8_t *)ke_payload) + sizeof(ike_payload_ke_t);
      break;

    case IKE_PAYLOAD_N:
      if(ike_statem_handle_notify((ike_payload_notify_t *)payload_start, session)) {
        return 0;
      }
      break;

    case IKE_PAYLOAD_CERTREQ:
      /* Always check the certificate request payload */
      cert_req_payload = (ike_payload_cert_t *)payload_start;

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
            return 0;
          }
        } else {
          IKE_PRINTF("We do not support more than 1 certificate authority\n");
        }
      } else {
        IKE_PRINTF("WRONG CERTIFICATE ENCODING: We only support X.509 Signature encoding\n");
      } break;

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
        IKE_PRINTF(IPSEC_IKE "Error: Encountered an unknown critical payload\n");
        return 0;
      } else {
        IKE_PRINTF(IPSEC_IKE "Ignoring unknown non-critical payload of type %u\n", payload_type);
        /* Info: Ignored unknown payload */
      }
    } /* End payload switch */

    ptr = (uint8_t *)payload_end;
    payload_type = genpayloadhdr->next_payload;
  } /* End payload loop */

  if(payload_type != IKE_PAYLOAD_NO_NEXT) {
    IKE_PRINTF(IPSEC_IKE_ERROR "Unexpected end of peer's message.\n");
    return 0;
  }

  /**
   * Generate keying material for the IKE SA.
   * See section 2.14 "Generating Keying Material for the IKE SA"
   */
  ike_statem_get_ike_keymat(session, peer_pub_key);

#if WITH_IPSEC
  /* Set our child SPI. To be used during the AUTH exchange. */
  session->ephemeral_info->my_child_spi = SAD_GET_NEXT_SAD_LOCAL_SPI;
#endif

#if IKE_WITH_RPL
  /**
   * Assert that we recieved a RPL supported notify payload
   */
  if(!session->recieved_rpl_supported) {
    IKE_PRINTF(IPSEC_IKE_ERROR "Peer does not support RPL key management \n");
    return 0;
  }
#endif
#if IKE_WITH_IEEE
  /**
   * Assert that we recieved a IEEE 802.15.4 supported notify payload
   */
  if(!session->recieved_ieee_supported) {
    IKE_PRINTF(IPSEC_IKE_ERROR "Peer does not support IEEE 802.15.4 key management \n");
    return 0;
  }
#endif

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  printf("Parsing IKE_SA_INIT message SUCCESSFUL total time, %lu us\n", (uint32_t)((uint64_t)total_time * 1000000 / RTIMER_SECOND));
#endif
#endif
  return 1;
}
/*---------------------------------------------------------------------------*/
void
ike_statem_write_sa_payload(payload_arg_t *payload_arg, const spd_proposal_tuple_t *offer, uint32_t spi)
{
  /* Write the SA payload */
  ike_payload_generic_hdr_t *sa_genpayloadhdr = (ike_payload_generic_hdr_t *)payload_arg->start;
  SET_GENPAYLOADHDR(sa_genpayloadhdr, payload_arg, IKE_PAYLOAD_SA);

  /* Loop over the offers associated with this policy */
  uint8_t *ptr = payload_arg->start;
  uint8_t numtransforms = 0;

  ike_payload_transform_t *transform = NULL;
  ike_payload_proposal_t *proposal = NULL;
  uint8_t n = 0;
  uint8_t proposal_number = 1;
  do {  /* Loop over the offer's tuples */
    switch(offer[n].type) {

    case SA_CTRL_NEW_PROPOSAL:
    case SA_CTRL_END_OF_OFFER:

      /**
       * Before writing the new proposal we'll set the length of the last
       */
      if(proposal != NULL) {
        proposal->proposal_len = uip_htons(ptr - (uint8_t *)proposal);
        proposal->numtransforms = numtransforms;

        /* There's an invariant in spd.h stating that a proposal must contain at least one transforms. */
        /* Therefore, we assume that at least one transform has been written to the payload. */
        transform->last_more = IKE_PAYLOADFIELD_TRANSFORM_LAST;
      }

      if(offer[n].type == SA_CTRL_END_OF_OFFER) {
        break;
      }
      proposal = (ike_payload_proposal_t *)ptr;
      proposal->last_more = IKE_PAYLOADFIELD_PROPOSAL_MORE;
      proposal->clear = 0U;

      proposal->proposal_number = proposal_number;
      proposal->proto_id = offer[n].value;

      ++proposal_number;
      ptr += sizeof(ike_payload_proposal_t);

      /* There are some differences between the IKE protocol and the other ones */
      if(proposal->proto_id == SA_PROTO_IKE) {
        if(spi) {
          proposal->spi_size = 8;
          *((uint32_t *)ptr) = 0U;
          *((uint32_t *)ptr + 4) = spi;
          ptr += 8;
        } else {
          /* This case will occur whenever we negotiate the first IKE */
          /* p.79: "For an initial IKE SA negotiation, this field MUST be zero" */
          proposal->spi_size = 0U;
        } numtransforms = 0;
      } else { /* AH and ESP */
        proposal->spi_size = 4;
        *((uint32_t *)ptr) = spi;
        ptr += 4;

        /* We don't support ESNs. Start our offer with a plain no. */
        transform = (ike_payload_transform_t *)ptr;
        transform->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
        transform->type = SA_CTRL_TRANSFORM_TYPE_ESN;
        transform->clear1 = transform->clear2 = 0U;
        transform->len = uip_htons(sizeof(ike_payload_transform_t));
        transform->id = uip_htons(SA_ESN_NO);
        ptr += sizeof(ike_payload_transform_t);
        numtransforms = 1;
      }
      break;

    case SA_CTRL_TRANSFORM_TYPE_ENCR:     /* Encryption Algorithm (ESP, IKE) */
    case SA_CTRL_TRANSFORM_TYPE_PRF:      /* Pseudorandom function (IKE) */
    case SA_CTRL_TRANSFORM_TYPE_INTEG:    /* Integrity Algorithm (IKE, AH, ESP (optional)) */
    case SA_CTRL_TRANSFORM_TYPE_DH:       /* Diffie-Hellman group (IKE, AH (optional), ESP (optional)) */
      transform = (ike_payload_transform_t *)ptr;
      transform->last_more = IKE_PAYLOADFIELD_TRANSFORM_MORE;
      transform->type = offer[n].type;
      transform->clear1 = transform->clear2 = 0U;
      transform->id = uip_htons(offer[n].value);
      ptr += sizeof(ike_payload_transform_t);

      /* Loop over any attributes associated with this transform */
      /* Value type: Key length of encryption algorithm */
      uint8_t j = n + 1;
      while(offer[j].type == SA_CTRL_ATTRIBUTE_KEY_LEN) {
        /* The only attribute defined in RFC 5996 is Key Length (p. 84) */
        ike_payload_attribute_t *attrib = (ike_payload_attribute_t *)ptr;
        attrib->af_attribute_type = IKE_PAYLOADFIELD_ATTRIB_VAL;
        attrib->attribute_value = uip_htons(offer[j].value << 3); /* Multiply offer->value by 8 to make it into bits */

        ptr += sizeof(ike_payload_attribute_t);
        j++;
        n++;
      }

      transform->len = uip_htons(ptr - (uint8_t *)transform);
      ++numtransforms;
      break;

    default:
      IKE_PRINTF(IPSEC_IKE_ERROR "ike_statem_write_sa_payload: Unexpected SA_CTRL %u\n", offer[n - 1].type);
    } /* End switch (offer) */
  } while(offer[n++].type != SA_CTRL_END_OF_OFFER); /* End while (offer) */

  /* Set the length of the offer in the generic payload header and */
  /* mark the last proposal as the last. */
  proposal->last_more = IKE_PAYLOADFIELD_PROPOSAL_LAST;
  sa_genpayloadhdr->len = uip_htons(ptr - (uint8_t *)sa_genpayloadhdr);

  /* End of SA payload */
  payload_arg->start = ptr;
}
/*---------------------------------------------------------------------------*/
#if IKE_WITH_RPL
uint8_t
ike_statem_parse_rpl_sa_payload(const spd_proposal_tuple_t *my_offer,
                                ike_payload_generic_hdr_t *sa_payload_hdr,
                                rpl_sad_entry_t *sad_entry,
                                uint8_t proto,
                                spd_proposal_tuple_t *accepted_transform_subset)
{

#if IKE_WITH_RPL
  if(proto != SA_PROTO_RPL) {
    IKE_PRINTF(IPSEC_IKE "#1 Rejecting proposal, wrong protocol %u\n", proto);
    return 1;   /* Fail */
  }
#endif

  uint8_t required_transforms;

  /* Both RPL */
  required_transforms = 1; /* Integ, encr */

  uint8_t candidates[10];       /* 10 is arbitrary, but enough */
  uint8_t acc_proposal_ctr = 0;
  uint32_t candidate_spi = 0;
  
  acc_proposal_ctr = parse_peer_proposal(candidate_spi, accepted_transform_subset, 
          my_offer, proto, candidates, sizeof(candidates), sa_payload_hdr, 
          required_transforms, 0);
  if(!acc_proposal_ctr){
    return 1;
  } 
  
  //accepted_transform_subset[acc_proposal_ctr + 1].type = SA_CTRL_END_OF_OFFER;

  /* Set the SA */
  sad_entry->sa.proto = proto;
  sad_entry->sa.encr = candidates[SA_CTRL_TRANSFORM_TYPE_ENCR];
  sad_entry->sa.integ = candidates[SA_CTRL_TRANSFORM_TYPE_INTEG];
#if IKE_WITH_RPL
  if(proto == SA_PROTO_RPL) {
    sad_entry->sa.encr_keylen = get_encr_rpl_keymat_len(candidates[SA_CTRL_TRANSFORM_TYPE_ENCR]);
  }
  if(sad_entry->sa.encr != 0) {
    sad_entry->LVL = get_rpl_lvl_from_transform(sad_entry->sa.encr);
  } else {
    sad_entry->LVL = get_rpl_lvl_from_transform(sad_entry->sa.integ);
  }
#endif
#if IKE_WITH_IEEE
  if(proto == SA_PROTO_IEEE_802_15_4) {
    sad_entry->sa.encr_keylen = get_encr_ieee_keymat_len(candidates[SA_CTRL_TRANSFORM_TYPE_ENCR]);
  }
#endif

  return 0;   /* Success */
}
#endif
/*---------------------------------------------------------------------------*/
#if IKE_WITH_IEEE
uint8_t
ike_statem_parse_ieee_sa_payload(const spd_proposal_tuple_t *my_offer,
                                 ike_payload_generic_hdr_t *sa_payload_hdr,
                                 ieee_sad_entry_t *sad_entry,
                                 uint8_t proto,
                                 spd_proposal_tuple_t *accepted_transform_subset)
{

  if(proto != SA_PROTO_IEEE_802_15_4) {
    printf(IPSEC_IKE "#1 Rejecting proposal, wrong protocol %u\n", proto);
    return 1;   /* Fail */
  }
  IKE_PRINTF("In parse_ieee_sa_payload\n");
  uint8_t required_transforms;

  /* IEEE 802.15.4 requires only one transform */
  required_transforms = 1; /* Integ, encr */

  uint8_t candidates[10];       /* 10 is arbitrary, but enough */
  uint8_t acc_proposal_ctr = 0;
  uint32_t candidate_spi = 0;
  
  acc_proposal_ctr = parse_peer_proposal(candidate_spi, accepted_transform_subset, 
          my_offer, proto, candidates, sizeof(candidates), sa_payload_hdr, 
          required_transforms, 0);
  if(!acc_proposal_ctr){
    return 1;
  } 
  
  printf("acc_proposal_ctr %u\n",acc_proposal_ctr);
  //accepted_transform_subset[acc_proposal_ctr + 1].type = SA_CTRL_END_OF_OFFER;

  /* Set the SA */
  sad_entry->sa.proto = proto;
  sad_entry->sa.encr = candidates[SA_CTRL_TRANSFORM_TYPE_ENCR];
  sad_entry->sa.integ = candidates[SA_CTRL_TRANSFORM_TYPE_INTEG];
  sad_entry->sa.encr_keylen = get_encr_ieee_keymat_len(candidates[SA_CTRL_TRANSFORM_TYPE_ENCR]);

  if(sad_entry->sa.encr != 0) {
    sad_entry->LVL = get_ieee_lvl_from_transform(sad_entry->sa.encr);
  } else {
    sad_entry->LVL = get_ieee_lvl_from_transform(sad_entry->sa.integ);
  }

  return 0;   /* Success */
}
#endif
/*---------------------------------------------------------------------------*/
uint8_t
parse_peer_proposal(uint32_t candidate_spi, spd_proposal_tuple_t *accepted_transform_subset, 
        const spd_proposal_tuple_t *my_offer, uint8_t proto, uint8_t *candidates, 
        uint16_t candidate_size, ike_payload_generic_hdr_t *sa_payload_hdr, 
        uint8_t required_transforms, uint8_t ke_dh_group)

{ 
  printf("parse_peer_proposal\n");
  uint8_t candidate_keylen = 0;
  uint8_t acc_proposal_ctr = 0;

  ike_payload_proposal_t *peerproposal = (ike_payload_proposal_t *)(((uint8_t *)sa_payload_hdr) + sizeof(ike_payload_generic_hdr_t));

  
  /* (#1) Loop over the proposals in the peer's offer */
  while((uint8_t *)peerproposal < ((uint8_t *)sa_payload_hdr) + uip_ntohs(sa_payload_hdr->len)) {

    if(proto == SA_PROTO_IKE && (peerproposal->proto_id != proto || peerproposal->spi_size != 0)) {
      printf(IPSEC_IKE "#1 Rejecting proposal, does not have the correct protocol\n");
      goto next_peerproposal;
    }
    if(proto != SA_PROTO_IKE && (peerproposal->proto_id != proto || peerproposal->spi_size != 4)) {
      printf(IPSEC_IKE "#1 Rejecting proposal, does not have the correct protocol\n");
      goto next_peerproposal;
    }

    candidate_spi = *((uint32_t *)(((uint8_t *)peerproposal) + sizeof(ike_payload_proposal_t)));

    const spd_proposal_tuple_t *mytuple = my_offer;
    accepted_transform_subset[0].type = SA_CTRL_NEW_PROPOSAL;
    accepted_transform_subset[0].value = proto;

    /* (#2) Loop over my proposals and see if any of them is a superset of this peer's current proposal */
    while(mytuple->type != SA_CTRL_END_OF_OFFER) {
      /* We're now at the beginning of one of our offers. */

      ++mytuple; /* Jump the SA_CTRL_NEW_PROPOSAL */
      memset(candidates, 0, candidate_size);
      uint8_t accepted_transforms = 0;  /* Number of accepted transforms */
      acc_proposal_ctr = 0;

      /* (#3) Loop over this proposal in my offer */
      while(mytuple->type != SA_CTRL_END_OF_OFFER && mytuple->type != SA_CTRL_NEW_PROPOSAL) {
        /* Does this transform have an attribute? */

        IKE_PRINTF(IPSEC_IKE "\n#3 Looking at mytuple->type %u mytuple->value %u\n", mytuple->type, mytuple->value);
        uint8_t my_keylen = 0;
        if((mytuple + 1)->type == SA_CTRL_ATTRIBUTE_KEY_LEN) {
          my_keylen = (mytuple + 1)->type;
        }
        ike_payload_transform_t *peertransform = (ike_payload_transform_t *)((uint8_t *)peerproposal + sizeof(ike_payload_proposal_t) + peerproposal->spi_size);

        /* (#4) Loop over the peer's proposal and see if this transform of mine can be found */
        while((uint8_t *)peertransform < (uint8_t *)peerproposal + uip_ntohs(peerproposal->proposal_len)) {
          IKE_PRINTF("candidates[...]: %u, peertransform->type: %u == %u,peertransform->id: %u == %u\n ",candidates[peertransform->type], peertransform->type,mytuple->type, uip_ntohs(peertransform->id),mytuple->value);
          
          /* Is this is DH group transform; if so, is acceptable with our requirements? */
          if(ke_dh_group &&
             peertransform->type == SA_CTRL_TRANSFORM_TYPE_DH &&
             uip_ntohs(peertransform->id) != ke_dh_group) {
            IKE_PRINTF(IPSEC_IKE "#4 Peer proposal with DH group that differs from that of the KE payload. Rejecting.\n");
            goto next_peertransform;
          }

          /* Check for extended sequence number */
          if(peertransform->type == SA_CTRL_TRANSFORM_TYPE_ESN && uip_ntohs(peertransform->id) != SA_ESN_NO) {
            IKE_PRINTF(IPSEC_IKE "#4 Peer proposal using extended sequence number found. Rejecting.\n");
            goto next_peertransform;
          }
          
          if(!candidates[peertransform->type] &&                  /* (that we haven't accepted a transform of this type!) */
             peertransform->type == mytuple->type &&
             uip_ntohs(peertransform->id) == mytuple->value) {

            /* Peer and I have the same type and value */
            if(my_keylen) {
              /* I have a keylen requirement. Does it fit that of the peer? */
              if(uip_ntohs(peertransform->len) != sizeof(ike_payload_transform_t)) {
                /* The peer have included an attribtue as well */
                ike_payload_attribute_t *peer_attrib = (ike_payload_attribute_t *)((uint8_t *)peertransform + sizeof(ike_payload_transform_t));

                if(uip_ntohs(peer_attrib->af_attribute_type) != UIP_HTONS(IKE_PAYLOADFIELD_ATTRIB_VAL)) {
                  IKE_PRINTF(IPSEC_IKE "#4 Error: Unrecognized attribute type: %x (UIP_HTONS(IKE_PAYLOADFIELD_ATTRIB_VAL): %x)\n", uip_ntohs(peer_attrib->af_attribute_type), UIP_HTONS(IKE_PAYLOADFIELD_ATTRIB_VAL));
                  goto next_peertransform;
                } else {
                  /* This is a keylen attribute */
                  if(uip_ntohs(peer_attrib->attribute_value) < my_keylen) {
                    /* The peer requested a shorter key length. We cannot accept this transform! */
                    goto next_peertransform;
                    /* Accept the candidate keylen (which might be longer than the one in our proposal) */
                  }
                  candidate_keylen = uip_ntohs(peer_attrib->attribute_value) >> 3;  /* Divide by eight */
                }
              } else {
                goto next_peertransform;
              }
            }
            /* We end up here if we've accepted the transform */
            /* Add the transform to the resulting output offer */
            ++acc_proposal_ctr;
            memcpy(&accepted_transform_subset[acc_proposal_ctr], mytuple, sizeof(spd_proposal_tuple_t));
            if(candidate_keylen && mytuple->type == SA_CTRL_TRANSFORM_TYPE_ENCR) {
              if(acc_proposal_ctr >= IKE_REPLY_MAX_PROPOSAL_TUPLES) {
                IKE_PRINTF("IKE_REPLY_MAX_PROPOSAL_TUPLES\n");
                return 0;
              }
              accepted_transform_subset[++acc_proposal_ctr].type = SA_CTRL_ATTRIBUTE_KEY_LEN;
              accepted_transform_subset[acc_proposal_ctr].value = candidate_keylen;
            }

            /* Set the SA */
            candidates[mytuple->type] = mytuple->value;
            ++accepted_transforms;
            
            /* From RFC5282:
             * This document updates [RFC4306] to require that when an
             * authenticated encryption algorithm is selected as the
             * encryption algorithm for any SA (IKE or ESP), an integrity
             * algorithm MUST NOT be selected for that SA.  This document
             * further updates [RFC4306] to require that if all of the
             * encryption algorithms in any proposal are authenticated
             * encryption algorithms, then the proposal MUST NOT propose
             * any integrity transforms.
             *
             */
            if((mytuple->value == SA_ENCR_AES_CCM_8)
               || (mytuple->value == SA_ENCR_AES_CCM_12)
               || (mytuple->value == SA_ENCR_AES_CCM_16)) {
              ++accepted_transforms; /* count as two */
            }
            
            if(accepted_transforms == required_transforms) {
              IKE_PRINTF("found acceptable_proposal\n");
              IKE_PRINTF("acc_proposal_ctr %u\n",acc_proposal_ctr);
              accepted_transform_subset[acc_proposal_ctr + 1].type = SA_CTRL_END_OF_OFFER;
              return acc_proposal_ctr;
              //goto found_acceptable_proposal;
            }
          }

          /* Forward to the next transform (jumping any attributes) */
next_peertransform:
          IKE_PRINTF("next_peertransform\n");
          peertransform = (ike_payload_transform_t *)(((uint8_t *)peertransform) + uip_ntohs(peertransform->len));
        } /* End #4 */

        if(my_keylen) {
          mytuple += 2;
        } else {
          ++mytuple;
        }
      } /* End #3 */
    }

  /**
   * If we end here we did so because this proposal from the peer didn't match any of ours
   * Go to the next proposal
   */
next_peerproposal:
      peerproposal = (ike_payload_proposal_t *)(((uint8_t *)peerproposal) + uip_ntohs(peerproposal->proposal_len));
  }
    /* We didn't find an acceptable proposal. Leave. */
  IKE_PRINTF("no acceptable proposal\n");

  return 0; /* Fail */  
}
/*---------------------------------------------------------------------------*/
uint8_t
ike_statem_parse_sa_payload(const spd_proposal_tuple_t *my_offer,
                            ike_payload_generic_hdr_t *sa_payload_hdr,
                            uint8_t ke_dh_group,
                            sa_ike_t *ike_sa,
                            sad_entry_t *sad_entry,
                            spd_proposal_tuple_t *accepted_transform_subset)
{

  uint8_t ike = (ike_sa != NULL);
  uint8_t required_transforms;
  uint8_t proto = 0;
  
  if(ike) {
    required_transforms = 4; /* Integ, encr, dh, prf */
    proto = SA_PROTO_IKE;
  } else {
    required_transforms = 2; /* Integ, encr */
    proto = SA_PROTO_ESP;
  } 
  
  uint8_t candidates[10];       /* 10 is arbitrary, but enough */
  uint8_t acc_proposal_ctr = 0;
  uint32_t candidate_spi = 0;
  
  acc_proposal_ctr = parse_peer_proposal(candidate_spi, accepted_transform_subset, 
          my_offer, proto, candidates, sizeof(candidates), sa_payload_hdr, 
          required_transforms, ke_dh_group);
  if(!acc_proposal_ctr){
    IKE_PRINTF("NO acceptable proposal\n");
    return 1;
  } 
  

  uint8_t i;
  uint8_t candidate_keylen = 0;
  
  for(i=0; i <= acc_proposal_ctr;i++){
    if(accepted_transform_subset[i].type == SA_CTRL_ATTRIBUTE_KEY_LEN){
      candidate_keylen = accepted_transform_subset[i].value;
    }
  }

  /* Set the SA */
  if(ike) {
    ike_sa->encr = candidates[SA_CTRL_TRANSFORM_TYPE_ENCR];
    ike_sa->encr_keylen = candidate_keylen;
    ike_sa->integ = candidates[SA_CTRL_TRANSFORM_TYPE_INTEG];
    ike_sa->prf = candidates[SA_CTRL_TRANSFORM_TYPE_PRF];
    ike_sa->dh = candidates[SA_CTRL_TRANSFORM_TYPE_DH];
  } else {
    ike_payload_proposal_t *peerproposal = (ike_payload_proposal_t *)(((uint8_t *)sa_payload_hdr) + sizeof(ike_payload_generic_hdr_t));
    candidate_spi = *((uint32_t *)(((uint8_t *)peerproposal) + sizeof(ike_payload_proposal_t)));

    sad_entry->spi = candidate_spi;
    sad_entry->sa.proto = SA_PROTO_ESP;
    sad_entry->sa.encr = candidates[SA_CTRL_TRANSFORM_TYPE_ENCR];
    sad_entry->sa.encr_keylen = candidate_keylen;
    sad_entry->sa.integ = candidates[SA_CTRL_TRANSFORM_TYPE_INTEG];
    
  }

  return 0; /* Success */
}
/*---------------------------------------------------------------------------*/
/**
 * Helper for ike_statem_get_authdata
 */
uint32_t
rerun_init_msg(uint8_t *out, uint8_t initreq, ike_statem_session_t *session)
{
  /* Stash the current state */
  /* Stash peer SPI */
  uint32_t peer_spi_high = session->peer_spi_high;
  uint32_t peer_spi_low = session->peer_spi_low;

  if(initreq) {
    session->peer_spi_high = 0;
    session->peer_spi_low = 0;
  }

  /* Stash my msg ID */
  uint32_t my_msg_id = session->my_msg_id;

  session->my_msg_id = 0;

  /* Buffers */
  uint8_t *msg_buf_save = msg_buf;  /* ike_statem_trans_initreq() writes to the address of msg_buf */
  msg_buf = out;
  if(initreq) {
    ike_statem_trans_initreq(session);  /* Re-write our first message to assembly_start */
  } else {
    ike_statem_trans_initresp(session);
    /**
     * Restore old state
     */
  } 
  msg_buf = msg_buf_save;
  session->peer_spi_high = peer_spi_high;
  session->peer_spi_low = peer_spi_low;
  session->my_msg_id = my_msg_id;

  return uip_ntohl(((ike_payload_ike_hdr_t *)out)->len);
}
/*---------------------------------------------------------------------------*/
uint16_t
ike_statem_get_authdata(ike_statem_session_t *session, const uint8_t myauth, uint8_t *out, ike_id_payload_t *id_payload, uint16_t id_payload_len)
{
#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  rtimer_clock_t exec_time;
  rtimer_clock_t total_time;
  exec_time = RTIMER_NOW();
  total_time = 0;
#endif
#endif

  uint8_t *ptr = out;
  IKE_PRINTF("ptr: %p\n", out);

  /**
   * There are four types of SignedOctets -strings that can be created:
   *   0. We are the responder, and we recreate the peer's InitiatorSignedOctets
   *   1. We are the responder, and we create our ResponderSignedOctets
   *   2. We are the initiator, and we recreate the peer's ResponderSignedOctets
   *   3. We are the initiator, and we create our InitiatorSignedOctets
   *
   */
  uint8_t type = 2 * (IKE_STATEM_IS_INITIATOR(session) > 0) + myauth;
  IKE_PRINTF("Type is %u, initiator: %u\n", type, IKE_STATEM_IS_INITIATOR(session));

  /* Pack RealMessage* */
  IKE_PRINTF("RealMessage1: ");

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  /* Stopping timer to skip printouts in IKE_SA_INIT */
#endif
#endif

  switch(type) {
  case 0:
    IKE_PRINTF("Using peer_first_msg, len %u\n", session->ephemeral_info->peer_first_msg_len);
    IKE_PRINTF("ptr: %p\n", ptr);
    memcpy(ptr, session->ephemeral_info->peer_first_msg, session->ephemeral_info->peer_first_msg_len);
    ptr = ptr + session->ephemeral_info->peer_first_msg_len;
    IKE_PRINTF("ptr: %p\n", ptr);
    break;

  case 1:
    IKE_PRINTF("Re-running our first message's transition\n");
    ptr += rerun_init_msg(ptr, 0, session);
    break;

  case 2:
    IKE_PRINTF("Using peer_first_msg\n");
    memcpy(ptr, session->ephemeral_info->peer_first_msg, session->ephemeral_info->peer_first_msg_len);
    ptr += session->ephemeral_info->peer_first_msg_len;
    break;

  case 3:
    IKE_PRINTF("Re-running our first message's transition\n");
    ptr += rerun_init_msg(ptr, 1, session);
  }
  IKE_PRINTF("ptr: %p\n", ptr);

#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW();
#endif
#endif

  /* Nonce(I/R)Datatop */
  IKE_PRINTF("Inserting Nonce for signed octets\n");
  if(myauth != 0) {
    memcpy(ptr, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
    ptr += session->ephemeral_info->peernonce_len;
  } else {
    memcpy(ptr, &session->ephemeral_info->my_nounce, IKE_PAYLOAD_MYNONCE_LEN);
    ptr += IKE_PAYLOAD_MYNONCE_LEN;
  }

  /* MACedIDForI ( prf(SK_pi, IDType | RESERVED | InitIDData) = prf(SK_pi, RestOfInitIDPayload) ) */
  prf_data_t prf_data =
  {
    .out = ptr,
    .keylen = SA_PRF_PREFERRED_KEYMATLEN(session), /* SK_px is always of the PRF's preferred keymat length */
    .data = (uint8_t *)id_payload,
    .datalen = id_payload_len
  };

  IKE_MEMPRINT("id_payload", (uint8_t *)id_payload, id_payload_len);

  /*
     0:pr
     1:pi
     2:pi
     3:pr
   */
  if(type % 3) {
    prf_data.key = session->ephemeral_info->sk_pr;
    IKE_MEMPRINT("Using key sk_pr", (uint8_t *)prf_data.key, prf_data.keylen);
  } else {
    prf_data.key = session->ephemeral_info->sk_pi;
    IKE_MEMPRINT("Using key sk_pi", (uint8_t *)prf_data.key, prf_data.keylen);
  }

  prf(session->sa.prf, &prf_data);
  ptr += SA_PRF_PREFERRED_KEYMATLEN(session);

  IKE_MEMPRINT("*SignedOctets", out, ptr - out);
#if IKE_IPSEC_INFO
#if IPSEC_TIME_STATS
  exec_time = RTIMER_NOW() - exec_time;
  total_time += exec_time;
  printf("Generation of signed octets, %lu us\n", (uint32_t)((uint64_t)total_time * 1000000 / RTIMER_SECOND));
#endif
#endif
  return ptr - out;
}
/*---------------------------------------------------------------------------*/
uint8_t
ike_statem_unpack_sk(ike_statem_session_t *session, ike_payload_generic_hdr_t *sk_genpayloadhdr)
{
  uint8_t icv_length = SA_INTEG_ICV_LEN(session);
  uint16_t integ_datalen = uip_ntohl(((ike_payload_ike_hdr_t *)msg_buf)->len) - icv_length;
  uint8_t trailing_bytes = 0;

  /* Find the ICV length if CCM is used */
  uint8_t encr_icv_length = SA_ENCR_ICV_LEN(session);

  uint8_t expected_icv[((encr_icv_length) > 0 ? encr_icv_length : icv_length)];

  /* Integrity */
  if(session->sa.integ) {
    /* Length of data to be integrity protected: */
    /* IKE header + (anything in between) + SK header + IV + data + padding + padding length field */

    integ_data_t integ_data = {
      .type = session->sa.integ,
      .data = msg_buf,          /* The start of the data */
      .datalen = integ_datalen, /* Data to be integrity protected */
      .out = expected_icv       /* Where the output will be written. IPSEC_ICVLEN bytes will be written. */
    };

    if(IKE_STATEM_IS_INITIATOR(session)) {
      integ_data.keymat = session->sa.sk_ar;                /* Address of the keying material */
    } else {
      integ_data.keymat = session->sa.sk_ai;
      /* IKE_MEMPRINT("integ keymat", integ_data.keymat, 20); */
    } 
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
    .type = session->sa.encr,
    .keylen = session->sa.encr_keylen,
    .encr_data = ((uint8_t *)sk_genpayloadhdr) + sizeof(ike_payload_generic_hdr_t),
    /* From the beginning of the IV to the pad length field */
    .encr_datalen = datalen,
    .ip_next_hdr = NULL
  };
  if(IKE_STATEM_IS_INITIATOR(session)) {
    encr_data.keymat = session->sa.sk_er;                /* Address of the keying material */
  } else {
    encr_data.keymat = session->sa.sk_ei;
  } if(encr_icv_length) {
    encr_data.integ_data = msg_buf;
    encr_data.icv = expected_icv;

  }


  espsk_unpack(&encr_data); /* Encrypt / combined mode */

  if(encr_icv_length) {
    if(memcmp(expected_icv, msg_buf + integ_datalen - encr_icv_length, encr_icv_length) != 0) {
      IKE_PRINTF("Expected ICV does not match message after encryption\n");
      return 0;
    }
    /* Move the data over the IV as the former's length might not be a multiple of four */
  }
  uint8_t *iv_start = (uint8_t *)sk_genpayloadhdr + sizeof(ike_payload_generic_hdr_t);

  memmove(iv_start, iv_start + sa_encr_ivlen[session->sa.encr], datalen);
  sk_genpayloadhdr->len = uip_htons(sizeof(ike_payload_generic_hdr_t));

  /* Adjust trailing bytes */
  /*                IV length                       + padding         + pad length field */
  trailing_bytes += sa_encr_ivlen[session->sa.encr] + encr_data.padlen + 1;

  trailing_bytes += encr_icv_length;

  return trailing_bytes;
}
/*---------------------------------------------------------------------------*/
void
ike_statem_prepare_sk(payload_arg_t *payload_arg)
{
  ike_payload_generic_hdr_t *sk_genpayloadhdr;
  SET_GENPAYLOADHDR(sk_genpayloadhdr, payload_arg, IKE_PAYLOAD_SK);

  /* Generate the IV */
  uint8_t n;
  for(n = 0; n < SA_ENCR_CURRENT_IVLEN(payload_arg->session); ++n) {
    payload_arg->start[n] = rand16();
  }
  payload_arg->start += n;
}
/*---------------------------------------------------------------------------*/
void
ike_statem_finalize_sk(payload_arg_t *payload_arg, ike_payload_generic_hdr_t *sk_genpayloadhdr, uint16_t data_len)
{
  IKE_PRINTF("msg_buf: %p\n", msg_buf);
  /*
   * Before calculating the ICV value we need to set the final length
   * of the IKE message and the SK payload
   */
  SET_NO_NEXT_PAYLOAD(payload_arg);

  uint8_t encr_icvlen = SA_ENCR_ICV_LEN_BY_TYPE(payload_arg->session->sa.encr);

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
    .type = payload_arg->session->sa.encr,
    .keylen = payload_arg->session->sa.encr_keylen,
    .integ_data = msg_buf,                    /* Beginning of the ESP header (ESP) or the IKEv2 header (SK) */
    .encr_data = (uint8_t *)sk_genpayloadhdr + sizeof(ike_payload_generic_hdr_t),
    .encr_datalen = data_len,                 /* From the beginning of the IV to the IP next header field (ESP) or the padding field (SK). */
    .ip_next_hdr = NULL
  };

  if(IKE_STATEM_IS_INITIATOR(payload_arg->session)) {
    encr_data.keymat = payload_arg->session->sa.sk_ei;
  } else {
    encr_data.keymat = payload_arg->session->sa.sk_er;                /* Address of the keying material */
  } 


  IKE_PRINTF("encr: %u\n", encr_data.type);
  IKE_MEMPRINT("encr_key", encr_data.keymat, encr_data.keylen);

  espsk_pack(&encr_data); /* Encrypt / combined mode */

  /* Integrity */
  if(payload_arg->session->sa.integ) {
    uint8_t icvlen = SA_INTEG_ICV_LEN_BY_TYPE(payload_arg->session->sa.integ);

    /* sk_len = ike_payload_generic_hdr_t size + ICV and data + pad length + pad length field + IPSEC_ICVLEN */
    sk_len = sizeof(ike_payload_generic_hdr_t) + data_len + encr_data.padlen + 1 + icvlen + encr_icvlen;
    sk_genpayloadhdr->len = uip_htons(sk_len);
    payload_arg->start = ((uint8_t *)sk_genpayloadhdr) + sk_len;
    msg_len = payload_arg->start - msg_buf;
    IKE_PRINTF("msg_len: %u\n", msg_len);
    ((ike_payload_ike_hdr_t *)msg_buf)->len = uip_htonl(msg_len);
    IKE_PRINTF("sk_genpayloadhdr->len: %u data_len: %u\n", uip_ntohs(sk_genpayloadhdr->len), data_len);

    /* Length of data to be integrity protected: */
    /* IKE header + (anything in between) + SK header + IV + data + padding + padding length field */
    uint16_t integ_datalen = msg_len - icvlen;

    integ_data_t integ_data = {
      .type = payload_arg->session->sa.integ,
      .data = msg_buf,                        /* The start of the data */
      .datalen = integ_datalen,               /* Data to be integrity protected */
      .out = msg_buf + integ_datalen          /* Where the output will be written. IPSEC_ICVLEN bytes will be written. */
    };
    IKE_PRINTF("msg_buf: %p\n", msg_buf);
    IKE_PRINTF("integ_data.out: %p\n", integ_data.out);

    if(IKE_STATEM_IS_INITIATOR(payload_arg->session)) {
      integ_data.keymat = payload_arg->session->sa.sk_ai;
    } else {
      integ_data.keymat = payload_arg->session->sa.sk_ar;                /* Address of the keying material */
    } 
    IKE_MEMPRINT("integ keymat", integ_data.keymat, SA_INTEG_CURRENT_KEYMATLEN(payload_arg->session));
    integ(&integ_data);                      /* This will write Encrypted Payloads, padding and pad length */
  }
}
/*---------------------------------------------------------------------------*/
void
ike_statem_set_id_payload(payload_arg_t *payload_arg, ike_payload_type_t payload_type)
{
  ike_payload_generic_hdr_t *id_genpayloadhdr;
  SET_GENPAYLOADHDR(id_genpayloadhdr, payload_arg, payload_type);

  ike_id_payload_t *id_payload = (ike_id_payload_t *)payload_arg->start;
  /* Clear the RESERVED area */
  *((uint32_t *)id_payload) = 0;
#if WITH_CONF_IKE_CERT_AUTH
  *((uint8_t *)id_payload) = IKE_ID_DER_ASN1_DN;
#else
  *((uint8_t *)id_payload) = IKE_ID_RFC822_ADDR;
#endif

  payload_arg->start += sizeof(ike_id_payload_t);

#if WITH_CONF_IKE_CERT_AUTH
  dtls_certificate_context_t cert;

  /* We need to parse the certificate to know the start of the subject that is
     used as an identifier when certificate authentication is used */
  load_certificate(&cert);

  /* We need the subject in X.509 encoding and the sequence starts 2 bytes before
     the subject in the certificate */
  memcpy(payload_arg->start, (uint8_t *)cert.subject - 2, cert.subject_len + 2);
  payload_arg->start += cert.subject_len + 2;
#else
  memcpy(payload_arg->start, (uint8_t *)ike_id, sizeof(ike_id));
  //printf("The id is %d. \n", payload_arg->start);
  payload_arg->start += sizeof(ike_id);
#endif
  id_genpayloadhdr->len = uip_htons(payload_arg->start - (uint8_t *)id_genpayloadhdr);
}
/*---------------------------------------------------------------------------*/
uint8_t
ike_statem_handle_notify(ike_payload_notify_t *notify_payload, ike_statem_session_t *session)
{
  notify_msg_type_t type = uip_ntohs(notify_payload->notify_msg_type);

  /**
   * See payload.h for a complete list of notify message types
   */
  if(type < IKE_PAYLOAD_NOTIFY_INITIAL_CONTACT) {
    switch(type) {
    /*
       IKE_PAYLOAD_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD = 1,
       IKE_PAYLOAD_NOTIFY_INVALID_IKE_SPI = 4,
       IKE_PAYLOAD_NOTIFY_INVALID_MAJOR_VERSION = 5,
     */
    case IKE_PAYLOAD_NOTIFY_INVALID_SYNTAX:
      IKE_PRINTF(IPSEC_IKE_ERROR "Peer didn't recognize our message's syntax\n");
      break;

    case IKE_PAYLOAD_NOTIFY_INVALID_MESSAGE_ID:
      IKE_PRINTF(IPSEC_IKE_ERROR "Peer believes our message's ID is incorrect\n");
      break;

    /* IKE_PAYLOAD_NOTIFY_INVALID_SPI = 11, */
    case IKE_PAYLOAD_NOTIFY_NO_PROPOSAL_CHOSEN:
      IKE_PRINTF(IPSEC_IKE_ERROR "Peer didn't not accept any of our proposals\n");
      break;

    case IKE_PAYLOAD_NOTIFY_INVALID_KE_PAYLOAD:
      IKE_PRINTF(IPSEC_IKE_ERROR "Peer found our KE payload (public key) to be invalid\n");
      break;

    case IKE_PAYLOAD_NOTIFY_AUTHENTICATION_FAILED:
      IKE_PRINTF(IPSEC_IKE_ERROR "Peer could not authenticate us.\n");
      break;

    case IKE_PAYLOAD_NOTIFY_MEMBER_AUTHORIZATION_FAILED:
      IKE_PRINTF(IPSEC_IKE_ERROR "Candidate member is not authorized or the requested group does not exist.\n");
      break;

    case IKE_PAYLOAD_NOTIFY_SINGLE_PAIR_REQUIRED:
      IKE_PRINTF("Peer requires a single pair of Traffic Selectors\n");
      break;

    /*
       IKE_PAYLOAD_NOTIFY_NO_ADDITIONAL_SAS = 35,
       IKE_PAYLOAD_NOTIFY_INTERNAL_ADDRESS_FAILURE = 36,
       IKE_PAYLOAD_NOTIFY_FAILED_CP_REQUIRED = 37,
     */

    case IKE_PAYLOAD_NOTIFY_TS_UNACCEPTABLE:
      IKE_PRINTF(IPSEC_IKE_ERROR "Peer found our Traffic Selectors to be unacceptable\n");
      break;

    case IKE_PAYLOAD_NOTIFY_INVALID_SELECTORS:
      IKE_PRINTF(IPSEC_IKE_ERROR "Peer found or Traffic Selectors to be invalid.\n");
      break;

    default:
      IKE_PRINTF(IPSEC_IKE_ERROR "Received error notify message of type no. %u\n", type);
    }
    return 1;
  } else {
    /* Informational types */

    /*
       IKE_PAYLOAD_NOTIFY_TEMPORARY_FAILURE = 43,
       IKE_PAYLOAD_NOTIFY_CHILD_SA_NOT_FOUND = 44,
     */
    switch(type) {
    /*
       IKE_PAYLOAD_NOTIFY_INITIAL_CONTACT = 16384,
       IKE_PAYLOAD_NOTIFY_SET_WINDOW_SIZE = 16385,
       IKE_PAYLOAD_NOTIFY_ADDITIONAL_TS_POSSIBLE = 16386,
       IKE_PAYLOAD_NOTIFY_IPCOMP_SUPPORTED = 16387,
       IKE_PAYLOAD_NOTIFY_NAT_DETECTION_SOURCE_IP = 16388,
       IKE_PAYLOAD_NOTIFY_NAT_DETECTION_DESTINATION_IP = 16389,
     */

    case IKE_PAYLOAD_NOTIFY_COOKIE:
      IKE_PRINTF(IPSEC_IKE_ERROR "Peer has handed us a cookie and expects us to use it, but we can't handle cookies\n");
      return 1;

    case IKE_PAYLOAD_NOTIFY_USE_TRANSPORT_MODE:
      IKE_PRINTF(IPSEC_IKE "Peer demands child SAs to use transport, not tunnel mode\n");
      break;
#if IKE_WITH_RPL
    /* We only process the RPL supported notify message if IKE is configured to do so */
    case IKE_PAYLOAD_NOTIFY_RPL_SUPPORTED:
      IKE_PRINTF(IPSEC_IKE "Received a RPL SUPPORTED Notify payload\n");
      session->recieved_rpl_supported = 1;
      break;
#endif
#if IKE_WITH_IEEE
    /* We only process the IEEE 802.15.4 supported notify message if IKE is configured to do so */
    case IKE_PAYLOAD_NOTIFY_IEEE_802_15_4_SUPPORTED:
      IKE_PRINTF(IPSEC_IKE "Received a IEEE 802.15.4 SUPPORTED Notify payload\n");
      session->recieved_ieee_supported = 1;
      break;
#endif
#if WITH_GROUP_IKE
    /* We only process the IEEE 802.15.4 supported notify message if IKE is configured to do so */
    case IKE_PAYLOAD_NOTIFY_INITIALIZE_GROUP_KEY_MANAGEMENT:
      IKE_PRINTF(IPSEC_IKE "Received a Group Key Management initialization with Notify payload. \n");
      session->received_gike_supported = 1;
      //member_entries_init();
      //gsak_entries_init();
      break;
    case IKE_PAYLOAD_NOTIFY_REQUEST_FOR_GROUP_SENDER:
    	session->sender_enabled = 1;
	break;
#endif
    /*
       IKE_PAYLOAD_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED = 16392,
       IKE_PAYLOAD_NOTIFY_REKEY_SA = 16393,
       IKE_PAYLOAD_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
       IKE_PAYLOAD_NOTIFY_NON_FIRST_FRAGMENTS_ALSO = 16395
     */
    default:
      IKE_PRINTF(IPSEC_IKE "Received informative notify message of type no. %u\n", type);
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
void
ike_statem_get_ike_keymat(ike_statem_session_t *session, uint8_t *peer_pub_key)
{
  /* Calculate the DH exponential: g^ir */
  IKE_PRINTF(IPSEC_IKE "Calculating shared ECC Diffie Hellman secret\n");
  uint8_t gir[IKE_DH_SCALAR_LEN];
  ecdh_get_shared_secret(gir, peer_pub_key, session->ephemeral_info->my_prv_key);
  IKE_MEMPRINT("Shared ECC Diffie Hellman secret (g^ir)", gir, IKE_DH_SCALAR_LEN);

  /**
   * The order of the strings will depend on who's the initiator. Prepare that.
   */
  uint8_t first_keylen = IKE_PAYLOAD_MYNONCE_LEN + session->ephemeral_info->peernonce_len;
  uint8_t first_key[first_keylen];

  uint8_t second_msg[IKE_PAYLOAD_MYNONCE_LEN +   /* Ni or Nr */
                     session->ephemeral_info->peernonce_len + /* Ni or Nr */
                     2 * 8 /* 2 * SPI */
  ];

  uint8_t *mynonce_start, *peernonce_start;
  uint8_t *ni_start, *nr_start, *spii_start, *spir_start;
  if(IKE_STATEM_IS_INITIATOR(session)) {
    mynonce_start = first_key;
    peernonce_start = mynonce_start + IKE_PAYLOAD_MYNONCE_LEN;

    ni_start = second_msg;
    nr_start = ni_start + IKE_PAYLOAD_MYNONCE_LEN;
    spii_start = nr_start + session->ephemeral_info->peernonce_len;
    spir_start = spii_start + 8;
  } else {

    peernonce_start = first_key;
    mynonce_start = peernonce_start + session->ephemeral_info->peernonce_len;

    nr_start = second_msg;
    ni_start = nr_start + session->ephemeral_info->peernonce_len;
    spir_start = ni_start + IKE_PAYLOAD_MYNONCE_LEN;
    spii_start = spir_start + 8;
  }

  /**
   * Run the first PRF operation

      SKEYSEED = prf(Ni | Nr, g^ir)
   *
   */
  memcpy(mynonce_start, &session->ephemeral_info->my_nounce, IKE_PAYLOAD_MYNONCE_LEN);
  memcpy(peernonce_start, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
  IKE_PRINTF("first_keylen: %u peernonce_len: %u\n", first_keylen, session->ephemeral_info->peernonce_len);

  IKE_MEMPRINT("Ni | Nr", first_key, first_keylen);

  IKE_MEMPRINT("Shared DH secret (g^ir)", gir, IKE_DH_SCALAR_LEN);

  uint8_t skeyseed[SA_PRF_OUTPUT_LEN(session)];

  prf_data_t prf_data =
  {
    .out = skeyseed,
    .key = first_key,
    .keylen = first_keylen,
    .data = gir,
    .datalen = IKE_DH_SCALAR_LEN
  };
  prf(session->sa.prf, &prf_data);

  IKE_MEMPRINT("SKEYSEED", skeyseed, 20);

  /**
   * Complete the next step:
   *
      {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
   */

  /**
   * Compile the second message (Ni | Nr | SPIi | SPIr)
   */
  memcpy(ni_start, &session->ephemeral_info->my_nounce, IKE_PAYLOAD_MYNONCE_LEN);
  memcpy(nr_start, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);
  *((uint32_t *)spii_start) = IKE_STATEM_MYSPI_GET_MYSPI_HIGH(session);
  *(((uint32_t *)spii_start) + 1) = IKE_STATEM_MYSPI_GET_MYSPI_LOW(session);
  *((uint32_t *)spir_start) = session->peer_spi_high;
  *(((uint32_t *)spir_start) + 1) = session->peer_spi_low;

  /**
   * Run the second, and last, PRF operation
   */

  /* Set up the arguments */
  sa_ike_t *sa = &session->sa;

  /**
   * Memory addresses and lengths of {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
   *
   * The lengths of the fields are determined as follows:
   *   SK_a* and SK_e* are the sources of keying material for the integrity and the encryption algorithm, respectively.
   *   Therefore their lengths are determined by the choice of algorithm (made so during the first exchange, which has
   *   been completed at when this function is called)
   *
   *   SK_d (source of keying material for child SAs) and SK_p* (used during authentication) length's are of the negotiated PRF's
   *   preferred key length. From p. 47, first paragraph:
   *     "The lengths of SK_d, SK_pi and SK_pr MUST be the preferred key length of the PRF agreed upon."
   *
   */
  uint8_t *sk_ptr[] = { sa->sk_d, sa->sk_ai, sa->sk_ar, sa->sk_ei, sa->sk_er, session->ephemeral_info->sk_pi, session->ephemeral_info->sk_pr };
  uint8_t sk_len[] = { SA_PRF_PREFERRED_KEYMATLEN(session), SA_INTEG_CURRENT_KEYMATLEN(session), SA_INTEG_CURRENT_KEYMATLEN(session), SA_ENCR_CURRENT_KEYMATLEN(session), SA_ENCR_CURRENT_KEYMATLEN(session), SA_PRF_PREFERRED_KEYMATLEN(session), SA_PRF_PREFERRED_KEYMATLEN(session) };

  prfplus_data_t prfplus_data = {
    .prf = sa->prf,
    .key = skeyseed,
    .keylen = sizeof(skeyseed),
    .no_chunks = sizeof(sk_len),
    .data = second_msg,
    .datalen = sizeof(second_msg),
    .chunks = sk_ptr,
    .chunks_len = sk_len
  };

  /**
   * Execute prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
   *
   * This will populate the IKE SA (the SK_* fields)
   */
  prf_plus(&prfplus_data);
}
/*---------------------------------------------------------------------------*/
void
ike_statem_get_child_keymat(ike_statem_session_t *session, sa_child_t *incoming, sa_child_t *outgoing)
{
  uint8_t key_num = 0;

  if(session->recieved_ieee_supported || session->recieved_rpl_supported) {
    IKE_PRINTF("Generating 1 key for both directions\n");
    key_num = 2;
  } else {
    key_num = 4;
  } 
  
  sa_child_t *i_to_r, *r_to_i;

  if(IKE_STATEM_IS_INITIATOR(session)) {
    i_to_r = outgoing;
    r_to_i = incoming;
  } else {
    r_to_i = outgoing;
    i_to_r = incoming;
  }
  uint8_t *keymat_ptr[key_num];
  uint8_t keymat_len[key_num];
  /* uint8_t *keymat_ptr[] = { i_to_r->sk_e, i_to_r->sk_a, r_to_i->sk_e, r_to_i->sk_a }; */
  keymat_ptr[0] = i_to_r->sk_e;
  keymat_ptr[1] = i_to_r->sk_a;
  if(key_num == 2) {
    if(session->recieved_ieee_supported) {
#if IKE_WITH_IEEE
      keymat_len[0] = get_encr_ieee_keymat_len(i_to_r->encr);
      keymat_len[1] = get_integ_ieee_keymat_len(i_to_r->integ);
#endif
    } else if(session->recieved_rpl_supported) {
#if IKE_WITH_RPL
      keymat_len[0] = get_encr_rpl_keymat_len(i_to_r->encr);
      keymat_len[1] = get_integ_rpl_keymat_len(i_to_r->integ);
#endif
    }
  } else {
    keymat_ptr[2] = r_to_i->sk_e;
    keymat_ptr[3] = r_to_i->sk_a;
    keymat_len[0] = SA_ENCR_KEYMATLEN_BY_SA(*i_to_r);
    keymat_len[1] = SA_INTEG_KEYMATLEN_BY_TYPE(i_to_r->integ);
    keymat_len[2] = SA_ENCR_KEYMATLEN_BY_SA(*r_to_i);
    keymat_len[3] = SA_INTEG_KEYMATLEN_BY_TYPE(r_to_i->integ);
  }

  int i;
  for(i = 0; i < key_num; i++) {
    IKE_PRINTF("keymat_ptr = %p, keymat_len = %u\n", keymat_ptr[i], keymat_len[i]);
  }
  
  /* Compose message (Ni | Nr) */
  uint8_t msg[IKE_PAYLOAD_MYNONCE_LEN + session->ephemeral_info->peernonce_len];
  uint8_t *my_nonce, *peer_nonce;
  if(IKE_STATEM_IS_INITIATOR(session)) {
    my_nonce = msg;
    peer_nonce = msg + IKE_PAYLOAD_MYNONCE_LEN;
  } else {
    peer_nonce = msg;
    my_nonce = msg + session->ephemeral_info->peernonce_len;
  }
  /* random_ike(my_nonce, IKE_PAYLOAD_MYNONCE_LEN, session->ephemeral_info->my_nonce_seed); */
  memcpy(my_nonce, &session->ephemeral_info->my_nounce, IKE_PAYLOAD_MYNONCE_LEN);
  memcpy(peer_nonce, session->ephemeral_info->peernonce, session->ephemeral_info->peernonce_len);

  prfplus_data_t prfplus_data = {
    .prf = session->sa.prf,
    .key = session->sa.sk_d,
    .keylen = sizeof(session->sa.sk_d),
    .no_chunks = sizeof(keymat_len),
    .data = msg,
    .datalen = sizeof(msg),
    .chunks = keymat_ptr,
    .chunks_len = keymat_len
  };
  prf_plus(&prfplus_data);

  if(key_num == 2) {
    /* Copy the keys that we made to outgoing because we only need 1 key for
       incoming and outgoing */
    memcpy(r_to_i->sk_e, keymat_ptr[0], keymat_len[0]);
    memcpy(r_to_i->sk_a, keymat_ptr[1], keymat_len[1]);
  }
}
/*---------------------------------------------------------------------------*/
/* Traffic selector management */
/*---------------------------------------------------------------------------*/
void
ts_pair_to_addr_set(ipsec_addr_set_t *traffic_desc, ike_ts_t *ts_me, ike_ts_t *ts_peer)
{
  /* peer_addr_from and peer_addr_to should point to the same memory location */
  memcpy(traffic_desc->peer_addr_from, &ts_peer->start_addr, sizeof(uip_ip6addr_t));

  traffic_desc->nextlayer_proto = ts_me->proto;
  traffic_desc->my_port_from = uip_ntohs(ts_me->start_port);
  traffic_desc->my_port_to = uip_ntohs(ts_me->end_port);
  traffic_desc->peer_port_from = uip_ntohs(ts_peer->start_port);
  traffic_desc->peer_port_to = uip_ntohs(ts_peer->end_port);
}
/*---------------------------------------------------------------------------*/
void
instanciate_spd_entry(const ipsec_addr_set_t *selector, uip_ip6addr_t *peer, ike_ts_t *ts_me, ike_ts_t *ts_peer)
{
  /**
   * Set common stuff
   */
  ts_peer->ts_type = ts_me->ts_type = IKE_PAYLOADFIELD_TS_TYPE;
  ts_peer->proto = ts_me->proto = selector->nextlayer_proto;
  ts_peer->selector_len = ts_me->selector_len = IKE_PAYLOADFIELD_TS_SELECTOR_LEN;

  /**
   * Address and port numbers
   */
  memcpy(&ts_peer->start_addr, peer, sizeof(uip_ip6addr_t));
  memcpy(&ts_peer->end_addr, peer, sizeof(uip_ip6addr_t));
  memcpy(&ts_me->start_addr, my_ip_addr, sizeof(uip_ip6addr_t));
  memcpy(&ts_me->end_addr, my_ip_addr, sizeof(uip_ip6addr_t));
  ts_peer->start_port = uip_htons(selector->peer_port_from);
  ts_peer->end_port = uip_htons(selector->peer_port_to);
  ts_me->start_port = uip_htons(selector->my_port_from);
  ts_me->end_port = uip_htons(selector->my_port_to);

  return;
}
/*---------------------------------------------------------------------------*/
spd_entry_t *
spd_get_entry_by_tspair(ike_ts_t *ts_me, ike_ts_t *ts_peer, uint8_t proto)
{
  IKE_PRINTF("In SPD_GET_ENTRY_BY_TSPAIR\n");
  uint8_t n;
  for(n = 0; n < SPD_ENTRIES; ++n) {
    PRINTSPDENTRY(&spd_table[n]);
    if(selector_is_superset_of_tspair(&spd_table[n].selector, ts_me, ts_peer) && spd_table[n].security_protocol == proto) {
      IKE_PRINTF("This SPD entry is a superset of the TS pair\n");
      return &spd_table[n];
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
uint8_t
selector_is_superset_of_tspair(const ipsec_addr_set_t *selector, ike_ts_t *ts_me, ike_ts_t *ts_peer)
{
  /* Assert peer address range */
  if(!(uip6_addr_a_is_in_closed_interval_bc(&ts_me->start_addr, selector->peer_addr_from, selector->peer_addr_to) &&
       uip6_addr_a_is_in_closed_interval_bc(&ts_me->end_addr, selector->peer_addr_from, selector->peer_addr_to))) {
    return 0;
  }
  IKE_PRINTF("addr ok\n");

  /* Source port range */
  if(!(a_is_in_closed_interval_bc(uip_ntohs(ts_me->start_port), selector->my_port_from, selector->my_port_to) &&
       a_is_in_closed_interval_bc(uip_ntohs(ts_me->end_port), selector->my_port_from, selector->my_port_to) &&
       a_is_in_closed_interval_bc(uip_ntohs(ts_peer->start_port), selector->peer_port_from, selector->peer_port_to) &&
       a_is_in_closed_interval_bc(uip_ntohs(ts_peer->end_port), selector->peer_port_from, selector->peer_port_to)
       )) {
    return 0;
  }
  IKE_PRINTF("port ok nl: ts_me->proto %u  selector->nextlayer_proto %u\n", ts_me->proto, selector->nextlayer_proto);

  /* Protocol (this assumes that ts_mee and ts_peer use the same proto, which they should) */
  if(ts_me->proto != selector->nextlayer_proto &&
     ts_me->proto != IKE_PAYLOADFIELD_TS_NL_ANY_PROTOCOL &&
     selector->nextlayer_proto != SPD_SELECTOR_NL_ANY_PROTOCOL) {
    return 0;
  }
  IKE_PRINTF("nl ok\n");

  /* Type (should be IPv6) */
  return ts_me->ts_type == IKE_PAYLOADFIELD_TS_TYPE;
}
/*---------------------------------------------------------------------------*/
/** @} */
