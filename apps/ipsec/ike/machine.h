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
 *              Vilhelm Jutvik <ville@imorgon.se>
 *
 */

#ifndef __MACHINE_H__
#define __MACHINE_H__

#include "contiki-net.h"
#include "payload.h"
#include "spd.h"
#include "common-ipsec.h"
#include "sa.h"
#include "ecc.h"
#include "bigint.h"
#include "ipsec-random.h"
#if WITH_IPSEC
#include "sad.h"
#endif
#include "spd-conf.h"
#define IKE_UDP_PORT 500

#if IKE_WITH_RPL
#include "rpl/rpl-sad.h"
#endif

#if IKE_WITH_IEEE
#include "ieee-802-15-4/ieee-802-15-4-sad.h"
#include "ieee-802-15-4/ieee-802-15-4-traffic-selector.h"
#endif

/**
 * Protocol-related stuff
 */
#define IKE_STATEM_TIMEOUT  10 * CLOCK_SECOND
#define IKE_RETRANSMIT_MAX 3

/**
 * Global buffers used for communicating information with the state machine
 */
extern uint8_t *msg_buf; /* Pointing at the first word of the UDP datagram's data areas */
extern const uip_ip6addr_t *my_ip_addr;

extern uint8_t *global;

/**
 * Code for state related stuff
 *
 * Each state is associated with a state function. The purpose of said function
 * is to decide, and execute, the next state transition upon an event occurring.
 * For facilitating this decision a pointer to the session struct is passed as an argument
 * and buffers containing UDP messages etc are made available to it.
 */

#define IKE_STATEM_MYSPI_MAX 32767 /* 15 bits. First bit occupied by initiator / responder. 2^15 - 1 */

/* Macros for manipulating 'initiator_and_my_spi' */
#ifdef BIGENDIAN
#define IKE_STATEM_MYSPI_I_MASK 0x8000l
#else
#define IKE_STATEM_MYSPI_I_MASK 0x0080
#endif

/* The maximum size of the peer's first message. */
/* Used for calculating the AUTH hash */
#define IKE_STATEM_FIRSTMSG_MAXLEN 500

/* The number of sessions that we can store */
#ifndef IKE_SESSION_NUM
#define IKE_SESSION_NUM 5
#endif

#ifndef IKE_HALF_OPEN_NUM
#define IKE_HALF_OPEN_NUM 5
#endif

/* The maximum number of tuples that can be returned in a reply from */
#define IKE_REPLY_MAX_PROPOSAL_TUPLES 10

#define IKE_STATEM_MYSPI_GET_MYSPI(session) ((session)->initiator_and_my_spi & ~IKE_STATEM_MYSPI_I_MASK)
#define IKE_STATEM_MYSPI_GET_MYSPI_HIGH(session) 0U
#define IKE_STATEM_MYSPI_GET_MYSPI_LOW(session) (uip_htonl(((uint32_t)IKE_STATEM_MYSPI_GET_MYSPI(session))))
#define IKE_STATEM_MYSPI_GET_I(var) (var & IKE_STATEM_MYSPI_I_MASK)
#define IKE_STATEM_IS_INITIATOR(session) (IKE_STATEM_MYSPI_GET_I(session->initiator_and_my_spi))
#define IKE_STATEM_MYSPI_SET_I(var) (var = var | IKE_STATEM_MYSPI_I_MASK)
#define IKE_STATEM_MYSPI_SET_R(var) (var = var & ~IKE_STATEM_MYSPI_I_MASK)
#define IKE_STATEM_MYSPI_SET_NEXT(var) (var = (var | (rand16() & ~IKE_STATEM_MYSPI_I_MASK))) /* (Note: This will overflow into the Initiator bit after 2^15 - 1 calls) */
#define IKE_STATEM_MYSPI_CLEAR_I(var) (var = var & ~IKE_STATEM_MYSPI_I_MASK)

#define IKE_STATEM_GET_GSAK_SPI(gsak_entry) ((gsak_entry)->spi)

typedef uint8_t state_return_t;
typedef uint16_t transition_return_t;

#define STATE_FAILURE        0
#define STATE_SUCCESS        1
#define TRANSITION_FAILURE   0

#define IKE_STATEM_INCRMYMSGID(session) ++ (session)->my_msg_id;
#define IKE_STATEM_INCRPEERMSGID(session) ++ (session)->peer_msg_id;
#define IKE_STATEM_SESSION_ISREADY(session) (ctimer_expired(&session->retrans_timer))

/**
 * Call this macro when you want to execute a state transition
 * (i.e. send a request / response).
 *
 * Can either be called from a state or from ike_statem_timeout_handler()
 */




#define IKE_STATEM_TRANSITION(session) \
  /* Run transition only retransmitter for initiator*/ \
  (IKE_STATEM_IS_INITIATOR(session) ? ike_statem_run_transition(session, 1) : ike_statem_run_transition(session, 0))

#define IKE_STATEM_TRANSITION_NO_TIMEOUT(session) \
  /* Run transition */ \
  ike_statem_run_transition(session, 0)
/* Called when REKEY_MESSAGES are programmed to be sent. */
/*#define SET_REKEY_TIMER(gsak_entry) \
  IPSEC_PRINTF("STARTING rekey timer for gska_entry %p\n", gsak_entry); \
  ctimer_set(&gsak_entry->rekey_timer, REKEY_TIMER * CLOCK_SECOND, &gike_rekeying_msg_init, (void *)gsak_entry); \*/

#define SET_REKEY_TIMER(gsak_entry) \
  IPSEC_PRINTF("STARTING rekey timer for gsak_entry %p\n", gsak_entry); \
  ctimer_set(&gsak_entry->rekey_timer, REKEY_TIMER * CLOCK_SECOND, &set_rekey_event, (void *)gsak_entry); \


#define STOP_REKEY_TIMER(gsak_entry) \
  IPSEC_PRINTF("STOPPING rekey timer for gsak_entry %p\n", gsak_entry); \
  ctimer_stop(&gsak_entry->rekey_timer); \

void set_rekey_event(void *gsak_entry);
/**
 * Storage structure for temporary information used during connection setup.
 */
typedef struct {
  /* Information about the triggering packet (used for IKE SA initiation) */
  spd_entry_t spd_entry;
  uip_ip6addr_t peer_addr_from;
  uip_ip6addr_t peer_addr_to;

  /* Temporary storage for our TS offer to the peer */
  ipsec_addr_set_t my_ts_offer_addr_set;

#if IKE_WITH_IEEE
  /* Temporary storage for IEEE TS offer */
  ieee_addr_set_t my_ts_offer_ieee_addr_set;
#endif

  uint32_t my_child_spi;
  uint32_t peer_child_spi;

  /* Used for generating the AUTH payload. Length MUST equal the key size of the negotiated PRF. */
  uint8_t sk_pi[SA_PRF_MAX_PREFERRED_KEYMATLEN];
  uint8_t sk_pr[SA_PRF_MAX_PREFERRED_KEYMATLEN];

  ike_ts_t peer_ts;
  ike_ts_t my_ts;

  /**
   * Seed for generating our Nonce. This will effectively cause our multibyte nonce to become a
   * function of this value, thus circumventing the RFC's nonce length requirements, making the cryptographic
   * protection weaker.
   *
   * This must clearly be fixed in the production code of this software. Though I hope that the principle of
   * generating the nonce on the fly is preserved, alleviating the need to storing an additional ~16 bytes in RAM.
   * Instead of using a single seed value we can add semi-static, semi-random, data from the network layer, the radio,
   * the OS etc.
   */
  uint8_t my_nounce[IKE_PAYLOAD_MYNONCE_LEN];
  uint8_t peernonce[IKE_PAYLOAD_PEERNONCE_LEN];
  uint8_t peernonce_len;

  uint8_t peer_first_msg[IKE_STATEM_FIRSTMSG_MAXLEN];
  uint16_t peer_first_msg_len;

  /* Internal representation of our reply to a responder's SA offer */
  spd_proposal_tuple_t ike_proposal_reply[IKE_REPLY_MAX_PROPOSAL_TUPLES];
  spd_proposal_tuple_t child_proposal_reply[IKE_REPLY_MAX_PROPOSAL_TUPLES];

  /* My private asymmetric key store in small endian ContikiECC format */
  u_word my_prv_key[IKE_DH_SCALAR_BUF_LEN];

  /* We only send our certificate if we receive a cert request payload */
  uint8_t cert_req_recieved;
} ike_statem_ephemeral_info_t;

/**
 * Session struct
 */
typedef struct ike_statem_session {
  struct ike_statem_session *next;

  /* The IPv6 of the peer that we're communicating with */
  uip_ip6addr_t peer;

  /*
   * This 16 bit variable is an amalgam of two pieces of information:

     In big endian systems:
                        1
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   ***+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ***|I|  My SPI                     |
   ***+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     In little endian systems:
                       1
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   ***+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  My SPI       |I|             |
   |||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   * The 'I' flag is set if we're the initator of this IKE session. This may
   * change upon IKE SA rekey.
   *
   * The values are set / read by using the macros as defined above.
   *
   * The My SPI -value is also the key of the linked list.
   */
  uint16_t initiator_and_my_spi;

  /* The peer's IKE SPI. Is not unique as it's decided by the peer. */
  /* (Can we remove this 8 B lump? We can't initiate requests without it.) */
  uint32_t peer_spi_high, peer_spi_low;

  /**
   * Message ID as described in section 2.2.
   * The values are only 8 bits large, much smaller than 32 bits as dictated by the standard.
   * We believe this is a reasonable tradeof as we don't expect much IKEv2 -traffic
   * to any IKE SA. The SA will be closed, or rekeyed (will we implement this?), in the event
   * of an overflow (in line with the RFC).
   */
  uint8_t my_msg_id, peer_msg_id;

  /* Message retransmission timer */
  struct ctimer retrans_timer;
  uint8_t num_retransmit;

  /* IKE SA parameters */
  /* Note for future functionality: We could make the SA and the whole sa_ike_t */
  /* of variable size (next and length info in the head, cast everything to smallest */
  /* common denominator) */
  sa_ike_t sa;

  /* Temporary scratchpad for use during setup of the IKE SA */
  ike_statem_ephemeral_info_t *ephemeral_info;

  /**
   * Address of COOKIE data. Used by ike_statem_trans_initreq(). The default value should be NULL.
   */
  ike_payload_generic_hdr_t *cookie_payload;

  /* Outgoing and incomming SAD entries (used to delete them) later*/
#if WITH_IPSEC
  sad_entry_t *outgoing_entry;
  sad_entry_t *incoming_entry;
#endif
#if IKE_WITH_RPL
  rpl_sad_entry_t *outgoing_entry;
  rpl_sad_entry_t *incoming_entry;
#endif
#if IKE_WITH_IEEE
  ieee_sad_entry_t *outgoing_entry;
  ieee_sad_entry_t *incoming_entry;
  uip_lladdr_t peer_lladdr;
#endif
  /* For RPL and IEEE 802.15.4 Key Management */
  uint8_t recieved_rpl_supported;
  uint8_t recieved_ieee_supported;
/*For Group Key Management with IKEv2*/
  uint8_t received_gike_supported;
  uint8_t *sender_id;
  uip_ip6addr_t group_ip;
  uint8_t sender_enabled;
  //gsak_entry_t *gsak_entry; //it is included in the session only for the members.
  //kek_kd_t *kd_entry;
  /* The edge (transition) to follow */
  uint16_t (*transition_fn)(struct ike_statem_session *);

  /* The above transition will (if all goes well) take us to this state. */
  uint8_t (*next_state_fn)(struct ike_statem_session *);
} ike_statem_session_t;

/**
 * Convenience macros for translating the roles of initiator/responder to myself/peer
 */
#define IKE_STATEM_GET_MY_SK_P(session) (IKE_STATEM_IS_INITIATOR(session) ? session->ephemeral_info->sk_pi : session->ephemeral_info->sk_pr)
#define IKE_STATEM_GET_PEER_SK_P(session) (IKE_STATEM_IS_INITIATOR(session) ? session->ephemeral_info->sk_pr : session->ephemeral_info->sk_pi)
#define IKE_STATEM_GET_MY_SK_A(session) (IKE_STATEM_IS_INITIATOR(session) ? session->sa.sk_ai : session->sa.sk_ar)
#define IKE_STATEM_GET_PEER_SK_A(session) (IKE_STATEM_IS_INITIATOR(session) ? session->sa.sk_ai : session->sa.sk_ar)
#define IKE_STATEM_GET_MY_SK_E(session) (IKE_STATEM_IS_INITIATOR(session) ? session->sa.sk_ei : session->sa.sk_er)
#define IKE_STATEM_GET_PEER_SK_E(session) (IKE_STATEM_IS_INITIATOR(session) ? session->sa.sk_er : session->sa.sk_ei)

/**
 * Common argument for payload writing functions
 */
typedef struct {
  uint8_t *start;                                 /* The address at which the paylaod should start */
  ike_statem_session_t *session;                  /* Session pointer */
  uint8_t *prior_next_payload;                    /* Pointer that stores the address of the last "next payload" -field, of type ike_payload_type_t */
} payload_arg_t;

/**
 * Traverses the list sessions, starting at head, returning the address of the first
 * entry with matching IPv6 address.
 *
 * \parameter addr Sought IPv6 address
 */
ike_statem_session_t *ike_statem_get_session_by_addr(uip_ip6addr_t *addr);

/**
 * Initializes an new IKE session with the purpose of creating an SA in response to triggering_pkt_addr
 * and commanding_entry
 */
void ike_statem_setup_initiator_session(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry);
gsak_entry_t *find_gsak_entry(uint32_t *spi);
gsak_entry_t *create_gsak_entry(uint32_t *spi);
void gike_rekeying_msg_leave(gsak_entry_t *gsak_entry);
void gike_rekeying_msg_init(gsak_entry_t *gsak_entry);
void gsak_entries_init();
gsak_entry_t *find_gsak_entry_by_mcst_addr(uip_ip6addr_t *mcst_addr);
//void member_entries_init();
//member_param_t * create_member_entry();

/**
 * Removes all stored session information
 * @param session
 */
void ike_statem_remove_session(ike_statem_session_t *session);

/**
 * Clean an IKE session when the SA has been established
 */
extern void ike_statem_clean_session(ike_statem_session_t *session);

/**
 * Send an UDP packet with the data currently stored in udp_buf (length derived from len)
 * to IP address session->peer
 */
extern void ike_statem_send(ike_statem_session_t *session, uint16_t len);

/**
 *  Initialize the state machine
 */
void ike_statem_init();

/**
 * Enters a state
 */
void ike_statem_enterstate(ike_statem_session_t *session);
/**
 * Handler for incoming UDP traffic. Matches the data with the correct session (state machine)
 * using the IKE header.
 */
void ike_statem_incoming_data_handler();

/*
 * ------------------------> Group IKEv2 <-------------------------------------
 */
/*
 * Sets up a new session for G-IKEv2 in the candidate group member.
 */
//void gike_statem_setup_member_session(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry);
void gike_statem_setup_member_session(ipsec_addr_t *triggering_pkt_addr, spd_entry_t *commanding_entry, uip_ip6addr_t server_ip);

/*
 * Sets up a new session for G-IKEv2 in the Group Controller/Key Server for incoming request.
 */
void gike_statem_setup_gcks_session();

#endif

/** @} */

