/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    Common functionality for IKEv2. Mostly helpers for the state machine.
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *
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

#ifndef __COMMON_IKE_H__
#define __COMMON_IKE_H__

#include <string.h>
#include "uip.h"
#include "ipsec.h"
#include "machine.h"
#include "payload.h"
#include "sad.h"

#if IKE_WITH_IEEE
#include "ieee-802-15-4/ieee-802-15-4-traffic-selector.h"
#endif

/**
 * References states of the responder machine
 */
extern state_return_t ike_statem_state_parse_initreq(ike_statem_session_t *session);
extern transition_return_t ike_statem_trans_initresp(ike_statem_session_t *session);
extern state_return_t ike_statem_state_parse_authreq(ike_statem_session_t *session);
extern transition_return_t ike_statem_trans_authresp(ike_statem_session_t *session);

/**
 * References states of the initiator machine
 */
extern uint16_t ike_statem_trans_initreq(ike_statem_session_t *session);
extern uint8_t ike_statem_state_initrespwait(ike_statem_session_t *session);




/*
 * References states of the established machine
 */
extern uint8_t ike_statem_state_established_handler(ike_statem_session_t *session);

/**
 * Major functions implementing behaviour that is shared across the machines
 */

/**
 * Completes a transition that responds to or requests an SA INIT exchange
 */
extern transition_return_t ike_statem_send_sa_init_msg(ike_statem_session_t *session, payload_arg_t *payload_arg, ike_payload_ike_hdr_t *ike_hdr, spd_proposal_tuple_t *offer);
extern state_return_t ike_statem_parse_auth_msg(ike_statem_session_t *session);

/**
 * Parse an SA INIT message
 */
extern state_return_t ike_statem_parse_sa_init_msg(ike_statem_session_t *session, ike_payload_ike_hdr_t *ike_hdr, spd_proposal_tuple_t *accepted_offer);

/**
 * Helper functions that parses and writes payloads, generates keying material etc
 */

/**
 * Write a notification payload (p. 97)
 *
 * \param payload_arg Payload argument
 * \param proto_id The type of protocol concerned.
 * \param spi Only used in conjunction with INVALID_SELECTORS and REKEY_SA, zero otherwise.
 * \param type Notificiation message type.
 * \param notify_payload Address of the payload. Null if none.
 * \param notify_payload_len Length of the payload starting at notify_payload.
 */
extern void ike_statem_write_notification(payload_arg_t *payload_arg,
                                          sa_ipsec_proto_type_t proto_id,
                                          uint32_t spi,
                                          notify_msg_type_t type,
                                          uint8_t *notify_payload,
                                          uint8_t notify_payload_len);
/**
 * Sends a single Notify payload encapsulated in an SK payload if cryptographic keys have been negotiated. Only to be called from state
 * function.
 *
 * The IKE header's exchange type will be recycled from the header currently sitting in msg_buf. The type will always be response. If the exchange is any other than SA_INIT
 * the notify payload will be protected by an encrypted payload.
 *
 * \param session Session concerned
 * \param type Notify message type. 0 does nothing.
 */
extern void ike_statem_send_single_notify(ike_statem_session_t *session, notify_msg_type_t type);

/**
 * Sets the Identification payload to the e-mail address defined auth.c or the
 * certificate subject
 */
extern void ike_statem_set_id_payload(payload_arg_t *payload_arg, ike_payload_type_t payload_type);

/**
 * Take the offer and write the corresponding SA payload to memory starting at payload_arg->start.
 * Handles IKE SA- as well as Child SA-offers.
 *
 * \parameter payload_arg Payload argument
 * \parameter offer The offer chain. Probably one from spd_conf.c.
 * \parameter spi The SPI of the offer's proposals (We only support one SPI per offer. Nothing tells us that this is illegal.)
 */
extern void ike_statem_write_sa_payload(payload_arg_t *payload_arg, const spd_proposal_tuple_t *offer, uint32_t spi);

/**
 * Performs the calculations as described in section 2.14
 *
    SKEYSEED = prf(Ni | Nr, g^ir)

    {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                    = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
 *
 * \parameter session The session concerned
 * \parameter peer_pub_key Address of the beginning of the field "Key Exchange Data" in the peer's KE payload (network byte order).
 * \return The address that follows the last byte of the nonce
 */
extern void ike_statem_get_ike_keymat(ike_statem_session_t *session, uint8_t *peer_pub_key);

/**
 * Get Child SA keying material as outlined in section 2.17
 *
 *     KEYMAT = prf+(SK_d, Ni | Nr)
 *
 * Encryption material from KEYMAT are used as follows:

      o All keys for SAs carrying data from the initiator to the responder are taken before SAs going from the responder to the initiator.

      o If multiple IPsec protocols are negotiated, keying material for each Child SA is taken in the order in which the protocol headers
        will appear in the encapsulated packet.

      o If an IPsec protocol requires multiple keys, the order in which they are taken from the SA’s keying material needs to be described
        in the protocol’s specification. For ESP and AH, [IPSECARCH] defines the order, namely: the encryption key (if any) MUST be taken
        from the first bits and the integrity key (if any) MUST be taken from the remaining bits.
 *
 * \parameter session The IKE session
 * \parameter incoming Incoming child SA
 * \parameter outgoing Outgoing child SA
 */
extern void ike_statem_get_child_keymat(ike_statem_session_t *session, sa_child_t *incoming, sa_child_t *outgoing);
extern transition_return_t ike_statem_run_transition(ike_statem_session_t *session, uint8_t retransmit);
extern transition_return_t ike_statem_send_auth_msg(ike_statem_session_t *session, payload_arg_t *payload_arg, uint32_t child_sa_spi, const spd_proposal_tuple_t *sai2_offer, const ipsec_addr_set_t *ts_instance_addr_set);

/**
 * Parses the Security Association Payload
 * peer			          me
 * responder SA(1) -> initiator offer (n): set transforms in SA, return subset
 * initiator SA(n) -> responder offer (n): set transforms in SA, return subset
 */
extern uint8_t ike_statem_parse_sa_payload(const spd_proposal_tuple_t *my_offer,
                                          ike_payload_generic_hdr_t *sa_payload_hdr,
                                          uint8_t ke_dh_group,
                                          sa_ike_t *ike_sa,
                                          sad_entry_t *sad_entry,
                                          spd_proposal_tuple_t *accepted_transform_subset);
/**
 * Get InitiatorSignedOctets or ResponderSignedOctets (depending on session) as described on p. 47.
 *
 * \param session      Current session
 * \param myauth       Generate my *SignedOctet (use my own RealMessage) if set to one, generate the peer's *SignedOctets (use the peer's stored RealMessage) if set to zero.
 * \param out          Address where AUTH will be written. Free space should amount to ~1 kB (depending on msg sizes etc).
 * \param id_payload   The address of the ID payload
 * \param id_len       The length of the ID payload, excluding its generic payload header
 *
 * \return length of *SignedOctets, 0 if an error occurred
 */
extern uint16_t ike_statem_get_authdata(ike_statem_session_t *session,
                                        uint8_t myauth,
                                        uint8_t *out,
                                        ike_id_payload_t *id_payload,
                                        uint16_t id_payload_len);

/**
 * This function completes the encryption of an SK payload and can only be
 * called after \c ike_statem_prepare_sk()
 *
 * BEFORE
 **+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Next Payload  |C|  RESERVED   |         Payload Length        |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                     Initialization Vector                     |
 |         (length is block size for encryption algorithm)       |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Unencrypted IKE Payloads                   ~
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * AFTER
 *
 **+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Next Payload  |C|  RESERVED   |         Payload Length        |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                     Initialization Vector                     |
 |         (length is block size for encryption algorithm)       |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Encrypted IKE Payloads                     ~
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |               |             Padding (0-255 octets)            |
 ||+-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
 |                                               |  Pad Length   |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Integrity Checksum Data                    ~
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 *
 *
 * \parameter session The session, used for fetching the encryption keys
 * \parameter sk_genpayloadhdr The generic payload header of the SK payload, as created by \c ike_statem_prepare_sk()
 * \parameter len The length of the IV + the data to be encrypted
 */
extern void ike_statem_finalize_sk(payload_arg_t *payload_arg,
                                   ike_payload_generic_hdr_t *sk_genpayloadhdr,
                                   uint16_t data_len);

/**
 * Function that delivers suitable actions and suitable informational / error messages.
 * Should work for all cases
 *
 * \return 1 if the notify message implies that the peer has hung up, 0 otherwise.
 */
extern uint8_t ike_statem_handle_notify(ike_payload_notify_t *payload_start, ike_statem_session_t *session);

/**
 * Unpacks (i.e. checks integrity and decrypts) an SK payload / IKE message.
 *
 * This function decrypts an SK payload using the IKE SA's parameters and the starting address of the SK payload's generic header.
 * If the SK payload's syntax is correct and the cryptographic checksum computation matches that included in the payload, the SK payload
 * (including its generic payload header) is replaced with the decrypted IKE payloads.
 *
 * This entails that the address of the generic payload header at sk_genpayload_hdr will contain the values of the first encrypted
 * IKE payload after the call to this function has been completed.
 *
 * BEFORE
 *
 **+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Next Payload  |C|  RESERVED   |         Payload Length        |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                     Initialization Vector                     |
 |         (length is block size for encryption algorithm)       |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Encrypted IKE Payloads                     ~
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |               |             Padding (0-255 octets)            |
 ||+-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
 |                                               |  Pad Length   |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Integrity Checksum Data                    ~
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * AFTER
 *
 **+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Next Payload  |C|  RESERVED   | Payload Len  (4 + IV length)  |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                     Initialization Vector                     |
 |         (length is block size for encryption algorithm)       |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                    Decrypted IKE Payloads                     ~
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * \parameter sk_genpayloadhdr The generic paylod header of the SK payload
 *
 * \return 0 if the integrity check fails. If successfull, the number of trailing bytes is returned
 */
extern uint8_t ike_statem_unpack_sk(ike_statem_session_t *session, ike_payload_generic_hdr_t *sk_genpayloadhdr);

/**
 * Writes a "skeleton" of the SK payload. You can continue building your message right after the
 * resulting SK payload and then finish the encryption by calling \c ike_statem_finalize_sk()
 *
 **+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Next Payload  |C|  RESERVED   |         Payload Length        |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                     Initialization Vector                     |
 |         (length is block size for encryption algorithm)       |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                   -- Put your IKE Payloads here --
 *
 * \parameter payload_arg Payload arg
 */
extern void ike_statem_prepare_sk(payload_arg_t *payload_arg);

/**
 * Writes the initial TSi and TSr payloads in the role as the initiator
 */
extern void ike_statem_write_tsitsr(payload_arg_t *payload_arg, const ipsec_addr_set_t *ts_addr_set);

/**
 * Is an SPD selector a superset of a TS pair?
 *
 * \return non-zero if selector is a superset of the TS pair, 0 otherwise
 */
extern uint8_t selector_is_superset_of_tspair(const ipsec_addr_set_t *selector, ike_ts_t *ts_me, ike_ts_t *ts_peer);

/**
 * Instanciate an SPD entry to a traffic selector pair in accordance with RFC 4301. PFP flags are hardwired in this function, as elsewhere.
 */
extern void instanciate_spd_entry(const ipsec_addr_set_t *selector, uip_ip6addr_t *peer, ike_ts_t *ts_me, ike_ts_t *ts_peer);

/**
 * Traverse the SPD table from the top to the bottom and return the first protected entry that
 * is a subset of the traffic selector pair constituted by ts_me and ts_peer
 *
 * \return the entry that matched. NULL is returned if no such is found
 */
extern spd_entry_t *spd_get_entry_by_tspair(ike_ts_t *ts_me, ike_ts_t *ts_peer, uint8_t proto);

/**
 * Copies a traffic selector pair into an ipsec_addr_set_t. Keep in mind that the IP address pointers of the address set must point to free memory.
 */
extern void ts_pair_to_addr_set(ipsec_addr_set_t *traffic_desc, ike_ts_t *ts_me, ike_ts_t *ts_peer);

extern uint8_t parse_peer_proposal(uint32_t candidate_spi, spd_proposal_tuple_t *accepted_transform_subset,
        const spd_proposal_tuple_t *my_offer, uint8_t proto, uint8_t *candidates, 
        uint16_t candidate_size, ike_payload_generic_hdr_t *sa_payload_hdr, 
        uint8_t required_transforms, uint8_t ke_dh_group);

#if IKE_WITH_RPL
/**
 * Parses the SA payload for RPL payloads
 */
extern uint8_t ike_statem_parse_rpl_sa_payload(const spd_proposal_tuple_t *my_offer,
                                               ike_payload_generic_hdr_t *sa_payload_hdr,
                                               rpl_sad_entry_t *sad_entry, uint8_t proto,
                                               spd_proposal_tuple_t *accepted_transform_subset);
#endif
#if IKE_WITH_IEEE
/**
 * Parses the SA payload for IEEE 802.15.4 sa payloads
 */
extern uint8_t ike_statem_parse_ieee_sa_payload(const spd_proposal_tuple_t *my_offer,
                                                ike_payload_generic_hdr_t *sa_payload_hdr,
                                                ieee_sad_entry_t *sad_entry, uint8_t proto,
                                                spd_proposal_tuple_t *accepted_transform_subset);
/**
 * Write IEEE 802.15.4 traffic selector
 */
extern void ike_statem_write_ieee_tsitsr(payload_arg_t *payload_arg, const ipsec_addr_set_t *ts_addr_set);

#endif

#define IPSEC_IKE "IPsec IKEv2: "
#define IPSEC_IKE_ERROR "IPsec IKEv2: Error: "

#define IKE_STATEM_ASSERT_COOKIE(payload_arg) \
  do { \
    if(payload_arg->session->cookie_payload != NULL) { \
      ike_payload_generic_hdr_t *genpayload_hdr = (ike_payload_generic_hdr_t *)(payload_arg)->start; \
      uint8_t offset = sizeof(genpayload_hdr) + sizeof(ike_payload_notify_t); \
      uint8_t *cookie_data = genpayload_hdr + offset; \
      uint8_t cookie_data_len = UIP_NTOHS(genpayload_hdr->len) - offset; \
      ike_statem_write_notification((payload_arg), \
                                    SA_PROTO_IKE, \
                                    0, \
                                    IKE_PAYLOAD_NOTIFY_COOKIE, \
                                    cookie_data, \
                                    cookie_data_len); \
    } \
  } while(false);

/**
 * Copies a complete IKE message to the session_ptr's ephemeral_info. Used for authentication.
 */
#define COPY_FIRST_MSG(session_ptr, ike_hdr_ptr) \
  do { \
    uint32_t len = uip_ntohl(ike_hdr_ptr->len); \
    if(len > IKE_STATEM_FIRSTMSG_MAXLEN) { \
      /* Error: Responder's first message is too big  */ \
      IPSEC_PRINTF(IPSEC_IKE_ERROR " Reponder's first message is too big\n"); \
      return 0; \
    } \
    else { \
      session_ptr->ephemeral_info->peer_first_msg_len = (uint16_t)len; \
      memcpy(&session_ptr->ephemeral_info->peer_first_msg, ike_hdr_ptr, len); \
    } \
  } while(0)

#endif

/** @} */
