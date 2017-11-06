/*
 * gike-functions.h
 *
 *  Created on: Jul 5, 2016
 *      Author: Argyro Lamproudi
 */

#ifndef APPS_IPSEC_IKE_GIKE_FUNCTIONS_H_
#define APPS_IPSEC_IKE_GIKE_FUNCTIONS_H_
#include <string.h>
#include "uip.h"
#include "ipsec.h"
#include "machine.h"
#include "payload.h"
#include "sad.h"
#include "spd-conf.h"
#include "common-ike.h"


/*
 * Reference Group IKEv2 states and transitions of member-machine.c and gcks-machine.c
 */

extern transition_return_t gike_statem_trans_initresp(ike_statem_session_t *session);
extern state_return_t gike_statem_state_parse_gsauthreq(ike_statem_session_t *session);
extern transition_return_t gike_statem_trans_gsauthresp(ike_statem_session_t *session);
extern uint16_t gike_statem_trans_initreq(ike_statem_session_t *session);
extern uint8_t gike_statem_state_initrespwait(ike_statem_session_t *session);
extern state_return_t gike_statem_state_rekey(ike_statem_session_t *session);
extern transition_return_t gike_statem_trans_rekeying(ike_statem_session_t *session);
extern uint8_t gike_statem_state_established_handler(ike_statem_session_t *session);
extern state_return_t gike_statem_state_gsauthrespwait(ike_statem_session_t *session);
state_return_t gike_statem_parse_gsauth_msg(ike_statem_session_t *session);
/*
 * Group IKEv2 functions for send, parse messages.
 */
extern transition_return_t gike_statem_send_rekey_msg(gsak_entry_t *gsak_entry, payload_arg_t *payload_arg, uint8_t *pairwise_secret_key);
void parse_rekey_msg(uint8_t *payload_start, gsak_entry_t *gsak_entry);
extern transition_return_t gike_statem_send_gsauth_msg(ike_statem_session_t *session, payload_arg_t *payload_arg);
extern void write_gsak_payload(payload_arg_t *payload_arg,uint32_t *spi,const spd_proposal_tuple_t *kek, uint16_t *lifetime,gsak_entry_t *gsak_entry);
extern void parse_gsak_payload(uint8_t *payload_start,ike_statem_session_t *session);
extern void parse_gsat_payload(uint8_t *payload_start, sad_entry_t *incoming_sad, sad_entry_t *outgoing_sad);
void parse_sid_payload(uint8_t *payload_start, sad_entry_t *outgoing_sad_entry);
void write_sid_payload(payload_arg_t *payload_arg, gsak_entry_t *gsak_entry,ike_statem_session_t *session, uint32_t *spi /*tek spi*/);
void write_kd_payload(payload_arg_t *payload_arg, sad_entry_t *incoming_entry, sad_entry_t *outgoing_entry ,uint32_t *spi,
				member_param_t member_entry, key_download_types_t *kd_type, gsak_entry_t *gsak);
void parse_kd_payload(uint8_t *payload_start, sad_entry_t *incoming_entry, sad_entry_t *outgoing_entry);
extern uint8_t is_candidate_member_of_group(uip_ip6addr_t candidate_multicast_group_id, uip_ip6addr_t member_addr,ike_statem_session_t *session);
uint8_t find_group_tek_gsa(uip_ip6addr_t group_address);
void ike_statem_set_group_id_payload(payload_arg_t *payload_arg, ike_payload_type_t payload_type, ike_statem_session_t *session);
uint8_t group_ike_rekey_statem_unpack_sk(gsak_entry_t *gsak_entry, ike_payload_generic_hdr_t *sk_genpayloadhdr, uint8_t isUsingPairwiseKey);
uint16_t gike_statem_get_server_authdata(gsak_entry_t *gsak_entry, uint8_t *out /*these are the signed octets*/, sad_entry_t *outgoing_sad);
#endif /* APPS_IPSEC_IKE_GIKE_FUNCTIONS_H_ */
