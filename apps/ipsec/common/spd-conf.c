/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    SPD configuration
 *	\details
 *    This file contains functions for SPD configuration.
 *
 *    All values and definitions described herein pertains to RFC 4301
 *    (Security Architecture for IP) and
 *    RFC 5996 (Internet Key Exchange Protocol Version 2).
 *    Sections of special interests are:
 *      RFC 4301: 4.4.1 (Security Policy Database)
 *      RFC 5996: 3.3 (Security Association Payload)
 *
 *    Please see spd.h for a quick overview of the data format.
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se>
 *    Argyro Lamproudi
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

#include "sa.h"
#include "spd.h"
#include "uip.h"
#include "spd-conf.h"
#include "g-ike-conf.h"
#include "auth.h"

#if IKE_WITH_RPL
#include "rpl/rpl-ike-conf.h"
#include "rpl/rpl-spd-conf.h"
#endif

#if IKE_WITH_IEEE
#include "ieee-802-15-4/ieee-802-15-4-conf.h"
#include "ieee-802-15-4/ieee-802-15-4-spd-conf.h"
#endif

#define uip_ip6addr_set_val16(ip6addr, val) \
  ip6addr.u16[0] = val, \
  ip6addr.u16[1] = val, \
  ip6addr.u16[2] = val, \
  ip6addr.u16[3] = val, \
  ip6addr.u16[4] = val, \
  ip6addr.u16[5] = val, \
  ip6addr.u16[6] = val, \
  ip6addr.u16[7] = val

/**
 * IKEv2 proposals as described in RFC 5996 with the following exceptions:
 *
 * > Every proposal must offer integrity protection.
 *  This is provided through a combined mode transform _or_ via the integrity
 */
const spd_proposal_tuple_t spdconf_ike_proposal[6] =
{
  /* Either ENCR,INTEG,PRF,DH or ENCR+INTEG,PRF,DH CCM is a type of ENCR+INTEG*/
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_IKE },
  /* Encryption transform */
#ifdef IKE_ENCR
  { SA_CTRL_TRANSFORM_TYPE_ENCR, IKE_ENCR },
  { SA_CTRL_ATTRIBUTE_KEY_LEN, 16 },
#else
  { SA_CTRL_TRANSFORM_TYPE_ENCR, IKE_ENCR_DEFAULT },
  { SA_CTRL_ATTRIBUTE_KEY_LEN, 16 },
#endif

  /* Integrity transform */
#ifdef IKE_INTEG
  { SA_CTRL_TRANSFORM_TYPE_INTEG, IKE_INTEG },
#endif

  /* Psuedo-random function transform */
#ifdef IKE_PRF
  { SA_CTRL_TRANSFORM_TYPE_PRF, IKE_PRF },
#else
  { SA_CTRL_TRANSFORM_TYPE_PRF, IKE_PRF_DEFAULT },
#endif

  /* Diffie-Hellman group */
#ifdef IKE_DH
  { SA_CTRL_TRANSFORM_TYPE_DH, IKE_DH },
#else
  { SA_CTRL_TRANSFORM_TYPE_DH, IKE_DH_DEFAULT },
#endif

  /* Terminate the offer */
  { SA_CTRL_END_OF_OFFER, 0 }
};

const spd_proposal_tuple_t spdconf_ike_open_proposal[6] =
{
  /* IKE proposal */
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_IKE },
  { SA_CTRL_TRANSFORM_TYPE_ENCR, SA_ENCR_NULL },
  { SA_CTRL_TRANSFORM_TYPE_INTEG, SA_INTEG_AES_XCBC_MAC_96 },
  { SA_CTRL_TRANSFORM_TYPE_DH, SA_IKE_MODP_GROUP },
  { SA_CTRL_TRANSFORM_TYPE_PRF, SA_PRF_HMAC_SHA1 },
  /* Terminate the offer */
  { SA_CTRL_END_OF_OFFER, 0 }
};


/**
 * ESP proposal
 */
const spd_proposal_tuple_t my_ah_esp_proposal[5] =
{
  /* ESP proposal */
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_ESP },
#ifdef ESP_ENCR
  { SA_CTRL_TRANSFORM_TYPE_ENCR, ESP_ENCR },
  { SA_CTRL_ATTRIBUTE_KEY_LEN, 16 },
#else
  { SA_CTRL_TRANSFORM_TYPE_ENCR, EPS_ENCR_DEFAULT },
  { SA_CTRL_ATTRIBUTE_KEY_LEN, 16 },
#endif

#ifdef ESP_INTEG
  { SA_CTRL_TRANSFORM_TYPE_INTEG, ESP_INTEG },
#endif

  /* Terminate the offer */
  { SA_CTRL_END_OF_OFFER, 0 }
};


/*
 * Group IKEv2 proposals
 */
const spd_proposal_tuple_t spdconf_kek_gsa[7] =
{
  /* IKE proposal */
  { GSA_CTRL_NEW_PROPOSAL, SA_PROTO_IKE },
  { GSA_CTRL_TYPE_MNG_ALGORITHM, GKMA },
#ifdef GIKE_ENCR
  { GSA_CTRL_TYPE_ENCR, GIKE_ENCR },
  { GSA_CTRL_ATTRIBUTE_KEY_LEN, KEY_LENGTH },
#else
  { GSA_CTRL_TYPE_ENCR, GIKE_ENCR_DEFAULT },
  { GSA_CTRL_ATTRIBUTE_KEY_LEN, KEY_LENGTH },
#endif
#ifdef GIKE_INTEG
  { GSA_CTRL_TYPE_INTEG, GIKE_INTEG },
#endif
  {GSA_CTRL_TYPE_AUTH_METHOD,IKE_AUTH_SHARED_KEY_MIC},

   /* Terminate the offer */
  { GSA_CTRL_END_OF_OFFER, 0 }
};

/**
 * GSA TEK proposal
 */
const spd_proposal_tuple_t spdconf_tek_gsa[5] =
{
  /* ESP proposal */
  { GSA_CTRL_NEW_PROPOSAL, SA_PROTO_ESP },
#ifdef ESP_ENCR
  { GSA_CTRL_TYPE_ENCR, ESP_ENCR },
  { GSA_CTRL_ATTRIBUTE_KEY_LEN, KEY_LENGTH },
#else
  { GSA_CTRL_TYPE_ENCR, EPS_ENCR_DEFAULT },
  { GSA_CTRL_ATTRIBUTE_KEY_LEN, KEY_LENGTH },
#endif

#ifdef ESP_INTEG
  { GSA_CTRL_TYPE_INTEG, ESP_INTEG },
#endif

  /* Terminate the offer */
  { GSA_CTRL_END_OF_OFFER, 0 }
};
/**
 * Convenience preprocessor commands for creating the policy table
 */
#define set_ip6addr(direction, ip6addr) \
  .ip6addr_##direction##_from = ip6addr, \
  .ip6addr_##direction##_to = ip6addr

#define set_any_peer_ip6addr() \
  .peer_addr_from = &spd_conf_ip6addr_min, \
  .peer_addr_to = &spd_conf_ip6addr_max

#define set_any_peer_not_multi() \
  .peer_addr_from = &spd_conf_ip6addr_min, \
  .peer_addr_to = &group1_id

#define set_any_peer_multi() \
  .peer_addr_from = &group1_id, \
  .peer_addr_to = &spd_conf_ip6addr_max

#define set_my_port(port) \
  .my_port_from = port, \
  .my_port_to = port

#define set_any_my_port() \
  .my_port_from = 0, \
  .my_port_to = PORT_MAX

#define set_peer_port(port) \
  .peer_port_from = port, \
  .peer_port_to = port

#define set_any_peer_port() \
  .peer_port_from = 0, \
  .peer_port_to = PORT_MAX

/**
 * IP adresses that we use in policy rules.
 *
 * spd_conf_ip6addr_init() must be called prior to using the data structures in question
 */
uip_ip6addr_t spd_conf_ip6addr_min; /* Address :: */
uip_ip6addr_t spd_conf_ip6addr_max; /* Address ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff */
uip_ip6addr_t border_router;
uip_ip6addr_t group_id;
uip_ip6addr_t group1_id; /* Address ff02::1a */
uip_ip6addr_t member1_addr;
uip_ip6addr_t member2_addr;

/**
 * Setup of the SPD. This is where you as the user enters the security policy of your system.
 *
 * Adjust SPD_ENTRIES (in spd.h) according to need.
 */
spd_entry_t spd_table[SPD_ENTRIES] =
{
  /* BYPASS IKE traffic */
  {
    .selector =
    {
      set_any_peer_ip6addr(),               /* ...from any host... */
      .nextlayer_proto = UIP_PROTO_UDP,     /* ...using UDP... */
      set_my_port(500),                     /* ...to destination port 500. */
      set_any_peer_port()                   /* ...from any source port */
    },
    .proc_action = SPD_ACTION_BYPASS,       /* No protection necessary */
    .offer = NULL,                           /* N/A */
    .security_protocol = 0
  },

  /* BYPASS mDNS traffic */
  {
    .selector =
    {
      set_any_peer_ip6addr(),               /* ...from any host... */
      .nextlayer_proto = UIP_PROTO_UDP,     /* ...using UDP... */
      set_my_port(5353),                     /* ...to destination port 500. */
      set_any_peer_port()                   /* ...from any source port */
    },
    .proc_action = SPD_ACTION_BYPASS,       /* No protection necessary */
    .offer = NULL,                           /* N/A */
    .security_protocol = 0
  },
#if WITH_IPSEC_IKE

  /*Protect all ipv6 multicast traffic for this specific group: ff1e::89:ABCD*/
  {
      .selector =
      {
    	.peer_addr_from = &group_id,
    	.peer_addr_to = &group_id,
        .nextlayer_proto = UIP_PROTO_UDP,
        set_any_my_port(),
        set_any_peer_port()
      },
      .proc_action = SPD_ACTION_PROTECT,       /* Protection rerquired */
      .offer = spdconf_tek_gsa,                           /* N/A */
      .security_protocol = SA_PROTO_ESP
    },
	  /* PROTECT all UDP traffic to host aaaa::1 */
	{
    .selector =
    {
      set_any_peer_ip6addr(),
      .nextlayer_proto = UIP_PROTO_UDP,
      /* .nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL, */
      set_any_my_port(),
      set_any_peer_port()
    },
    .proc_action = SPD_ACTION_PROTECT,
    .offer = my_ah_esp_proposal,
    .security_protocol = SA_PROTO_ESP
  },
  {
    .selector =
    {
      .peer_addr_from = &border_router,
      .peer_addr_to = &border_router,
      .nextlayer_proto = UIP_PROTO_ICMP6,
      /* .nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL, */
      set_any_my_port(),
      set_any_peer_port()
    },
    .proc_action = SPD_ACTION_PROTECT,
    .offer = my_ah_esp_proposal,
    .security_protocol = SA_PROTO_ESP
  },

  /* BYPASS all ICMP6 traffic in order to make RPL auto configuration possible */
  {
    .selector =
    {
      set_any_peer_ip6addr(),
      .nextlayer_proto = UIP_PROTO_ICMP6,
      set_any_my_port(),
      set_any_peer_port()
    },
    .proc_action = SPD_ACTION_BYPASS,       /* No protection necessary */
    .offer = NULL,                           /* N/A */
    .security_protocol = 0
  },

#endif
#if IKE_WITH_RPL
  {
    .selector =
    {
      set_any_peer_not_multi(),   /* Any source (incoming traffic), any destination (outgoing) */
      .nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL,
      set_any_my_port(),
      set_any_peer_port()
    },
    .proc_action = SPD_ACTION_PROTECT,
    .offer = my_rpl_proposal,
    .security_protocol = SA_PROTO_RPL
  },
  {
    .selector =
    {
      set_any_peer_multi(),     /* Any multicast traffic */
      .nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL,
      set_any_my_port(),
      set_any_peer_port()
    },
    .proc_action = SPD_ACTION_BYPASS,
    .offer = NULL,
    .security_protocol = 0
  },
#endif
#if IKE_WITH_IEEE
  {
    .selector =
    {
      set_any_peer_not_multi(),   /* Any source (incoming traffic), any destination (outgoing) */
      .nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL,
      set_any_my_port(),
      set_any_peer_port()
    },
    .proc_action = SPD_ACTION_PROTECT,
    .offer = my_ieee_proposal,
    .security_protocol = SA_PROTO_IEEE_802_15_4
  },
  {
    .selector =
    {
      set_any_peer_multi(),     /* Any multicast traffic */
      .nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL,
      set_any_my_port(),
      set_any_peer_port()
    },
    .proc_action = SPD_ACTION_BYPASS,
    .offer = NULL,
    .security_protocol = 0
  },
#endif
  /* DISCARD all traffic which haven't matched any prior policy rule */
  /* All IPSec implementations SHOULD exhibit this behaviour (p. 60 RFC 4301) */
  {
    .selector =
    {
      set_any_peer_ip6addr(),   /* Any source (incoming traffic), any destination (outgoing) */
      .nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL,
      set_any_my_port(),
      set_any_peer_port()
    },
    .proc_action = SPD_ACTION_DISCARD,
    .offer = NULL,
    .security_protocol = 0
  }
};

/*Group IKEv2 Keys*/
//const uint8_t *kek_encr_keys[] ={0x3b, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59};

//const uint8_t *kek_integ_keys[] = {0xcf, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63};
		//{ 0xa9, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30 }

const uint8_t kek_encr_keys[MAX_KEYS][20] ={
		{0x3b, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59},
		{0x3c, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59},
		{0x3d, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59},
		{0x3e, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59},
		{0x3f, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59}
};

const uint8_t kek_integ_keys[MAX_KEYS][KEY_LENGTH] = {
		{0xcf, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63},
		{0xa9, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30},
		{0xa7, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30},
		{0xc6, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63},
		{0xc7, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63}
};

const uint8_t kek_auth_keys[MAX_KEYS][SA_PRF_MAX_OUTPUT_LEN] = {
		{0xdf, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63,0x3d, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4},
		{0xd9, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30,0x3d, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4},
		{0xd7, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30,0x3d, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4},
		{0xd6, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63,0x3d, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4},
		{0xf7, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63,0x3d, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4}
};

const uint8_t tek_encr_keys[MAX_KEYS][20] ={
		{0x4b, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59},
		{0x4c, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59},
		{0x4d, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59},
		{0x4e, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59},
		{0x4f, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4, 0xd4, 0xa8, 0x07, 0x59}
};
const uint8_t tek_integ_keys[MAX_KEYS][KEY_LENGTH] = {
		{0xce, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63},
		{ 0xaf, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30},
		{ 0xae, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30},
		{ 0xa1, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30},
		{ 0xa2, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30}
};
					//
/*Member Entries*/
/*
 * Be careful with memberships. Members in the same group should have the same key_id[0] to indicate the same tek - kek group key.
 * Members in different groups should not indicate the same group key.
 */
member_param_t gpad_table[NUM_OF_MEMBERS]=
{
		{
				.group_id = GROUP_ID,
				.group_member= MEMBER1,
				.kek = &spdconf_kek_gsa,
				.tek = &spdconf_tek_gsa,
				.tek_spi = 1001,
				.kek_spi = 1,
				.key_id = {0},//group key row 0, individual key is in row 1 for kek. for tek seder_id[0]=0 is the group key.
				.pairwise_secret_key = SHARED_IKE_SECRET_MEMBER1,

		},
		{
				.group_id = GROUP_ID,
				.group_member= MEMBER2,
				.kek = &spdconf_kek_gsa,
				.tek = &spdconf_tek_gsa,
				.tek_spi = 1001,
				.kek_spi = 1,
				.key_id = {0},//group key row 0, individual row 2
				//.keys = &kek_keys
				.pairwise_secret_key = SHARED_IKE_SECRET_MEMBER2,


		},
		{
				.group_id = GROUP_ID,
				.group_member= MEMBER3,
				.kek = &spdconf_kek_gsa,
				.tek = &spdconf_tek_gsa,
				.tek_spi = 1001,
				.kek_spi = 1,
				.key_id = {0}, //group key in row 3, individual key in 4.
				.pairwise_secret_key = SHARED_IKE_SECRET_MEMBER3,

		},
		{
				.group_id = GROUP_ID,
				.group_member= MEMBER4,
				.kek = &spdconf_kek_gsa,
				.tek = &spdconf_tek_gsa,
				.tek_spi = 1001,
				.kek_spi = 1,
				.key_id = {0}, //group key in row 3, individual key in 4.
				.pairwise_secret_key = SHARED_IKE_SECRET_MEMBER4,
		},
		{
				.group_id = GROUP_ID,
				.group_member= MEMBER5,
				.kek = &spdconf_kek_gsa,
				.tek = &spdconf_tek_gsa,
				.tek_spi = 1001,
				.kek_spi = 1,
				.key_id = {0},
				.pairwise_secret_key = SHARED_IKE_SECRET_MEMBER5,
		}
};


void
spd_conf_init()
{
  uip_ip6addr_set_val16(spd_conf_ip6addr_min, 0x0);
  uip_ip6addr_set_val16(spd_conf_ip6addr_max, 0xffff);

  uip_ip6addr(&border_router, 0xaaaa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1);
  uip_ip6addr(&group1_id, 0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a);
  uip_ip6addr(&group_id, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
  //uip_ip6addr(&member1_addr,0xfe80, 0x0, 0x0, 0x0, 0x212, 0x4b00, 0x60d, 0x9ec1); //mote 23
  //uip_ip6addr(&member2_addr,0xfe80, 0x0, 0x0, 0x0, 0x212, 0x4b00, 0x615, 0xa592); //mote 6
}
/** @} */
