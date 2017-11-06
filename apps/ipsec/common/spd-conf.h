/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *  SPD configuration
 * \details
 *  This file contains functions for SPD configuration.
 *
 *  All values and definitions described herein pertains to RFC 4301 (Security Architecture for IP) and
 *  RFC 5996 (Internet Key Exchange Protocol Version 2). Sections of special interests are:
 *
 *  RFC 4301: 4.4.1 (Security Policy Database)
 *  RFC 5996: 3.3 (Security Association Payload)
 *
 *       Please see spd.h for a quick overview of the data format.
 * \author
 *	Vilhelm Jutvik <ville@imorgon.se>
 *       Runar Mar Magnusson <rmma@kth.se> - Added default configuration
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

#ifndef __SPD_CONF_H__
#define __SPD_CONF_H__

#include "spd.h"

extern spd_entry_t spd_table[];
extern const spd_proposal_tuple_t spdconf_ike_proposal[];
extern const spd_proposal_tuple_t spdconf_ike_open_proposal[];

/*
 * Group member parameters.
 */


typedef struct {
	//struct member_param_t *next;
	uip_ip6addr_t *group_id;
	uip_ip6addr_t *group_member;
	spd_proposal_tuple_t *kek;
	spd_proposal_tuple_t *tek;
	uint32_t tek_spi;
	uint32_t kek_spi;
	//sa_encr_transform_type_t encr;
	//uint16_t key_len;
	//sa_integ_transform_type_t integ;
	//kek_management_algorithm_t mng;
	//kek_auth_method_t auth_method;	//authentication algorithm is always same
	uint8_t key_id[1];//we consider only one key to be sent for GSAK.
	uint8_t pairwise_secret_key[PAIRWISE_SHARED_IKE_SECRET_LEN];
	uint8_t active;
}member_param_t;



//extern member_param_t member_conf_init(void);
extern member_param_t gpad_table[];
extern const uint8_t kek_encr_keys[MAX_KEYS][20];
extern const uint8_t kek_integ_keys[MAX_KEYS][16];
extern const uint8_t tek_encr_keys[MAX_KEYS][20];
extern const uint8_t tek_integ_keys[MAX_KEYS][16];
extern const uint8_t kek_auth_keys[MAX_KEYS][SA_PRF_MAX_OUTPUT_LEN];
/* Section "3.4.  Key Exchange Payload" specifies an interdependence between the IKE proposal's */
/* MODP group and the KE payload. The following define states this common property. */
#define CURRENT_IKE_PROPOSAL spdconf_ike_proposal

/* Default transforms */
/* We define aes-ccm_8 as the default encryption transform so we don't have to
   define a default integrity transform */
#define IKE_ENCR_DEFAULT SA_ENCR_AES_CCM_8
#define IKE_PRF_DEFAULT SA_PRF_HMAC_SHA1
#define EPS_ENCR_DEFAULT SA_ENCR_AES_CCM_8

/* Change the default modgroup from 192-bit to 256-bit*/
#if WITH_CONF_IKE_CERT_AUTH
#define IKE_DH_DEFAULT SA_DH_256_RND_ECP_GROUP
#undef IKE_DH
#define IKE_DH IKE_DH_DEFAULT
#else
#define IKE_DH_DEFAULT SA_DH_192_RND_ECP_GROUP
#endif

/* Set the modgroup based on the configuration*/
#ifndef IKE_DH
#define IKE_DH IKE_DH_DEFAULT
#endif
#define SA_IKE_MODP_GROUP IKE_DH

#endif

/** @} */
