/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    Length of material consumed or produced by cryptographic functions used by IPsec
 * \author
 *	Vilhelm Jutvik <ville@imorgon.se>
 *      Runar Mar Magnusson <rmma@kth.se>
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

#ifndef __SA_H__
#define __SA_H__

#include <contiki.h>
#include <stdio.h>
#include "uip.h"
/* #include "bigint.h" */
#include "g-ike-conf.h"

#if IKE_WITH_RPL
#include "rpl/rpl-sa.h"
#endif

/**
 * This source code is part of an implementation of RFC 5996, 4301 and 4307.
 */

/* IKEv2 proposal attribute ID for Key Length */
#define SA_ATTRIBUTE_KEYLEN_ID 14

/**
 * The following enumerated types pertains to RFC 4307 "IKEv2 Cryptographic Algorithms"
 *
 * Although the transform payload's "transform id" field is 16 bits large,
 * the enums declared below and the code elsewhere is only capable of handling
 * 8 bit values. I deem this as sufficient given the fact that all currently
 * defined IDs are well below 255.
 */
/* DH */
#define SA_UNASSIGNED_TYPE 255
typedef enum {
  SA_DH_1024_MODP_GROUP = 2,            /* MUST- */
  SA_DH_2048_MODP_GROUP = 14,           /* SHOULD+ */
  SA_DH_256_RND_ECP_GROUP = 19,         /* [RFC5903] */
  SA_DH_384_RND_ECP_GROUP,              /* [RFC5903] */
  SA_DH_521_RND_ECP_GROUP,              /* [RFC5903] */
  SA_DH_1024_MODP_GROUP_160_PRIME,      /* [RFC5114] */
  SA_DH_2048_MODP_GROUP_224_PRIME,      /* [RFC5114] */
  SA_DH_2048_MODP_GROUP_256_PRIME,      /* [RFC5114] */
  SA_DH_192_RND_ECP_GROUP,              /* [RFC5114] */
  SA_DH_224_RND_ECP_GROUP,              /* [RFC5114] */
  SA_DH_224_BP_GROUP,                   /* [RFC6954] */
  SA_DH_256_BP_GROUP,                   /* [RFC6954] */
  SA_DH_384_BP_GROUP,                   /* [RFC6954] */
  SA_DH_512_BP_GROUP,                   /* [RFC6954] */
  SA_DH_UNASSIGNED = 255
} sa_dh_transform_type_t;

/**
 * DH key sizes.
 */
#define IKE_DH_SCALAR_BUF_LEN (NUMWORDS * WORD_LEN_BYTES)  /* Length of ECC's buffer in the session struct */
#define IKE_DH_SCALAR_LEN IKE_DH_SCALAR_BUF_LEN  /* Length of a deserialized scalar */
#define IKE_DH_POINT_LEN (2 * IKE_DH_SCALAR_LEN)  /* Length of a deserialized point */

/**
 * Transform type #1 for ESP and IKEv2: Encryption (confidentiality / combined mode)
 *
 * Implementation requirements for IKEv2 according to RFC4307 (2005) and IPsec RFC4835 (2007)
 */
typedef enum {                  /* RFC4307      Status of this implementation */
  SA_ENCR_RESERVED = 0,
  SA_ENCR_3DES = 3,             /* MUST-          Status of this implementation */
  SA_ENCR_NULL = 11,            /* MAY            IMPLEMENTED */
  SA_ENCR_AES_CBC = 12,         /* SHOULD+        FIX: IN PROGRESS */
  SA_ENCR_AES_CTR = 13,         /* SHOULD         IMPLEMENTED */
  SA_ENCR_AES_CCM_8 = 14,       /* MAY            IMPLEMENTED */
  SA_ENCR_AES_CCM_12 = 15,      /* MAY            IMPLEMENTED */
  SA_ENCR_AES_CCM_16 = 16,      /* MAY            IMPLEMENTED */
  SA_ENCR_UNASSIGNED = 255
} sa_encr_transform_type_t;

/**
 * IMPORTANT!
 *
 * This value must be equal to the following:
 * The maximum encryption keylength that we can negotiate (currently 16 bytes)
 *   -plus-
 * The greatest value of sa_encr_keymat_extralen[] (from sad.c)
 */
#define SA_ENCR_MAX_KEYMATLEN 20

extern const uint8_t sa_encr_ivlen[];
extern const uint8_t sa_encr_keymat_extralen[];
extern const uint8_t sa_encr_icvlen[];
extern const uint8_t sa_prf_preferred_keymatlen[];
extern const uint8_t sa_prf_output_len[];
#define SA_ENCR_CURRENT_IVLEN(session) sa_encr_ivlen[(session)->sa.encr]
#define SA_ENCR_IVLEN_BY_TYPE(encr) sa_encr_ivlen[encr]
#define SA_ENCR_CURRENT_KEYMATLEN(session) (sa_encr_keymat_extralen[(session)->sa.encr] + (session)->sa.encr_keylen)
#define SA_ENCR_KEYMATLEN_BY_SA(sa) (sa_encr_keymat_extralen[(sa).encr] + (sa).encr_keylen)

/* For authenticated encryption algorithms */
#define SA_ENCR_ICV_LEN(session) (sa_encr_icvlen[(session)->sa.encr])
#define SA_ENCR_ICV_LEN_BY_TYPE(encr) sa_encr_icvlen[encr]

/**
 * Transform type #2 for IKEv2 only: Pseudorandom functions
 *
 * Implementation requirements for IKEv2 according to RFC4307 (2005)
 */
typedef enum {                  /* RFC4307      Status of this implementation */
  SA_PRF_RESERVED = 0,
  SA_PRF_HMAC_MD5 = 1,          /* MAY-         NOT IMPLEMENTED */
  SA_PRF_HMAC_SHA1 = 2,         /* MUST         IMPLEMENTED */
  SA_PRF_AES128_CBC = 4,        /* SHOULD+      NOT IMPLEMENTED */
  SA_PRF_HMAC_SHA2_256 = 5,     /* MAY          IMPLEMENTED */
  SA_PRF_UNASSIGNED = 255
} sa_prf_transform_type_t;

#define SA_PRF_MAX_OUTPUT_LEN 32  /* This value must be the maximum value of sa_prf_output_len[] */
#define SA_PRF_MAX_PREFERRED_KEYMATLEN 32   /* This value must be the maximum value of sa_prf_preferred_keymatlen */
#define SA_PRF_PREFERRED_KEYMATLEN(session) sa_prf_preferred_keymatlen[session->sa.prf]
#define SA_PRF_OUTPUT_LEN(session) sa_prf_output_len[session->sa.prf]
#define SA_PRF_OUTPUT_LEN_BY_ID(prf) sa_prf_output_len[prf]

/**
 * Transform type #3 for ESP, AH and IKEv2: Integrity
 *
 * Implementation requirements for IKEv2 according to RFC 4307 (2005) and IPsec RFC 4835 (2007)
 */
typedef enum {                            /* RFC4307    RFC4835 Status of this implementation */
  SA_INTEG_NONE = 0,                      /* N/A        MUST    IMPLEMENTED */
  SA_INTEG_HMAC_MD5_95 = 1,               /* MAY        MAY     NOT IMPLEMENTED */
  SA_INTEG_HMAC_SHA1_96 = 2,              /* MUST       MUST    IMPLEMENTED */
  SA_INTEG_AES_XCBC_MAC_96 = 5,           /* SHOULD+    SHOULD+ IMPLEMENTED */
  SA_INTEG_HMAC_SHA2_256_128 = 12,        /* MAY        MAY     IMPLEMENTED */

  SA_INTEG_UNASSIGNED = 255
} sa_integ_transform_type_t;

extern const uint8_t sa_integ_keymatlen[];
extern const uint8_t sa_integ_icvlength[];

#define SA_INTEG_MAX_KEYMATLEN 32    /* This value must be the maximum value of sa_integ_keymatlen */
#define SA_INTEG_CURRENT_KEYMATLEN(session) sa_integ_keymatlen[session->sa.integ]
#define SA_INTEG_KEYMATLEN_BY_TYPE(integ) sa_integ_keymatlen[integ]
#define SA_INTEG_ICV_LEN(session) sa_integ_icvlength[session->sa.integ]
#define SA_INTEG_ICV_LEN_BY_TYPE(integ) sa_integ_icvlength[integ]

/* Extended Sequence Numbers (4 vs 6 bytes). */
/* (This implementation only supports the former.) */
typedef enum {
  SA_ESN_NO,
  SA_ESN_YES
} sa_esn_type_t;

/**
 * Transform type values (section 3.3.2, p. 80).
 */
typedef enum {
  /* Transform types as described on p. 80 in RFC 5996 */
  SA_CTRL_TRANSFORM_TYPE_ENCR = 1, /* Encryption Algorithm (ESP, IKE) */
  SA_CTRL_TRANSFORM_TYPE_PRF,     /* Pseudorandom function (IKE) */
  SA_CTRL_TRANSFORM_TYPE_INTEG,   /* Integrity Algorithm (IKE, AH, ESP (optional)) */
  SA_CTRL_TRANSFORM_TYPE_DH,      /* Diffie-Hellman group (IKE, AH (optional), ESP (optional)) */
  SA_CTRL_TRANSFORM_TYPE_ESN,     /* Extended Sequence Numbers (AH, ESP) (not supported by this implementation) */

  /* Internal control types that are specific to this implementation */
  SA_CTRL_NEW_PROPOSAL = 100,     /* Value type: Protocol ID (sa_ipsec_proto_type_t) */
  SA_CTRL_ATTRIBUTE_KEY_LEN,      /* Value type: Key length _in bytes_ of encryption algorithm */
  SA_CTRL_END_OF_OFFER            /* Value is ignored */
} sa_ctrl_t;




/* KEK management algorithm ~ With none or with LKH.
 * In the future more KEK management algorithms can be implemented. */
typedef enum {
	NO_GKM = 0,		/* Without any KEK management algorithm.*/
	LKH = 1
}kek_management_algorithm_t;

typedef enum{
	NO_CERT = 0,
	CERT = 1
}kek_auth_method_t;

/* KEK attribute types for Group Security Associations */
typedef enum {
  /* KEK Attributes specified in internet draft G-IKEv2 page 18 */
	GSA_CTRL_TYPE_MNG_ALGORITHM = 1,
	GSA_CTRL_TYPE_ENCR, 			/* Encryption Algorithm (ESP, IKE) */
	GSA_CTRL_TYPE_INTEG,   			/* Integrity Algorithm (IKE, AH, ESP (optional)) */
	GSA_CTRL_TYPE_AUTH_METHOD,      /* Authentication method used */
	//GSA_CTRL_TYPE_AUTH_ALGORITHM,	/* Hash algorithm used to generate AUTH KEY to authenticate GSA_REKEY message */

  /* Internal control types that are specific to this implementation */
  GSA_CTRL_NEW_PROPOSAL = 100,     /* Value type: Protocol ID (sa_ipsec_proto_type_t) */
  GSA_CTRL_ATTRIBUTE_KEY_LEN,      /* Value type: Key length _in bytes_ of encryption algorithm */
  GSA_CTRL_END_OF_OFFER            /* Value is ignored */
} kek_gsa_ctrl_t;


/*
 * Key Download parameters
 */
/* KEK key packet attribute types*/
typedef enum{
	KEK_ENCR_KEY = 1,
	KEK_INTEGRITY_KEY,
	KEK_AUTH_KEY,
	TEK_ENCR_KEY,
	TEK_INTEGRITY_KEY,
	NO_MORE_KEYS = 100
}key_type_t;


/**
 * Protocol IDs as described in section 3.3.1, p. 79.
 */
typedef enum {
  SA_PROTO_IKE = 1,
  SA_PROTO_AH,
  SA_PROTO_ESP,
} sa_ipsec_proto_type_t;

/**
 * SA entry for IKE
 *
 * Important relationships of the keys:

   SKEYSEED = prf(Ni | Nr, g^ir)
   {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                   = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )

   For deriving key material for the child SAs:

   KEYMAT = prf+(SK_d, Ni | Nr)
 */
typedef struct {
  sa_encr_transform_type_t encr;    /* ESP, IKE */
  sa_prf_transform_type_t prf;      /* IKE */
  sa_integ_transform_type_t integ;  /* IKE, AH, ESP (optional) */
  sa_dh_transform_type_t dh;        /* IKE, AH (optional), ESP (optional) */

  /* Always */
  /**
   * SK_d is used for generating subsequent child SA keying materials (KEYMAT).
   * The length is a function of the negotiated PRF. From p.47:

     "The lengths of SK_d, SK_pi, and SK_pr MUST be the preferred key length
     of the PRF agreed upon."
   */
  /* Used for derivation of further keying material for Child SAs.
   * Length MUST equal the key size of the PRF. */
  uint8_t sk_d[SA_PRF_MAX_OUTPUT_LEN];

  /**
   * IKE SA authentication / integrity KEYMAT. (Often the K in PRF(K, M))
   *
   * If the key length of the transform denoted by integ is shorter than
   * SA_INTEG_MAX_KEYMATLEN the residual bytes will be ignored.
   */
  uint8_t sk_ai[SA_INTEG_MAX_KEYMATLEN];
  uint8_t sk_ar[SA_INTEG_MAX_KEYMATLEN];

  /**
   * IKE SA encryption KEYMAT.
   *
   * If the key length, denoted by encr_keylen, is shorter than SA_INTEG_MAX_KEYMATLEN
   * the residual bytes will be ignored.
   */
  uint8_t sk_ei[SA_ENCR_MAX_KEYMATLEN];
  uint8_t sk_er[SA_ENCR_MAX_KEYMATLEN];

  uint8_t encr_keylen; /* Length of key _in bytes_ */
} sa_ike_t;

/* Must be in the same order as */
typedef struct {
  sa_ipsec_proto_type_t proto;
  sa_encr_transform_type_t encr;    /* ESP, IKE */
  sa_integ_transform_type_t integ;  /* IKE, AH, ESP (optional) */
  /* DH: IKE, AH (optional), ESP (optional) (We don't support new DH secrets for child SAs) */

  /* IKE SA integrity */
  uint8_t sk_a[SA_INTEG_MAX_KEYMATLEN];

  /* IKE SA encryption */
  uint8_t sk_e[SA_ENCR_MAX_KEYMATLEN];

  /* Length of sk_e key _in bytes_. Only used by ESP.
   * A value of 0 signifies that this SA is used in conjunction with the AH protocol. */
  /* (We can do this as the key length of the ESP protocol is given by its attribute,
   * while the key length of the AH protocol is solely determined by its transform type). */
  uint8_t encr_keylen;
} sa_child_t;

/*typedef struct {
	struct kek_kd_t* next;
	uint8_t encr_key[SA_ENCR_MAX_KEYMATLEN];
	uint8_t integ_key[SA_INTEG_MAX_KEYMATLEN];

}kek_kd_t;
*/
typedef struct{
	struct gsak_entry_t* next;
	uip_ip6addr_t group_id; //used by gckserver and member
	uint32_t spi;
	sa_encr_transform_type_t encr;

	sa_integ_transform_type_t integ;
	kek_management_algorithm_t mng;
	uint8_t auth_method;	//authentication algorithm is always same
	uint8_t key_len;
	uint8_t rekey_case; //This indicates that a new member triggered the rekey, therefore the server should send the new kek kd as well. Prieodic Rekeying = 0, Join Rekeying = 1, Leave Rekeying = 2 and 3
	uint8_t msg_id;
	uint8_t key_index;
	struct ctimer rekey_timer;
	uint8_t encr_key[SA_ENCR_MAX_KEYMATLEN]; //1 row, assuming that there is only one group key.
	uint8_t integ_key[KEY_LENGTH];
	uint8_t auth_key[SA_PRF_MAX_OUTPUT_LEN];
}gsak_entry_t;

/* Macro that returns true if the sa_child_t at child_sa_ptr is for the AH protocol, false if it's ESP. */
/* Macros that */
#define IKE_CHILD_SA_IS_ESP(child_sa) (child_sa->proto == SA_PROTO_ESP)
#define IKE_CHILD_SA_IS_AH(child_sa) (child_sa->proto == SA_PROTO_AH)

#if IKE_WITH_RPL
#define IKE_CHILD_SA_IS_RPL(child_sa) (child_sa->proto == SA_PROTO_RPL)
#endif

#if IKE_WITH_IEEE_802_15_4
#define IKE_CHILD_SA_IS_IEEE_802_15_4(child_sa) (child_sa->proto == SA_PROTO_IEEE_802_15_4)
#endif

/**
 * Macro for setting the algorithm specifications of an SA to "unassigned".
 *
 * We simply write a four byte ULONG_MAX to the beginning of the struct. This will
 * change the value of sk_d in sa_child as well, but this side-effect doesn't affect
 * the behaviour of the implementation.
 *
 * sa should be of type sa_child_t or sa_ike_t
 */
#define SA_UNASSIGN_SA(sa_ptr) *((uint32_t *)sa_ptr) = ULONG_MAX

/**
 * Access the algorithm properties of the sa* structs by index
 *
 * sa_ptr is a pointer of either sa_child_t or sa_ike_t
 * type is of type sa_ctrl_t
 */
#define SA_GET_PARAM_BY_INDEX(sa_ptr, type) *(((uint8_t *)sa_ptr) + type - 1)



#endif

/** @} */
