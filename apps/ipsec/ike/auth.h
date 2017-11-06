/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    Authentication for IKEv2
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
#include "cert-parser.h"
#include "prf.h"
#ifndef SHARED_IKE_SECRET
#warning Using default shared secret, define a shared secret in ipsec-conf.h
#warning With #define SHARED_IKE_SECRET "<32-byte-long-string>"
#define SHARED_IKE_SECRET "aa280649dc17aa821ac305b5eb09d445"
#endif

#ifndef IKE_ID
#define IKE_ID "test@sics.se"
#endif

/**
 * IKEv2 ID
 */
extern const uint8_t ike_auth_sharedsecret[32];
extern const uint8_t ike_id[16];
extern const uint8_t cert_id[21];

extern void auth_psk(uint8_t transform, prf_data_t *auth_data);

extern uint8_t auth_ecdsa(dtls_certificate_context_t *cert_ctx, uint8_t sign, uint8_t *signed_octets,
                          uint16_t signed_octets_len, uint8_t *auth_data, uint16_t *auth_data_len);
/**
 * Authentication methods used in the IKE AUTH payload
 */
typedef enum {
  IKE_AUTH_METHOD_RSA_SIG = 1,
  /*
      Computed as specified in Section 2.15 using an RSA private key
      with RSASSA-PKCS1-v1_5 signature scheme specified in [PKCS1]
      (implementers should note that IKEv1 used a different method for
      RSA signatures).  To promote interoperability, implementations
      that support this type SHOULD support signatures that use SHA-1
      as the hash function and SHOULD use SHA-1 as the default hash
      function when generating signatures.  Implementations can use the
      certificates received from a given peer as a hint for selecting a
      mutually understood hash function for the AUTH payload signature.
      Note, however, that the hash algorithm used in the AUTH payload
      signature doesn't have to be the same as any hash algorithm(s)
      used in the certificate(s).
   */

  IKE_AUTH_SHARED_KEY_MIC,
  /*
     Shared Key Message Integrity Code
     Computed as specified in Section 2.15 using the shared key
     associated with the identity in the ID payload and the negotiated
     PRF.
   */

  IKE_AUTH_DSS_SIG,
  /*
     Computed as specified in Section 2.15 using a DSS private key
     (see [DSS]) over a SHA-1 hash.
   */

  IKE_AUTH_ECDSA_256_SHA_256 = 9,   /* [RFC4754] (Implemented) */
  IKE_AUTH_ECDSA_384_SHA_384,       /* [RFC4754] (NOT Implemented) */
  IKE_AUTH_ECDSA_521_SHA_521,       /* [RFC4754] (NOT Implemented) */
  IKE_AUTH_SECURE_PWD,              /* [RFC6467] (NOT Implemented) */
  IKE_AUTH_NULL,                    /* [draft-ietf-ipsecme-ikev2-null-auth] */
  IKE_AUTH_DIGITAL_SIG,             /* [RFC7427] */
} ike_auth_type_t;

/** @} */
