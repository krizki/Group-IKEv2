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
 *        Authentication for IKEv2
 * \author Vilhelm Jutvik <ville@imorgon.se>
 * \author Runar Mar Magnusson <rmma@kth.se> - ECDSA signature authentication
 *
 */

/**
 * \addtogroup ipsec
 * @{
 */


#include "contiki-conf.h"
#include "common-ike.h"
#include <stdio.h>
#include "auth.h"

#include "ecc.h"
#include "bigint.h"
#include "cert/cert-conf.h"
#include "cert/cert-parser.h"

/* Debugging of authentication */
#ifndef DEBUG_AUTH
#define DEBUG_AUTH 0
#endif

#if DEBUG_AUTH
#define PRINTF_DBG(...) printf(__VA_ARGS__)
#define PRINTF_ERROR(...) printf(__VA_ARGS__)
#define HEXDUMP(...) hexdump(__VA_ARGS__)
#else
#define PRINTF_DBG(...)
#define PRINTF_ERROR(...) printf(__VA_ARGS__)
#define HEXDUMP(...)
#endif

/**
 * \name IKEv2 ID data
 * @{
 */
/* The shared key used in the AUTH payload. The shared secret is defined in ipsec-conf* / */
const uint8_t ike_auth_sharedsecret[32] = SHARED_IKE_SECRET;

/* The length of ike_id _must_ be a multiple of 4 (as implied in "Identification payload" in RFC 5996) */
const uint8_t ike_id[] = IKE_ID;

static const uint8_t auth_keypad[17] = { 'K', 'e', 'y', ' ', 'P', 'a', 'd', ' ', 'f', 'o', 'r', ' ', 'I', 'K', 'E', 'v', '2' };

/** @} */

/**
 * \brief Implementation of AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"),
 * <*SignedOctets>) as seen on p. 49.
 * Used for authentication with pre-shared keys.
 *
 * \note auth_data should be set up in the following way:
 * auth_data->out = out;
 * auth_data->data = signed_octets;
 * auth_data->datalen = signed_octets_len;
 */
void
auth_psk(uint8_t transform, prf_data_t *auth_data)
{
  const uint8_t prf_out_len = SA_PRF_OUTPUT_LEN_BY_ID(transform);
  uint8_t data_out[prf_out_len];

  /* Perform the inner PRF operation */
  prf_data_t keypad_arg = {
    .out = data_out,
    .key = ike_auth_sharedsecret,
    .keylen = sizeof(ike_auth_sharedsecret),
    .data = (uint8_t *)auth_keypad,
    .datalen = sizeof(auth_keypad)
  };
  prf(transform, &keypad_arg);

  PRINTF_DBG("IKE AUTH: Result from inner prf operation: %u\n", prf_out_len);
  HEXDUMP(data_out, prf_out_len);

  /* Perform the outer PRF operation */
  auth_data->key = data_out;
  auth_data->keylen = prf_out_len;

  prf(transform, auth_data);

  PRINTF_DBG("IKE AUTH: Result from outer prf operation: %u\n", auth_data->keylen);
  HEXDUMP(auth_data->out, auth_data->keylen);
}
/**
 * \brief ECDSA signature generation and verification used in the IKE_AUTH exchange
 *
 * This function performs both the ecdsa signature generation and verification
 * of the IKE_AUTH exchange
 *
 * \param cert_ctx the peer's cert_ctx, used in verification
 * \param sign, is 0 if the signed octets should be verified, 1 if a signature should be generated
 */
uint8_t
auth_ecdsa(dtls_certificate_context_t *cert_ctx, uint8_t sign, uint8_t *signed_octets,
           uint16_t signed_octets_len, uint8_t *auth_data, uint16_t *auth_data_len)
{
  if(sign) {
#if WITH_CONF_IKE_CERT_AUTH || SOURCE_AUTH
    /* Generating a signature */
    u_word r[CA_KEY_WORD_LEN];
    u_word s[CA_KEY_WORD_LEN];
    u_word priv_key[CA_KEY_WORD_LEN];

    /* Initialize r and s*/
    bigint_null(r, CA_KEY_WORD_LEN);
    bigint_null(s, CA_KEY_WORD_LEN);

    uint16_t private_key_len = CA_PRI_KEY_LEN;
    bigint_decode(priv_key, CA_KEY_WORD_LEN, get_cert_private_key(), CA_PRI_KEY_LEN);

    PRINTF_DBG("Private Key %u\n", private_key_len);
    HEXDUMP(priv_key, private_key_len);

    ecc_generate_signature(priv_key, signed_octets, signed_octets_len, s, r);

    if(!bigint_is_zero(r, CA_KEY_WORD_LEN) && !bigint_is_zero(s, CA_KEY_WORD_LEN)) {
      *auth_data_len = 2 * (CA_KEY_BYTE_LEN);

      /* Encode the signature */
      bigint_encode(auth_data, CA_KEY_BYTE_LEN, r, CA_KEY_WORD_LEN);
      bigint_encode(auth_data + CA_KEY_BYTE_LEN, CA_KEY_BYTE_LEN, s, CA_KEY_WORD_LEN);

      PRINTF_DBG("AUTH data generated %u\n", *auth_data_len);
      HEXDUMP(auth_data, *auth_data_len);

      PRINTF_DBG("AUTH r part\n");
      HEXDUMP(auth_data, CA_KEY_BYTE_LEN);
      PRINTF_DBG("AUTH s part\n");
      HEXDUMP(auth_data + CA_KEY_BYTE_LEN, CA_KEY_BYTE_LEN);

      return 1;
    } else {
      PRINTF_ERROR("AUTH: ECDSA signature generation failed\n");
      return 0;
    }
#else
    PRINTF_ERROR("AUTH: ECDSA signatures not configured in ipsec-conf.h\n");
    return 0;
#endif
  } else {
    /* Verifying a signature */
    u_word r[CA_KEY_WORD_LEN];
    u_word s[CA_KEY_WORD_LEN];
    ecc_point_a cert_pub;

    /* Initialize r and s */
    bigint_null(r, CA_KEY_WORD_LEN);
    bigint_null(s, CA_KEY_WORD_LEN);

    PRINTF_DBG("Signed octets %u\n", signed_octets_len);
    HEXDUMP(signed_octets, signed_octets_len);

    PRINTF_DBG("AUTH data generated %u\n", *auth_data_len);
    HEXDUMP(auth_data, *auth_data_len);

    bigint_decode(r, CA_KEY_WORD_LEN, auth_data, CA_KEY_BYTE_LEN);
    bigint_decode(s, CA_KEY_WORD_LEN, auth_data + CA_KEY_BYTE_LEN, CA_KEY_BYTE_LEN);

    bigint_decode(cert_pub.x, CA_KEY_WORD_LEN, cert_ctx->subject_pub_key, CA_KEY_BYTE_LEN);
    bigint_decode(cert_pub.y, CA_KEY_WORD_LEN, cert_ctx->subject_pub_key + CA_KEY_BYTE_LEN,
                  CA_KEY_BYTE_LEN);

    PRINTF_DBG("Public Key %u\n", CA_PUB_KEY_LEN);
    HEXDUMP(cert_ctx->subject_pub_key, CA_PUB_KEY_LEN);

    uint8_t result = 0;

    result = ecc_check_signature(&cert_pub, signed_octets, signed_octets_len, s, r);
    PRINTF_DBG("Result from Signature verification %u", result);

    /* Return 1 if SUCCESSFUL, 0 if there was a failure */
    if(result) {
      return 1;
    }
    PRINTF_ERROR("AUTH: ECDSA signature verification failed\n");
    return 0;
  }
}
/** @} */

