/*
 * Author: Runar Mar Magnusson <rmma@kth.se>
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
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \addtogroup ipsec
 * @{
 */

#include "cert-conf.h"
#include "ecc-sha1.h"

#if DEBUG
#define CERT_CONF_DBG_PRINT 1
#else
#define CERT_CONF_DBG_PRINT 0
#endif

#if CERT_CONF_DBG_PRINT
#include <stdio.h>
#include <stdlib.h>
#include "common-ipsec.h"
#define PRINTF(...) printf(__VA_ARGS__)
#define MEMPRINT(...) memprint(__VA_ARGS__)
#define HEXDUMP(...) hexdump(__VA_ARGS__)
#else
#define PRINTF(...)
#define MEMPRINT(...)
#define HEXDUMP(...)
#endif

#define DEFAULT_KEY_AUTHORITY { 0x00 }

/** Change this to change the public key of the CA
 * The subject public key info element contains the public key algorithm
 * and the subject public key.
 */
#ifdef CERT_KEY_AUTHORITY
static uint8_t ca_pub_key_info_element[] = CERT_KEY_AUTHORITY;
#else
#warning Define CERT_KEY_AUTHORITY in ipsec-conf with \
  #define CERT_KEY_AUTHORITY {0x##,...}
static uint8_t ca_pub_key_info_element[] = DEFAULT_KEY_AUTHORITY; /* To avoid other compile errors */
#endif

#if WITH_CONF_IKE_CERT_AUTH || SOURCE_AUTH

#ifdef CLIENT_CERT
static uint8_t client_cert[] = CLIENT_CERT;
#else
#error Define CLIENT_CERT in ipsec-conf with \
  #define CLIENT_CERT {0x##,...}
static uint8_t client_cert[] = { 0x00 }; /* To avoid other compile errors */
#endif

#ifdef CLIENT_PRIVATE_CERT_KEY
static uint8_t client_private_key[] = CLIENT_PRIVATE_CERT_KEY;
#else
#error Define CLIENT_PRIVATE_CERT_KEY in ipsec-conf with \
  #define CLIENT_PRIVATE_CERT_KEY {0x##,...}
static uint8_t client_private_key[] = { 0x00 }; /* To avoid other compile errors */
#endif
#endif

/*---------------------------------------------------------------------------*/
uint8_t
gen_cert_authority(uint8_t cert_authority[SHA1_CERT_HASH_LEN])
{
  int err = 0;
  SHA1Context sha;
  memset(cert_authority, 0, SHA1_CERT_HASH_LEN);

  err = SHA1Reset(&sha);
  if(err != shaSuccess) {
    PRINTF("SHA1Reset error %d in gen_cert_authority\n", err);
    return 0;
  }

  err = SHA1Input(&sha, ca_pub_key_info_element, sizeof(ca_pub_key_info_element));
  if(err != shaSuccess) {
    PRINTF("SHA1Input error %d in gen_cert_authority\n", err);
    return 0;
  }

  err = SHA1Result(&sha, cert_authority);
  if(err != shaSuccess) {
    PRINTF("SHA1Result error %d in gen_cert_authority\n", err);
    return 0;
  }

  return 1;
}
/*---------------------------------------------------------------------------*/
uint8_t *get_ca_public_key()
{
  return &ca_pub_key_info_element[sizeof(ca_pub_key_info_element) - CA_PUB_KEY_LEN];
}
/*---------------------------------------------------------------------------*/
#if WITH_CONF_IKE_CERT_AUTH || SOURCE_AUTH
uint8_t
load_certificate(struct dtls_certificate_context_t *client_cert_ctx)
{
  PRINTF("Loading the client certificate");
  uint16_t cert_len = 0;

  cert_len = cert_parse(client_cert, sizeof(client_cert), client_cert_ctx);

  if(cert_len == 0) {
    PRINTF("Certificate loading failure\n");
    return 0;
  }
  PRINTF("Certificate loading successful\n");
  return 1;
}
/*---------------------------------------------------------------------------*/
uint8_t
*get_certificate_hex(uint16_t *cert_len)
{
  uint16_t len = sizeof(client_cert);
  *cert_len = len;
  if(len > 0) {
    PRINTF("Cert len longer than 0\n");
    return &client_cert[0];
  } else {
    return NULL;
  }
}
/*---------------------------------------------------------------------------*/
uint8_t
*get_cert_private_key()
{
  if(sizeof(client_private_key) == CA_PRI_KEY_LEN) {
    return client_private_key;
  } else {
    return &client_private_key[7];
  }
}
/*---------------------------------------------------------------------------*/
#endif /* WITH_CONF_IKE_CERT_AUTH */
/** @} */
