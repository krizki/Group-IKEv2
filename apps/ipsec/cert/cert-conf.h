/*
 * Copyright (c) 2015, Runar Mar Magnusson.
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
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *   Certificate configuration for the node
 * \details
 *   Contains certificates and public keys used with IKE
 * \author
 *   Runar Mar Magnusson <rmma@kth.se>
 */

#ifndef CERT_CONF_H
#define CERT_CONF_H

#include "contiki.h"
#include "ecc.h"
#include "cert-parser.h"
#include "bigint.h"
#include "payload.h"

#define CA_PUB_KEY_LEN 64
#define CA_PRI_KEY_LEN 32 /** We only support 256-bit keys for certificates*/

#define CA_KEY_BYTE_LEN 32 /** Number of bytes in a key */
#define CA_KEY_WORD_LEN 8 /** Number of 32-bit words in a key */

/**
 * Generates the SHA-1 hash of the public key info element used in the certificate
 * request payload
 * @param cert_authority
 * @return 1 if successful 0 otherwise
 */
uint8_t gen_cert_authority(uint8_t cert_authority[SHA1_CERT_HASH_LEN]);

/**
 * Load our certificate to a certificate context
 * @param client_cert
 * @return 1 if successful, 0 otherwise
 */
uint8_t load_certificate(struct dtls_certificate_context_t *client_cert);

/**
 * Returns a pointer to our CA public key defined in ipsec-conf
 * @return a pointer to the public key of the CA
 */
uint8_t *get_ca_public_key();

/**
 * Returns a pointer to our certificate defined in ipsec-conf.
 * @param cert_len the length of the certificate
 * @return A pointer to our certificate
 */
uint8_t *get_certificate_hex(uint16_t *cert_len);

/**
 * Get a pointer to our certificate private key.
 * @return A pointer to our private key
 */
uint8_t *get_cert_private_key();

#endif /* CERT_CONF_H */

/** @} */