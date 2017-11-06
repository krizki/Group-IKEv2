/*
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

/*  cert-parser.h
 *
 *
 *  This is a parser for X.509 ECC Certificates in PEM format that use
 *  ecdsa-sha keys.
 *
 *  It consists of two parts:
 *    I)  base64 decoding
 *    II) Parsing the decoded Certificate in its elements.
 *
 *  Created on: 16.01.2013
 *      Author: Hossein Shafagh <hossein.shafagh@rwth-aachen.de>
 */

#ifndef CERT_PARSER_H_
#define CERT_PARSER_H_

#include <stdint.h>
#include "ecc.h"
#include "bigint.h"

/* This struct holds pointers to different components of a Certificate in
 * process.
 */
typedef struct dtls_certificate_context_t {
  unsigned char *TBSCertificate;
  uint16_t TBSCertificate_len;
  unsigned char *issuer;
  uint16_t issuer_len;
  unsigned char *subject;
  uint16_t subject_len;
  unsigned char *subject_pub_key;
  uint16_t subject_pub_key_len;
  unsigned char *signature;
} dtls_certificate_context_t;

uint16_t decode_b64(unsigned char *in, unsigned char *out, uint16_t len_in);
uint8_t cert_parse(const unsigned char *certificate,
                   const uint16_t certificate_len,
                   struct dtls_certificate_context_t *cert_ctx);
uint8_t cert_verfiy_signature(struct dtls_certificate_context_t *cert_ctx,
                              unsigned char *public_key_signer);

#endif /* CERT_PARSER_H_ */
