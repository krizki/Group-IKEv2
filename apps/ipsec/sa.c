/**
 * \addtogroup ipsec
 * @{
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

/**
 * \file
 *    Length of material consumed or produced by cryptographic functions used by IPsec
 * \author
 *    Vilhelm Jutvik <ville@imorgon.se>
 *    Runar Mar Magnusson <rmma@kth.se>
 *
 */

#include <contiki.h>

/**
 * Additional KEYMAT length of each "encr" transform
 *
 * The length of the keying material (KEYMAT) for any given encryption transform
 * is dependent upon:
 *   > If the encryption transform is of variable key length:
 *        Attribute as given by the IKEv2 negotiation
 *   > If the encryption transform is of fixed key length:
 *        Key size is determined solely by the transform type
 *   > Additional requirements (e.g. AES-CTR also expects a nonce in addition
 *     to its key: key material (variable) + 4 bytes (nonce)
 *   > Other requirements, AES-CCM requires a 3 byte salt that is used in the
 *     nonce along with the IV
 * The keymat length of any "encr" transform is defined as follows:
 *   Length specified in key length attribute + sa_encr_keymat_extralen[encr transform id]
 *
 * This framework is believed to suit all "encr" transforms defined for
 * IKEv2 and IPsec, with the exception of those having "default key lengths"
 * as described in RFC 5996, p. 85:
 *
 *    "Some transforms allow variable-length keys, but also specify a default
 *     key length if the attribute is not included.
 *     For example, these transforms include ENCR_RC5 and ENCR_BLOWFISH."
 */
const uint8_t sa_encr_keymat_extralen[] =
{
  0,  /* NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* 3DES. NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* NOT IN USE */
  0,  /* NULL */
  0,  /* AES CBC. Completely determined by the key length attribute. */
  4,  /* AES CTR. Nonce length is 4 byte (RFC 3686, section 5.1) */
  3,  /* ENCR_AES-CCM_8, Salt length for nonce is 3 bytes  See RFC 4309, section 7.1 */
  3,  /* ENCR_AES-CCM_12, Salt length for nonce is 3 bytes  See RFC 4309, section 7.1 */
  3,  /* ENCR-AES-CCM_16. Salt length for nonce is 3 bytes  See RFC 4309, section 7.1 */
};

/**
 * IV size in bytes of each encryption transform.
 *
 * This includes IVs of block as well as stream ciphers. In the former case
 * the IV size is also the same as the transform's block size.
 *
 * NOTE REGARDING NULL ENCRYPTION:
 * The block size of NULL encryption is actually different for IP ESP payloads
 * (length 0) and IKE SK payloads (length 1). The value below reflects the SK case.
 */
const uint8_t sa_encr_ivlen[] =
{
  0,    /* Reserved                                       N/A */
  0,    /* ENCR_DES_IV64                                  (not implemented) */
  0,    /* ENCR_DES                                       (not implemented) */
  8,    /* ENCR_3DES                                      (not implemented) */
  0,    /* ENCR_RC5                                       (not implemented) */
  0,    /* ENCR_IDEA                                      (not implemented) */
  0,    /* ENCR_CAST                                      (not implemented) */
  0,    /* ENCR_BLOWFISH                                  (not implemented) */
  0,    /* ENCR_3IDEA                                     (not implemented) */
  0,    /* ENCR_DES_IV32                                  (not implemented) */
  0,    /* Reserved                                       N/A */
  1,    /* NULL (its block size). SEE NOTE above!         (implemented) */
  16,   /* ENCR_AES_CBC                                   (not implemented) */
  8,    /* ENCR_AES_CTR. See RFC 3686, section 4          (implemented) */
  8,    /* ENCR_AES-CCM_8. See RFC 4309, section 3.1      () */
  8,    /* ENCR-AES-CCM_12. See RFC 4309, section 3.1 */
  8,    /* ENCR-AES-CCM_16. See RFC 4309, section 3.1 */
};

/**
 * ICV lengths for authenticated algorithms (AES-CCM)
 */
const uint8_t sa_encr_icvlen[] =
{
  0,    /* Reserved                                       N/A */
  0,    /* ENCR_DES_IV64                                  (not implemented) */
  0,    /* ENCR_DES                                       (not implemented) */
  0,    /* ENCR_3DES                                      (not implemented) */
  0,    /* ENCR_RC5                                       (not implemented) */
  0,    /* ENCR_IDEA                                      (not implemented) */
  0,    /* ENCR_CAST                                      (not implemented) */
  0,    /* ENCR_BLOWFISH                                  (not implemented) */
  0,    /* ENCR_3IDEA                                     (not implemented) */
  0,    /* ENCR_DES_IV32                                  (not implemented) */
  0,    /* Reserved                                       N/A */
  0,    /* NULL (its block size). SEE NOTE above!         (implemented) */
  0,    /* ENCR_AES_CBC                                   (not implemented) */
  0,    /* ENCR_AES_CTR. See RFC 3686, section 4          (implemented) */
  8,    /* ENCR_AES-CCM_8. See RFC 4309, section 3.1      () */
  12,   /* ENCR-AES-CCM_12. See RFC 4309, section 3.1 */
  16,   /* ENCR-AES-CCM_16. See RFC 4309, section 3.1 */
};

/**
 * Authenticator lengths (output lengths) of the PRFs in bytes.

 * Also, from p.46, second paragraph:
 *
 * "For PRFs based on the HMAC construction, the preferred key size is equal to
 * the length of the output of the underlying hash function. Other types of PRFs
 * MUST specify their preferred key size."
 *
 * The output length of each IKE PRF is defined in its standard document.
 */
const uint8_t sa_prf_output_len[] =
{
  0,            /* Reserved */
  0,            /* PRF_HMAC_MD5                           (not implemented) */
  20,           /* PRF_HMAC_SHA1                          (implemented) */
  0,            /* PRF_HMAC_TIGER                         (not implemented) */
  0,            /* PRF_AES128_XCBC                        (not implemented) */
  32,           /* PRF_HMAC_SHA2_256. See RFC 4686        (not implemented) */
};

/**
 * Preferred key length of the PRFs in bytes. (where key length is length of K in PRF(K, S))
 *
 * According to p.46, second paragraph:
 *  "It is assumed that PRFs accept keys of any length, but have a preferred
 *  key size. The preferred key size MUST be used as the length of SK_d,
 *  SK_pi, and SK_pr (see Section 2.14). For PRFs based on the HMAC construction,
 *  the preferred key size is equal to the length of the output of the
 *  underlying hash function. Other types of PRFs MUST specify their preferred
 *  key size."
 *
 * The output length of each IKE PRF is defined in its standard document.
 */
const uint8_t sa_prf_preferred_keymatlen[] =
{
  0,            /* Reserved */
  0,            /* PRF_HMAC_MD5                           (not implemented) */
  20,           /* PRF_HMAC_SHA1                          (implemented) */
  0,            /* PRF_HMAC_TIGER                         (not implemented) */
  0,            /* PRF_AES128_XCBC                        (not implemented) */
  32,           /* PRF_HMAC_SHA2_256. See RFC 4868        (not implemented) */
};

/**
 * KEYMAT length of each integrity/auth transform in bytes.
 *
 * As of RFC 5996, no transform of type 2 nor 3 uses variable key length (p. 85).
 * The same passage also recommends this as the future behaviour of
 * type 2 and 3 transforms.
 */
const uint8_t sa_integ_keymatlen[] =
{
  0,
  12, /* MD5                                              (not implemented) */
  20, /* SHA1_96                                          (not implemented) */
  0,  /* AUTH_DES_MAC                                     (not implemented) */
  0,  /* AUTH_KPDK_MD5                                    (not implemented) */
  16, /* AUTH_AES_XCBC_96                                 (implemented) */
  0,  /* AUTH_HMAC_MD5_128 */
  0,  /* AUTH_HMAC_SHA1_160 */
  0,  /* AUTH_AES_CMAC_96 */
  0,  /* AUTH_AES_128_GMAC */
  0,  /* AUTH_AES_192_GMAC */
  0,  /* AUTH_AES_256_GMAC */
  32,  /* AUTH_HMAC_SHA2_256_128                          (implemented) */
};

/**
 * ICV lengths of different integrity transforms
 */
const uint8_t sa_integ_icvlength[] =
{
  0,
  0, /* MD5                                              (not implemented) */
  12, /* SHA1_96                                          (not implemented) */
  0,  /* AUTH_DES_MAC                                     (not implemented) */
  0,  /* AUTH_KPDK_MD5                                    (not implemented) */
  12, /* AUTH_AES_XCBC_96                                 (implemented) */
  0,  /* AUTH_HMAC_MD5_128 */
  0,  /* AUTH_HMAC_SHA1_160 */
  0,  /* AUTH_AES_CMAC_96 */
  0,  /* AUTH_AES_128_GMAC */
  0,  /* AUTH_AES_192_GMAC */
  0,  /* AUTH_AES_256_GMAC */
  16,  /* AUTH_HMAC_SHA2_256_128                          (implemented) */
};

/** @} */
