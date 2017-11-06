/**
 * \addtogroup ipsec
 * @{
 */
/*
 * Copyright (c) 2015, SICS
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
 *        IPsec and IKEv2 configuration
 * \author
 *        Simon Duquennoy <simonduq@sics.se>
 *	  Vilhelm Jutvik <ville@imorgon.se>
 *        Runar Mar Magnusson <rmma@kth.se>
 */

#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <contiki-conf.h>
#include "net/ip/uip.h"
#include "sa.h"

#if WITH_CONF_IPSEC_AH
#define WITH_IPSEC_AH     WITH_CONF_IPSEC_AH
#if WITH_IPSEC_SICSLOWPAN
#define WITH_IPSEC_AH_SICSLOWPAN 1
#endif
#else
#define WITH_IPSEC_AH     0
#endif

#if WITH_CONF_IPSEC_ESP
#define WITH_IPSEC_ESP     WITH_CONF_IPSEC_ESP
#if WITH_IPSEC_SICSLOWPAN
#define WITH_IPSEC_ESP_SICSLOWPAN 1
#endif
#else
#define WITH_IPSEC_ESP     0
#endif

#if WITH_CONF_IPSEC_IKE
#ifndef WITH_IPSEC_IKE
#define WITH_IPSEC_IKE  1
#endif
#else
#ifndef WITH_IPSEC_IKE
#define WITH_IPSEC_IKE  0
#endif
#endif

#ifndef WITH_IPSEC
#define WITH_IPSEC    (WITH_IPSEC_ESP | WITH_IPSEC_AH)
#endif

/**
 * Debbugging for IKEv2 and IPsec
 */
#define IKE "IKEv2: "
#define IPSEC "IPsec: "
#define IPSEC_ERROR "IPsec error: "

/**
 * IPsec / IKEv2 debug configuration options are set here!
 *
 * There are more debuging options in uip6.c
 */
#ifndef IPSEC_DEBUG
#define IPSEC_DEBUG 0
#endif

/**
 * IPSEC/IKE Informational printouts
 */
#ifndef IKE_IPSEC_INFO
#define IKE_IPSEC_INFO 1
#endif

/* Turn on timing measurements with info messages  default off with info*/
#ifndef IPSEC_TIME_STATS
#define IPSEC_TIME_STATS 0
#endif

#if IPSEC_DEBUG
#include <stdio.h>
#define IPSEC_PRINTF(...) printf(__VA_ARGS__)
#define PRINTIPSEC6ADDR(addr) uip_debug_ipaddr_print(addr)
#define PRINTIPSECLLADDR(lladdr) IPSEC_PRINTF(" %02x:%02x:%02x:%02x:%02x:%02x ", lladdr->addr[0], lladdr->addr[1], lladdr->addr[2], lladdr->addr[3], lladdr->addr[4], lladdr->addr[5])
/* #define PRINTIPSEC6ADDR(addr) */
#define IPSEC_MEM_STATS 0
#else
#define IPSEC_MEM_STATS 1
#define IPSEC_PRINTF(...)
#define PRINTIPSEC6ADDR(addr)
#define PRINTIPSECLLADDR(lladdr)
#endif

/* End debug configuration options */

/**
 * IP header types for ESP and AH
 */
#define UIP_PROTO_ESP   50
#define UIP_PROTO_AH    51

#define UIP_ESP_BUF ((struct uip_esp_header *)&uip_buf[uip_l2_l3_hdr_len])

/* ESP header as defined in RFC 2406 */
struct uip_esp_header {
  uint32_t spi;
  uint32_t seqno;
};

/* AH header as defined in RFC 4302 (NOT used)*/
struct uip_ah_header {
  unsigned char next;
  unsigned char len;
  uint16_t reserved;
  uint32_t spi;
  uint32_t seqno;
  /* unsigned char     mac[IPSEC_MACSIZE]; */
};

/* The length of extension headers data coming after the payload */
extern uint8_t uip_ext_end_len;

#endif /* __IPSEC_H__ */
/** @} */
