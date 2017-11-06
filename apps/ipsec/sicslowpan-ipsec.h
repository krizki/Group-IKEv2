/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *         6lowpan extension for IPsec
 * \author
 *         Simon Duquennoy <simonduq@sics.se>
 *         Runar Mar Magnusson <rmma@kth.se> - additions from draft-raza-6lo-ipsec-01
 */

#ifndef __SICSLOWPAN_IPSEC_H__
#define __SICSLOWPAN_IPSEC_H__

#include "net/ip/uip.h"
#include "ipsec.h"

#define SICSLOWPAN_ESP_BUF  ((struct uip_esp_header *)&sicslowpan_buf[UIP_LLIPH_LEN])
#define SICSLOWPAN_AH_BUF   ((struct uip_ah_header *)&sicslowpan_buf[UIP_LLIPH_LEN])

/* 6lowpan IPsec extension */
#define SICSLOWPAN_NHC_DEFAULT_SPI                  1000
#define SICSLOWPAN_NHC_IPSEC_BASE                   0xEB /* IPv6 EH starts with 1110, IPsec EID is 101, next header (AH or ESP) is always compressed */
#define SICSLOWPAN_NHC_IPSEC_SPI0                   0x00 /* SPI compression (== DEFAULT_SPI) */
#define SICSLOWPAN_NHC_IPSEC_SPI1                   0x04 /* SPI compression (1 bytes instead of 4)*/
#define SICSLOWPAN_NHC_IPSEC_SPI2                   0x08 /* SPI compression (2 bytes instead of 4)*/
#define SICSLOWPAN_NHC_IPSEC_SPI3                   0x0C /* SPI uncompressed )*/
#define SICSLOWPAN_NHC_IPSEC_SN0                    0x00 /* Seqno compression (1 bytes instead of 4)*/
#define SICSLOWPAN_NHC_IPSEC_SN1                    0x01 /* Seqno compression (2 bytes instead of 4)*/
#define SICSLOWPAN_NHC_IPSEC_SN2                    0x02 /* Seqno compression (3 bytes instead of 4)*/
#define SICSLOWPAN_NHC_IPSEC_SN3                    0x03 /* Seqno uncompression */

/* 6lowpan ESP */
#define SICSLOWPAN_NHC_ESP_ID                       0xE0 /* ESP EH starts with 1110 */

/* 6lowpan AH */
#define SICSLOWPAN_NHC_AH_ID                        0xD0 /* AH EH starts with 1101 */
#define SICSLOWPAN_NHC_AH_PL                        0x08 /* Payload Len compression (inferred from crypto suite) */

#endif /* __SICSLOWPAN_IPSEC_H__ */

/** @} */
