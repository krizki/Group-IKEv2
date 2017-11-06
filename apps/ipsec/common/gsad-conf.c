/*
/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file gsad-conf.c
 *    Configuration of manual GSAs
 * \author
 *
 *  Created on: Jun 18, 2016
 *      Author: Argyro Lamproudi <arglam90@gmail.com>
 *
 * /
*/

#include <string.h>

#include "uip.h"
#include "sad.h"
#include "common-ipsec.h"

/**
 * Set your IP-adresses
 */
static uip_ip6addr_t ip6_link_local_gckserver; //mote 22 fe80::212:4b00:60d:9f4c
static uip_ip6addr_t ip6_link_local_client23; //mote 23 fe80::212:4b00:60d:9ec1
static uip_ip6addr_t ip6_link_local_client6; //mote 6 fe80::212:4b00:615:a592
static uip_ip6addr_t ip6_multicast; //multicast IPv6


void
gsad_conf()
{
  /**
   * This is where the administrator of the group can add manual GSAs to the GSAD.
   *
   * With manual SAs you don't need to use the IKE component, but you also have
   * to perform key management manually (changing keys, addresses etc) and will
   * lose anti-replay protection (see sad.h).
   *
   * Please keep in mind that:
   *   -> The SAD is unordered and its contents may change during runtime.
   *   -> Any predefined SAD entry must be defined in such a way that
   *     its memory is persistent during the runtime of the IPsec subsystem.
   *     i.e. use the storage class static or declare the sad_entry_t -variables in the global scope.
   *   -> The SPI must be a value in the range > 0 and < SAD_DYNAMIC_SPI_START.
   */

  /**
   * This is an example of how to add a two manual GSAs to the GSAD.
   */

  /**
   * Initialize the IP address that your configuration will refer to.
   *
   * Some memory can be saved here by handling the byte order issue prior to run time.
   */
  uip_ip6addr(&ip6_link_local_gckserver, 0xfe80, 0x0, 0x0, 0x0, 0x212, 0x4b00, 0x60d, 0x9f4c); /* An example address */
  uip_ip6addr(&ip6_link_local_client23, 0xfe80, 0x0, 0x0, 0x0, 0x212, 0x4b00, 0x60d, 0x9ec1);
  uip_ip6addr(&ip6_link_local_client6, 0xfe80, 0x0, 0x0, 0x0, 0x212, 0x4b00, 0x615, 0xa592);
  uip_ip6addr(&ip6_multicast, 0xff1e,0x0,0x0,0x0,0x0,0x0,0x89,0xabcd);

  /**
   * Create an INCOMING entry. time_of_creation is set to 0, distinguishing the entry as a manual one.
   * Doing so will disable anti-replay protection (see RFC 4301, section 4.5).
   */
  sad_entry_t *my_incoming_entry = NULL;
  my_incoming_entry = sad_create_incoming_entry(0);
  if(my_incoming_entry == NULL) {
    IPSEC_PRINTF(IPSEC_ERROR "Panic! Could not set up static SAs\n");
    return;
  }

  /**
   * Upon the return of sad_create_incoming_entry() we need to set GSA and Traffic Descriptor and SPI.
   *
   * This will match all incoming UDP traffic from the GCKS IPv6 address. The clients will use this incoming entry.
   */
  /* Source address range for client incoming traffic*/

  //my_incoming_entry->traffic_desc.peer_addr_from = &ip6_link_local_gckserver;
  //my_incoming_entry->traffic_desc.peer_addr_to = &ip6_link_local_gckserver;

  /*source address range for gckserver incoming traffic*/
  my_incoming_entry->traffic_desc.peer_addr_from = &ip6_link_local_client23;
  my_incoming_entry->traffic_desc.peer_addr_to = &ip6_link_local_client23;

  my_incoming_entry->traffic_desc.nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL;
  /* No HTONS needed here as the maximum and miniumum unsigned ints are represented the same way */
  /* in network as well as host byte order. */
  my_incoming_entry->traffic_desc.my_port_from = 0;
  my_incoming_entry->traffic_desc.my_port_to = PORT_MAX;
  my_incoming_entry->traffic_desc.peer_port_from = 0;
  my_incoming_entry->traffic_desc.peer_port_to = PORT_MAX;

  /**
   * Set the parameters of the SA.
   */

  const uint8_t integ_key[] = { 0xcf, 0x5f, 0xaa, 0xca, 0x70, 0xee, 0x5e, 0xc4, 0xc8, 0xf4, 0x31, 0x58, 0xa4, 0x5c, 0x03, 0x63 };
  /* const uint8_t integ_key[] = { 0xa9, 0x5f, 0x84, 0x3c, 0xe3, 0xd1, 0xfd, 0xc9, 0x9d, 0xcc, 0xbe, 0xf8, 0x23, 0x8a, 0xf1, 0x30 }; */
  const uint8_t encr_key[] =
  {
    0x3b, 0xda, 0x5b, 0x6c, 0x05, 0x59, 0x5d, 0xe5, 0x64, 0x2b, 0xf6, 0x13, 0xf8, 0xd1, 0xaf, 0xd4,  /* 128 bit key */
    0xd4, 0xa8, 0x07, 0x59 /* 32 bit nonce */
  };
  my_incoming_entry->sa.proto = SA_PROTO_ESP;
 // my_incoming_entry->sa.encr = SA_ENCR_AES_CTR;
  my_incoming_entry->sa.encr = SA_ENCR_AES_CCM_8;
  //my_incoming_entry->sa.integ = SA_INTEG_AES_XCBC_MAC_96;

 // memcpy(my_incoming_entry->sa.sk_a, &integ_key, sizeof(integ_key));
  memcpy(my_incoming_entry->sa.sk_e, &encr_key, sizeof(encr_key));
  //my_incoming_entry->sa.encr_keylen = 16; /* 128 bits encryption keylength */
 my_incoming_entry->sa.encr_keylen = 8;
  /* We may assign any SPI value that's below the range of automatic SPIs (SAD_DYNAMIC_SPI_START) */
  /* Important: Keep in mind that the SAD stores the SPIs in network byte order */
  //my_incoming_entry->spi = UIP_HTONL(2);//for client
  my_incoming_entry->spi = UIP_HTONL(1);//for server

  /**
   * Create an OUTGOING entry. time_of_creation is set to 0 in order to mark is as manual,
   * thus disabling anti-replay protection.
   */
  sad_entry_t *my_outgoing_entry = NULL;
  my_outgoing_entry = sad_create_outgoing_entry(0);

  if(my_outgoing_entry == NULL) {
    IPSEC_PRINTF(IPSEC_ERROR "Panic! Could not set up static SAs\n");
    return;
  }

  /**
   * Upon the return of sad_create_outgoing_entry() we need to set GSA, Traffic Descriptor and spi.
   *
   * This will match all outgoing UDP traffic from the address peer.
   */
  /* Destination address range */
  my_outgoing_entry->traffic_desc.peer_addr_from = &ip6_multicast;
  my_outgoing_entry->traffic_desc.peer_addr_to = &ip6_multicast;
  my_outgoing_entry->traffic_desc.nextlayer_proto = SPD_SELECTOR_NL_ANY_PROTOCOL;

  my_outgoing_entry->traffic_desc.my_port_from = 0;
  my_outgoing_entry->traffic_desc.my_port_to = PORT_MAX;
  my_outgoing_entry->traffic_desc.peer_port_from = 0;
  my_outgoing_entry->traffic_desc.peer_port_to = PORT_MAX;

  /**
   * Set the parameters of the SA. We use the same key as that of the incoming because we're lazy.
   */
  my_outgoing_entry->sa.proto = SA_PROTO_ESP;

  my_outgoing_entry->sa.encr = SA_ENCR_AES_CCM_8;
  //my_outgoing_entry->sa.encr = SA_ENCR_AES_CTR;
//my_outgoing_entry->sa.integ = SA_INTEG_AES_XCBC_MAC_96;
  //memcpy(my_outgoing_entry->sa.sk_a, &integ_key, sizeof(integ_key)); /* 12 bytes */
  memcpy(my_outgoing_entry->sa.sk_e, &encr_key, sizeof(encr_key));   /* 16 bytes */
  //my_outgoing_entry->sa.encr_keylen = 16;
  my_outgoing_entry->sa.encr_keylen = 8;

  /* We may assign any SPI value whatsoever since the key of outgoing */
  /* SAD entries is the traffic descriptor, not the SPI. */
  /* Important: Keep in mind that the SAD stores the SPIs in network byte order */
  //my_outgoing_entry->spi = UIP_HTONL(1);//for client
  my_outgoing_entry->spi = UIP_HTONL(2); //for server
}
/** @} */
