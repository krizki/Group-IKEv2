/*
 * File:   ieee-802-15-4-traffc-selector.h
 * Author: user
 *
 * Created on July 22, 2015, 7:24 AM
 */

#ifndef IEEE_802_15_4_TRAFFIC_SELECTOR_H
#define IEEE_802_15_4_TRAFFIC_SELECTOR_H

#include "net/ip/uip.h"

#if IPSEC_DEBUG
#define PRINTIEEEADDRSET(addr_set) \
  do { \
    PRINTF("Peer address from to: "); \
    PRINTLLADDR((addr_set)->peer_addr_from); \
    PRINTLLADDR((addr_set)->peer_addr_to); \
    PRINTF("\nNextlayer proto: %u\n", (addr_set)->nextlayer_proto); \
    PRINTF("My ports: %u - %u\n", (addr_set)->my_port_from, (addr_set)->my_port_to); \
    PRINTF("Peer ports: %u - %u\n", (addr_set)->peer_port_from, (addr_set)->peer_port_to); \
  } while(0)

#else
#define PRINTIEEEADDRSET(...)
#endif

/* An ipsec_addr_set_t struct represents a set of incoming or outgoing traffic
 * (or their union). Depending on the direction of the traffic,
 * the semantics of the fields differ.
 *
 * The peer_addr_from field is a pointer to an IPv6 address that marks the
 * beginning of a closed address range, peer_addr_to marks its end.
 * This address range is coupled to a packet's source address
 * if it's incoming traffic, its destination address otherwise.
 *
 * nextlayer_proto is the next layer protocol's type.
 */
typedef struct {
  uip_lladdr_t *peer_lladdr_from, *peer_lladdr_to;
} ieee_addr_set_t;

/**
 * Traffic selector (p. 105)
 *
                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 **+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |   TS Type     |Reserved        |       Selector Length         |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                                |
   ~          Starting IEEE 802.15.4 long Address                 ~
 |                                                                |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                                |
   ~          Ending IEEE 802.15.4 long Address                   ~
 |                                                                |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

              Figure 20: Traffic Selector
 */
/* Only IPv6 type selectors are supported */
#define IKE_PAYLOADFIELD_TS_802_15_4_ADDR 10
#define IKE_PAYLOADFIELD_TS_IEEE_SELECTOR_LEN (sizeof(ike_ieee_ts_t))
#define SET_TSSELECTOR_IEEE_INIT(ts) \
  (ts)->ts_type = IKE_PAYLOADFIELD_TS_802_15_4_ADDR; \
  (ts)->selector_len = uip_htons(sizeof(ike_ieee_ts_t))

#define SET_TSSAME_IEEE_ADDR(ts, addr) \
  memcpy((ts)->start_addr, addr, sizeof(uip_lladdr_t)); \
  memcpy((ts)->end_addr, addr, sizeof(uip_lladdr_t))

typedef struct {
  uint8_t ts_type;
  uint8_t clear;
  uint16_t selector_len;
  uip_lladdr_t start_addr;
  uip_lladdr_t end_addr;
} ike_ieee_ts_t;

#endif /* IEEE_802_15_4_TRAFFIC_SELECTOR_H */
