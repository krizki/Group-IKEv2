/*
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
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-udp-packet.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "g-ike-example-conf.h"

#if WITH_IPSEC
#include "machine.h"
#include "sad.h"
#include "ike.h"
#include "g-ike-conf.h"
#endif

#include <string.h>
#include <stdbool.h>

#if WITH_COMPOWER
#include "powertrace.h"
#endif

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define SEND_INTERVAL   15 * CLOCK_SECOND
#define MAX_PAYLOAD_LEN   40
#define GROUP_MEMBER_LISTENING_PORT 3000
#define MULTICAST_PORT 3001

static struct uip_udp_conn *client_conn;
static struct uip_udp_conn *multi_conn;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
#if WITH_OPENMOTE
#include "flash-erase.h"
AUTOSTART_PROCESSES(&udp_client_process, &flash_erase_process);
#else
AUTOSTART_PROCESSES(&udp_client_process);
#endif
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;

  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    printf("Message received: '%s'\n", str);

  /* count2++;
      PRINTF("In: [0x%08lx], TTL %u, total %u\n",
      uip_ntohl((unsigned long) *((uint32_t *)(uip_appdata))),
      UIP_IP_BUF->ttl, count2);*/
  }
}
/*---------------------------------------------------------------------------*/
static char buf[MAX_PAYLOAD_LEN];
static void
timeout_handler(void)
{
  static int seq_id;

  printf("Client sending to: ");
  PRINT6ADDR(&client_conn->ripaddr);
  sprintf(buf, "Hello %d from the client", ++seq_id);
  printf(" (msg: %s)\n", buf);
#if SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION
  uip_udp_packet_send(client_conn, buf, UIP_APPDATA_SIZE);
#else /* SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION */
  uip_udp_packet_send(client_conn, buf, strlen(buf));
#endif /* SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION */
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      printf("i = %d \n", i);
    }
  }
}
/*---------------------------------------------------------------------------*/
#if UIP_CONF_ROUTER
static uip_ds6_maddr_t *
set_global_address(void)
{
  uip_ipaddr_t ipaddr;
  uip_ds6_maddr_t *rv;
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
/*#if WITH_OPENMOTE

  uip_ipaddr_t server_ipaddr;
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0212, 0x4b00,0x60d,0x9f4c); //mote no 22 as server
#else

   uip_ip6addr(&server_ipaddr, 0xfdfd, 0, 0, 0, 0, 0xff, 0xfe00, 0x10); //WITH_MINIMALNET
#endif*/
    /*-----------JOIN MULTICAST GROUP-----------------*/
    //uip_ip6addr(&ipaddr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
    uiplib_ipaddrconv(GROUP_ID, &ipaddr);
    rv = uip_ds6_maddr_add(&ipaddr);

    if(rv) {
      PRINTF("Joined multicast group ");
      PRINT6ADDR(&uip_ds6_maddr_lookup(&ipaddr)->ipaddr);
      PRINTF("\n");
    }
    return rv;
}
#endif /* UIP_CONF_ROUTER */

static void prepare_mcast(void)
{
  uip_ipaddr_t ipaddr;

  /*
   * IPHC will use stateless multicast compression for this destination
   * (M=1, DAC=0), with 32 inline bits (1E 89 AB CD)
   */
  uip_ip6addr(&ipaddr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
  client_conn = udp_new(&ipaddr, UIP_HTONS(MULTICAST_PORT), NULL); //Connecting to the members port 3000
  udp_bind(client_conn, UIP_HTONS(GROUP_MEMBER_LISTENING_PORT)); // set local port 3001
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

clock_time_t start_time = clock_time();
printf("Start time: %lu\n", (uint32_t)(start_time));

#if WITH_COMPOWER
  powertrace_sniff(POWERTRACE_ON);
  powertrace_print("#P IKE Init <");
#endif
  static struct etimer et;
  static uint8_t count1 = 0;
#if WITH_COMPOWER
  static int print = 0;
#endif

  set_global_address();

  PRINTF("UDP client process started\n");
  print_local_addresses();
  etimer_set(&et, SEND_INTERVAL);
  /* new connection with GCKServer - multicast address */
#if CLIENT_SEND_MULTICAST
  prepare_mcast();

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
  UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

#else
  uip_ip6addr_t server_ipaddr;

  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0212, 0x4b00,0x60d,0x9f4c); //mote no 22 as server
  client_conn = udp_new(&server_ipaddr, UIP_HTONS(MULTICAST_PORT), NULL);
  udp_bind(client_conn, UIP_HTONS(GROUP_MEMBER_LISTENING_PORT));
#endif

#if WITH_COMPOWER
  powertrace_print("#P IKE Init >");
#endif

  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
#if WITH_COMPOWER
  powertrace_print("#P UDP out");
#endif
      timeout_handler();
#if WITH_COMPOWER
  powertrace_print("#P UDP out");
#endif
      etimer_restart(&et);
    } else if(ev == tcpip_event){
        printf("we are here \n");
    	tcpip_handler();

#if WITH_COMPOWER
  powertrace_print("#P UDP");
#endif
    }
#if WITH_IPSEC
    else if(ev == ike_negotiate_done) {
          printf("IKE Negotiation done event %u\n", count1);
          multi_conn = udp_new(NULL, UIP_HTONS(UIP_HTONS(0)), NULL);
          udp_bind(multi_conn, UIP_HTONS(MULTICAST_PORT)); /* This will set lport to IKE_UDP_PORT */
          multi_conn->rport = 0;
          uip_create_unspecified(&multi_conn->ripaddr);
    }
#endif
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
