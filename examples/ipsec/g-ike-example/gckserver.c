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
#include "net/rpl/rpl.h"
#include "net/netstack.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include <string.h>


#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"
#include "net/rpl/rpl.h"

#if WITH_IPSEC
#include "machine.h"
#include "sad.h"
#include "ike.h"
#include "g-ike-conf.h"
#endif

#if WITH_COMPOWER
#include "powertrace.h"
#endif

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define MAX_PAYLOAD_LEN 120
#define PERIOD 30 * CLOCK_SECOND
#define GROUP_MEMBER_LISTENING_PORT 3000
#define SERVER_LISTENING_PORT 3001
PROCESS(udp_server_process, "UDP server process");

#if WITH_OPENMOTE
#include "flash-erase.h"
AUTOSTART_PROCESSES(&udp_server_process, &flash_erase_process);
#else
AUTOSTART_PROCESSES(&udp_server_process);
#endif

static struct uip_udp_conn *server_conn;

/*---------MULTICAST FUNCIONS--------------*/
//static char buf[MAX_PAYLOAD_LEN];

/*
static void
multicast_send(void)
{
	static int multicast_seq_id;

  printf("GCKS sending to: ");
  PRINT6ADDR(&server_conn->ripaddr);
  sprintf(buf, "Hello %d from the GCKS", ++multicast_seq_id);
  printf(" (msg: %s)\n", buf);
#if SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION
  uip_udp_packet_send(server_conn, buf, UIP_APPDATA_SIZE);
#else
//SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION
  uip_udp_packet_send(server_conn, buf, strlen(buf));
#endif
//SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION

  // Restore server connection to allow data from any node
//memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));

}
*/

/*
static void prepare_mcast(void)
{
  uip_ipaddr_t ipaddr;


  //  IPHC will use stateless multicast compression for this destination
  //	(M=1, DAC=0), with 32 inline bits (1E 89 AB CD)

  uip_ip6addr(&ipaddr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
  server_conn = udp_new(&ipaddr, UIP_HTONS(GROUP_MEMBER_LISTENING_PORT), NULL); //Connecting to the members port 3000
  udp_bind(server_conn, UIP_HTONS(SERVER_LISTENING_PORT)); // set local port 3001
}*/

/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{

	  char *str;

	  if(uip_newdata()) {
	    str = uip_appdata;
	    str[uip_datalen()] = '\0';
	    printf("Message received: '%s'\n", str);

	//static int seq_id;
  //char buf[MAX_PAYLOAD_LEN];

 /* if(uip_newdata()) {
    ((char *)uip_appdata)[uip_datalen()] = 0;
    PRINTF("Server received: '%s' from ", (char *)uip_appdata);
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF("\n");

    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
    PRINTF("Responding with message: ");
    sprintf(buf, "Hello from the server! (%d)", ++seq_id);
    PRINTF("%s\n", buf);

    uip_udp_packet_send(server_conn, buf, strlen(buf));*/
    /* Restore server connection to allow data from any node */
   // memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
  }
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: ");
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
#if UIP_CONF_ROUTER
static void
set_global_addresses(void){

	uip_ipaddr_t ipaddr;
	uip_ds6_maddr_t *rv;
	struct uip_ds6_addr *root_if;

	uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0,0,0);
	//uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
	uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
	uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
	root_if = uip_ds6_addr_lookup(&ipaddr);

  if(root_if != NULL) {
    rpl_dag_t *dag;
    dag = rpl_set_root(RPL_DEFAULT_INSTANCE, (uip_ip6addr_t *)&ipaddr);
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &ipaddr, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
  /*-----------JOIN MULTICAST GROUP-----------------*/
  uip_ip6addr(&ipaddr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
  rv = uip_ds6_maddr_add(&ipaddr);

  if(rv) {
    PRINTF("Joined multicast group ");
    PRINT6ADDR(&uip_ds6_maddr_lookup(&ipaddr)->ipaddr);
    PRINTF("\n");
  }


}
#endif /* UIP_CONF_ROUTER */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{

#if WITH_COMPOWER
 // static int print = 0;
#endif

  PROCESS_BEGIN();

  PROCESS_PAUSE();
#if WITH_MINIMALNET
  uip_ipaddr_t server_ipaddr;
  uip_ip6addr(&server_ipaddr, 0xfdfd, 0, 0, 0, 0, 0xff, 0xfe00, 0x10); /*minimal-net*/
  uip_ds6_addr_add(&server_ipaddr, 0, ADDR_MANUAL);
#endif
  PRINTF("UDP server started\n");


  set_global_addresses();

  print_local_addresses();
  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(server_conn, UIP_HTONS(SERVER_LISTENING_PORT));


#if WITH_COMPOWER
  powertrace_sniff(POWERTRACE_ON);
#endif
  gsak_entries_init();

while(1) {
    PROCESS_YIELD();
    //SEND A MULTICAST WHEN THE client sends a message


    if(ev == tcpip_event) {
#if WITH_COMPOWER

         powertrace_print("#P UDP<");
   #endif
            tcpip_handler();
    #if WITH_COMPOWER
         /* if(print == 0) {
            powertrace_print("#P UDP");
          }
          if(++print == 3) {
            print = 0;
          }*/
          powertrace_print("#P UDP>");
    #endif
        }


}
  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
