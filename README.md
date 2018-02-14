# Group-IKEv2

Group-IKEv2 is an adaptation of the IKEv2 protocol for the IPsec suite, and is especially designed to address Internet of Things (IoT) scenarios composed of resource-constrained devices.

# How to run Group-IKEv2 code
1. Power on InstantContiki3.0 - IKE - Clean
```
Login:
User: Instant Contiki
Password: user
```
2. Open terminal as the root

3. Enable usb-serial using the following command:
```
modprobe ftdi_sio
echo 0403 a6d1 > /sys/bus/usb-serial/drivers/ftdi_sio/new_id
```
(or for older Ubuntu in another machine)
```
modprobe ftdi_sio vendor=0x403 product=0xa6d1
```
4. Change directory to g-ike-example directory where the code for the server (GC/KS) and client are located
```
cd contiki/examples/Group-IKE/examples/ipsec/g-ike-example
```
5. Clean and compile the code
```
make clean all TARGET=openmote
```
6. Connect Openmote

From Argyro: So I would suggest you to try and test server with mote 22 and client with mote 23.

7. With the antenna up, press the right button (the left button is for reset) before downloading the code to the board

8. Download the binary file to Openmote

Note: Connect only one Openmote while downloading
```
make gckserver.upload TARGET=openmote
make client.upload TARGET=openmote
```
When the binary file is successfully loaded, the log should show something similar to the following log:
```
python ../../../tools/cc2538-bsl/cc2538-bsl.py -e -w -v client.bin
Opening port /dev/ttyUSB0, baud 500000
Reading data from client.bin
Firmware file: Raw Binary
Connecting to target...
CC2538 PG2.0: 512KB Flash, 32KB SRAM, CCFG at 0x0027FFD4
Primary IEEE Address: 06:0D:9E:C1:00:12:4B:00
Erasing 524288 bytes starting at address 0x00200000
    Erase done
Writing 524288 bytes starting at address 0x00200000
Write 16 bytes at 0x0027FFF0F8
    Write done                                
Verifying by comparing CRC32 calculations.
    Verified (match: 0x99eccfae)
rm obj_openmote/startup-gcc.o client.co
```
9. Connect all Openmotes used for measurement, run the code and save the log

Note: You need to know which device is attached to which port (e.g. /dev/ttyUSB0 - /dev/ttyUSB5)
* Connect server and client(s)
* Press server reset button (let assume the server is /dev/ttyUSB0)
* Run picocom for the server
```
picocom -b 115200 -r -l /dev/ttyUSB0 --imap lfcrlf | tee sserverlog.txt
```
* Run picocom for the clients (let assume the clients are /dev/ttyUSB1 and /dev/ttyUSB2)
```
picocom -b 115200 -r -l /dev/ttyUSB1 --imap lfcrlf | tee cclient1log.txt
picocom -b 115200 -r -l /dev/ttyUSB2 --imap lfcrlf | tee cclient2log.txt
```
* Immediately press client reset button since the measurement start right after the client is started

10. Extract log files information using the Perl script
```
perl getticks.pl
```
Note: You need to change the following lines in getticks.pl to match the log file names.

For the client log file, find the following line:
```
my @logfiles 	= glob('/home/user/contiki/examples/Group-IKE/examples/ipsec/g-ike-example/cc*');
```
For the server log file, find the following line:
```
my @logfiles 	= glob('/home/user/contiki/examples/Group-IKE/examples/ipsec/g-ike-example/ss*');
```
11. Copy server.csv and client.csv


# Configuration
1. There are two main directories that runs Group-IKEv2 functions
* Group-IKE/examples/ipsec/g-ike-example
* Group-IKE/apps/ipsec

2. Most of the setting/configuration are located in 2 configuration files:
* g-ike-conf.h (in Group-IKE/apps/ipsec/ike)
* g-ike-example-conf.h (in Group-IKE/examples/ipsec/g-ike-example)

3. To switch between PSK and Cert mode, change the following line in g-ike-example-conf.h
```
#define WITH_CONF_IKE_CERT_AUTH 0
```
(0 = PSK, 1 = Cert)

4. To change IKE_SA encryption algorithm, change the following line in g-ike-example-conf.h
```
#define IKE_ENCR SA_ENCR_AES_CCM_8
```
or
```
#define IKE_ENCR SA_ENCR_AES_CTR
#define IKE_INTEG SA_INTEG_AES_XCBC_MAC_96
```
Note that AES_CCM_8 supports integrity which is not supported by AES_CTR. Therefore, if and only if AES_CTR is enabled, AES_XCBC_MAC_96 should be enabled as well.

5. To change GSAT encryption algorithm, change the following line in g-ike-example-conf.h
```
#define ESP_ENCR  SA_ENCR_AES_CCM_8
```
or
```
#define ESP_ENCR SA_ENCR_AES_CTR
#define ESP_INTEG SA_INTEG_AES_XCBC_MAC_96
```
Note that AES_CCM_8 supports integrity which is not supported by AES_CTR. Therefore, if and only if AES_CTR is enabled, AES_XCBC_MAC_96 should be enabled as well.

6. To change GSAK encryption algorithm, change the following line in g-ike-conf.h
```
#define GIKE_ENCR SA_ENCR_AES_CCM_8
```
or
```
#define GIKE_ENCR SA_ENCR_AES_CTR
#define GIKE_INTEG SA_INTEG_AES_XCBC_MAC_96
```
Note that AES_CCM_8 supports integrity which is not supported by AES_CTR. Therefore, if and only if AES_CTR is enabled, AES_XCBC_MAC_96 should be enabled as well.

7. IP addresses of the server (GC/KS), the nodes, and the group are hard-coded. The change should be done for the following lines: 
* in g-ike-conf.h:
```
#define GCKS_HARDCODED_ADDRESS "aaaa::212:4b00:60d:9f4c" //address of GCKS
#define GROUP_ID "ff1e:0:0:0:0:0:89:abcd" // the group the client is configured. If you wanna change it
#define MEMBER1 "aaaa:0:0:0:212:4b00:60d:9ec1" //mote 23
#define MEMBER2 "aaaa:0:0:0:212:4b00:60d:9b19" //mote []
#define MEMBER3 "aaaa:0:0:0:212:4b00:433:ed7e"//mote11
#define MEMBER4 "aaaa:0:0:0:212:4b00:60d:9f10"//mote14
#define MEMBER5 "aaaa:0:0:0:212:4b00:615:a5be"//mote7
```
and in client.c
```
uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0212, 0x4b00,0x60d,0x9f4c); //mote no 22 as server
```
or gckserver.c
```
uip_ip6addr(&ipaddr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
```
8. To run Leave case, LEAVE_TEST in ike.c should be changed to 1. By changing LEAVE_TEST to 1, the server will send GSA_REKEY_LEAVE1 and GSA_REKEY_LEAVE2 messages periodically, instead of GSA_REKEY_PERIODIC.
```
#define LEAVE_TEST 1
```
LEAVE_TEST = 0 means the server will send GSA_REKEY_PERIODIC periodically.

9. Change the following line in g-ike-conf.h accordingly in order to show the ORDER of candidate member joining:
```
#define NUM_OF_CAN_MEMBERS 1
```
10. For rekeying message (e.g. gsa_rekey0), note that 0 means 'periodic', 1 means 'join', 2 and 3 mean 'leave'
