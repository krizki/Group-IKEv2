# Group-IKEv2

Group-IKEv2 is an adaptation of the IKEv2 protocol for the IPsec suite, and is especially designed to address Internet of Things (IoT) scenarios composed of resource-constrained devices.

# How to run Group-IKEv2 code
1. Power on InstantContiki3.0 - IKE - Clean
Login:
	User: Instant Contiki
	Password: user

2. Open terminal as the root

3. Enable usb-serial using the following command:
modprobe ftdi_sio
echo 0403 a6d1 > /sys/bus/usb-serial/drivers/ftdi_sio/new_id
(or for older Ubuntu in another machine)
modprobe ftdi_sio vendor=0x403 product=0xa6d1

4. Change directory to g-ike-example directory where the code for the server (GC/KS) and client are located
cd contiki/examples/Group-IKE/examples/ipsec/g-ike-example

5. Clean and compile the code
make clean all TARGET=openmote

6. Connect Openmote
From Argyro: So I would suggest you to try and test server with mote 22 and client with mote 23.

7. With the antenna up, press the right button (the left button is for reset) before downloading the code to the board

8. Download the binary file to Openmote
Note: Connect only one Openmote while downloading
make gckserver.upload TARGET=openmote
make client.upload TARGET=openmote

When the binary file is successfully loaded, the log should show something similar to the following log:
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

9. Connect all Openmotes used for measurement, run the code and save the log
Note: You need to know which device is attached to which port (e.g. /dev/ttyUSB0 - /dev/ttyUSB5)
- Connect server and client(s)
- Press server reset button (let assume the server is /dev/ttyUSB0)
- Run picocom for the server
picocom -b 115200 -r -l /dev/ttyUSB0 --imap lfcrlf | tee sserverlog.txt
- Run picocom for the clients (let assume the clients are /dev/ttyUSB1 and /dev/ttyUSB2)
picocom -b 115200 -r -l /dev/ttyUSB1 --imap lfcrlf | tee cclient1log.txt
picocom -b 115200 -r -l /dev/ttyUSB2 --imap lfcrlf | tee cclient2log.txt
- Immediately press server reset button since the measurement start right after the client is started

10. Extract log files information using the Perl script
perl getticks.pl
Note: You need to change the following lines in getticks.pl to match the log file names.
For the client log file, find the following line:
my @logfiles 	= glob('/home/user/contiki/examples/Group-IKE/examples/ipsec/g-ike-example/cc*');
For the server log file, find the following line:
my @logfiles 	= glob('/home/user/contiki/examples/Group-IKE/examples/ipsec/g-ike-example/ss*');

11. Copy server.csv and client.csv
