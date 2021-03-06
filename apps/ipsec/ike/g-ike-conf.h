/*
 * g-ike-conf.h
 *
 *  Created on: Jun 7, 2016
 *      Author: Argyro Lamproudi
 */

#ifndef _G_IKE_CONF_H_
#define _G_IKE_CONF_H_

/*Enable Group Key Management with IKEv2 */

#define WITH_GROUP_IKE		1

#ifndef WITH_GROUP_IKE
#define WITH_GROUP_IKE		1
#endif
#if WITH_GROUP_IKE
#define GKMA NO_GKM //no_lkh =0, lkh = 1
#define GCKS_HARDCODED_ADDRESS "aaaa::212:4b00:60d:9f4c" //address of GCKS
#define GROUP_ID "ff1e:0:0:0:0:0:89:abcd" // the group the client is configured. If you wanna change it
//#define GROUP_ID_2 "ff02:0:0:0:0:0:0:001a"	// you have to change the GROUP_ID="xxxxx"
#define MEMBER1 "aaaa:0:0:0:212:4b00:60d:9ec1" //mote 23
//#define MEMBER2 "aaaa:0:0:0:212:4b00:615:a592" //mote 6
#define MEMBER2 "aaaa:0:0:0:212:4b00:60d:9b19" //mote []
#define MEMBER3 "aaaa:0:0:0:212:4b00:433:ed7e"//mote11
//#define MEMBER4 "aaaa:0:0:0:212:4b00:615:a5d8"//mote12
#define MEMBER4 "aaaa:0:0:0:212:4b00:60d:9f10"//mote14
#define MEMBER5 "aaaa:0:0:0:212:4b00:615:a5be"//mote7

/* Pair-wise shared secret between GCKS and member-n defined below used in the GSA_REKEY payload */
#define PAIRWISE_SHARED_IKE_SECRET_LEN 32
#define SHARED_IKE_SECRET_MEMBER1 {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
#define SHARED_IKE_SECRET_MEMBER2 {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
#define SHARED_IKE_SECRET_MEMBER3 {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
#define SHARED_IKE_SECRET_MEMBER4 {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
#define SHARED_IKE_SECRET_MEMBER5 {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

/*Security Algorithms*/

/*
 * Encryption
 */
//#define GIKE_ENCR SA_ENCR_AES_CTR
#define GIKE_ENCR SA_ENCR_AES_CCM_8
//#define GIKE_ENCR SA_ENCR_AES_CCM_12
//#define GIKE_ENCR  SA_ENCR_AES_CCM_16
//#define GIKE_ENCR_DEFAULT SA_ENCR_AES_CCM_8
/*
 * Integrity, however it must not be defined when SA_ENCR_AES_CCM_8,12,16 are enabled
 *  Integrity transform to use for the IKE SA, supported transforms:
   SA_INTEG_AES_XCBC_MAC_96, SA_INTEG_HMAC_SHA1_96, SA_INTEG_HMAC_SHA2_256_128
 */
//#define GIKE_INTEG SA_INTEG_AES_XCBC_MAC_96

#define NUM_OF_MEMBERS 5
#define NUM_OF_CAN_MEMBERS 1
#define NUM_OF_GROUPS 1
#define MAX_KEYS 5

#define GSAK_LIFETIME 70
#define REKEY_TIMER 10 // it has to be less that GSAK_LIFETIME
#define KEY_LENGTH 16

#endif

#endif /* _G_IKE_CONF_H_ */
