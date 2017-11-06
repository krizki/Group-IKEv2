/*
 * Original file:
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Runar Mar Magnusson <rmma@kth.se>
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
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \addtogroup cc2538-crypto
 * @{
 *
 * \defgroup cc2538-ccm cc2538 AES-ECB
 *
 * Driver for the cc2538 AES-ECB mode of the security core
 * @{
 * 
 * \file
 * Header file for the cc2538 AES-ECB driver
 */

#ifndef AES_H_
#define AES_H_

#include "contiki.h"
#include "crypto.h"
#include "sys-ctrl.h"
#include "dev/nvic.h"

#include <stdbool.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * General constants
 */

/* Key store module defines */
#define STATE_BLENGTH   16      // Number of bytes in State 
#define KEY_BLENGTH     16      // Number of bytes in Key 
#define KEY_EXP_LENGTH  176     // Nb * (Nr+1) * 4 
#define KEY_STORE_SIZE_BITS  0x03UL
#define KEY_STORE_SIZE_NA    0x00UL
#define KEY_STORE_SIZE_128   0x01UL
#define KEY_STORE_SIZE_192   0x02UL
#define KEY_STORE_SIZE_256   0x03UL

/* AES module defines */
#define AES_BUSY    0x08
#define ENCRYPT     0x00
#define DECRYPT     0x01

/* Defines for setting the mode of the AES operation */
#define ECB         0x1FFFFFE0
#define CCM         0x00040000

/**
 * For 128 bit key all 8 Key Area locations from 0 to 8 are valid
 * However for 192 bit and 256 bit keys, only even Key Areas 
 * 0, 2, 4, 6 are valid. This is passes as a parameter to aes_ecb_start()
 */
enum 
{
    KEY_AREA_0,        
    KEY_AREA_1,          
    KEY_AREA_2,       
    KEY_AREA_3,       
    KEY_AREA_4,
    KEY_AREA_5,       
    KEY_AREA_6,  
    KEY_AREA_7 
};

/*---------------------------------------------------------------------------*/
/** \name AES-ECB functions
 * @{
 */

/**
 * \brief aes_ecb_start starts an AES-ECB operation.
 * 
 * \param msg_in is pointer to input data.
 * \param msg_out is pointer to output data.
 * \param key_area is the location in Key RAM.
 * \param ui8Encrypt is set 'true' to ui8Encrypt or set 'false' to decrypt.
 * \param process Process to be polled upon completion of the operation, or \c NULL
 * disable AES interrupt.
 * 
 * The \e ui8KeyLocation parameter is an enumerated type which specifies
 * the Key Ram location in which the key is stored.
 * This parameter can have any of the following values:
 * - \b KEY_AREA_0
 * - \b KEY_AREA_1
 * - \b KEY_AREA_2,
 * - \b KEY_AREA_3,
 * - \b KEY_AREA_4,
 * - \b KEY_AREA_5,
 * - \b KEY_AREA_6,
 * - \b KEY_AREA_7
 * 
 * \return  AES_SUCCESS if successful.
 */
uint8_t aes_ecb_start(const void *msg_in, const void *msg_out, uint8_t key_area,
                      uint8_t ui8Encrypt, struct process *process);

/**
 * \brief aes_ecb_check_status is called to check the result of AES-ECB 
 * aes_ecb_start operation.
 * 
 * \return  if result is available or error occurs returns true.  If result
 * is not yet available or no error occurs returns false
 */
uint8_t aes_ecb_check_status(void);

/**
 * 
 * \brief aes_ecb_get_result gets the result of the AES ECB operation.  
 * This function must only be called after aes_ecb_start function is called.
 * 
 * \return  AES_SUCCESS if successful.
 */
uint8_t aes_ecb_get_result(void);

/** @} */

#endif	/* AES_H_ */

/**
 * @}
 * @}
 */
