/*
 * Original file:
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Author: Runar Mar Magnusson <rmma@kth.se>
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
 * \addtogroup cc2538-aes
 * @{
 *
 * \file
 * Implementation of the cc2538 AES-ECB driver
 */
#include "contiki.h"
#include "aes.h"
#include "dev/crypto.h"
#include "dev/nvic.h"
#include "dev/sys-ctrl.h"
#include "reg.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define AES_ECB_LENGTH  16

#define ECB         0x1FFFFFE0
#define CCM         0x00040000
/*---------------------------------------------------------------------------*/
#define MIN(n,m)   (((n) < (m)) ? (n) : (m)) /* Macro for MIN */
/*---------------------------------------------------------------------------*/
uint8_t 
aes_ecb_start(const void *msg_in, const void *msg_out, uint8_t key_area,
                    uint8_t ui8Encrypt, struct process *process)
{
    if(REG(AES_CTRL_ALG_SEL) != 0x00000000) {
      return AES_RESOURCE_IN_USE;
    }
    
    /* workaround for AES registers not retained after PM2 */
    REG(AES_CTRL_INT_CFG) = AES_CTRL_INT_CFG_LEVEL;
    //REG(AES_CTRL_INT_EN) = AES_CTRL_INT_EN_DMA_IN_DONE;
    REG(AES_CTRL_INT_EN) = AES_CTRL_INT_EN_DMA_IN_DONE |
                         AES_CTRL_INT_EN_RESULT_AV;

    /* Interrupt handling */
    if(process != NULL) {
      crypto_register_process_notification(process);
      nvic_interrupt_unpend(NVIC_INT_AES);
      nvic_interrupt_enable(NVIC_INT_AES);
    }

    /* configure the master control module
       enable the DMA path to the AES engine */
    REG(AES_CTRL_ALG_SEL) = AES_CTRL_ALG_SEL_AES;
    
    /* clear any outstanding events */ 
    REG(AES_CTRL_INT_CLR) = (AES_CTRL_INT_CLR_DMA_IN_DONE |
                                AES_CTRL_INT_CLR_RESULT_AV);

    REG(AES_KEY_STORE_READ_AREA) = (uint32_t)key_area;

    /* wait until key is loaded to the AES module */
    while((REG(AES_KEY_STORE_READ_AREA) & AES_KEY_STORE_READ_AREA_BUSY));
 
    /* check for Key Store read error */
    if((REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_KEY_ST_RD_ERR))
    {
        /* Clear Key Store Read error */
        REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_KEY_ST_RD_ERR;
        REG(AES_CTRL_ALG_SEL) = 0x00000000;

        return AES_KEYSTORE_READ_ERROR;
    }

    /* configure AES engine 
       program AES-ECB-128 encryption and no IV */
    if(ui8Encrypt)
    {
        REG(AES_AES_CTRL) = 0x0000000C;
    }
    else
    {
        REG(AES_AES_CTRL) = 0x00000008;
    }
    
    REG(AES_CTRL_INT_EN) = AES_CTRL_INT_EN_RESULT_AV;

    /* write length of the message (lo) */
    REG(AES_AES_C_LENGTH_0) = (uint32_t) AES_ECB_LENGTH;
    /* write length of the message (hi) */
    REG(AES_AES_C_LENGTH_1) = 0;

    /* configure DMAC
       enable DMA channel 0 */
    REG(AES_DMAC_CH0_CTRL) = AES_DMAC_CH_CTRL_EN;

    /* base address of the input data in ext. memory */
    REG(AES_DMAC_CH0_EXTADDR) = (uint32_t)msg_in;

    /* input data length in bytes, equal to the message */
    REG(AES_DMAC_CH0_DMALENGTH) = AES_ECB_LENGTH;
    
    /* length (may be non-block size aligned) */ 
    REG(AES_DMAC_CH1_CTRL) = AES_DMAC_CH_CTRL_EN; /* enable DMA channel 1 */

    /* base address of the output data buffer */
    REG(AES_DMAC_CH1_EXTADDR) = (uint32_t)msg_out;

    /* output data length in bytes, equal to the result */
    REG(AES_DMAC_CH1_DMALENGTH) = AES_ECB_LENGTH;

    return AES_SUCCESS;
}
/*---------------------------------------------------------------------------*/
uint8_t 
aes_ecb_check_status(void)
{
  return !!(REG(AES_CTRL_INT_STAT) &
            (AES_CTRL_INT_STAT_DMA_BUS_ERR | AES_CTRL_INT_STAT_KEY_ST_WR_ERR |
             AES_CTRL_INT_STAT_KEY_ST_RD_ERR | AES_CTRL_INT_STAT_RESULT_AV));
}
/*---------------------------------------------------------------------------*/
uint8_t 
aes_ecb_get_result(void)
{
    uint32_t aes_ctrl_int_stat;

    aes_ctrl_int_stat = REG(AES_CTRL_INT_STAT);

    REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_DMA_BUS_ERR |
                          AES_CTRL_INT_CLR_KEY_ST_WR_ERR |
                          AES_CTRL_INT_CLR_KEY_ST_RD_ERR;
    
    nvic_interrupt_disable(NVIC_INT_AES);
    crypto_register_process_notification(NULL);
    
  /* Disable the master control / DMA clock */
    REG(AES_CTRL_ALG_SEL) = 0x00000000;

    
    //check for errors
    if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_DMA_BUS_ERR)
    {
        // clear the DMA error bit
        //REG(AES_CTRL_INT_CLR) |= AES_CTRL_INT_CLR_DMA_BUS_ERR;
        return AES_DMA_BUS_ERROR;
    }
    if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_KEY_ST_WR_ERR)
    {
        // clear the Key Store Write error bit
        //REG(AES_CTRL_INT_CLR) |= AES_CTRL_INT_CLR_KEY_ST_WR_ERR;
        return AES_KEYSTORE_WRITE_ERROR;
    }
    if(aes_ctrl_int_stat & AES_CTRL_INT_STAT_KEY_ST_RD_ERR)
    {
        // clear the Key Store Read error bit
        //REG(AES_CTRL_INT_CLR) |= AES_CTRL_INT_CLR_KEY_ST_RD_ERR;
        return AES_KEYSTORE_READ_ERROR;
    }

    /* if no errors then AES ECB operation was successful, disable AES
       interrupt */
    nvic_interrupt_disable(NVIC_INT_AES);
    crypto_register_process_notification(NULL);

    /* clear DMA done and result available bits */
    REG(AES_CTRL_INT_CLR) = (AES_CTRL_INT_CLR_DMA_IN_DONE |
                                AES_CTRL_INT_CLR_RESULT_AV);

    /* result has already been copied to the output buffer by DMA */
    REG(AES_AES_CTRL) = 0x00000000; // clear mode
    
    return AES_SUCCESS;
}

/** @} */
