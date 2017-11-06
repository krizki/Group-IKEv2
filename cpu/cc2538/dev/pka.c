/* Driver for the PKA HW module
 * 
 * Original file:
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Copyright (c) 2015, Swedish Institute of Computer Science.
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
 * 
 * Author: Runar Mar Magnusson <rmma@kth.se>
 */

/**
 *
 * \addtogroup pka_driver
 * @{
 * 
 * \file 
 * Implementation of the cc2538 public accelerator driver (PKA) API
 */

#include "contiki.h"
#include "sys/energest.h"
#include "dev/hw-pka.h"
#include "dev/pka.h"
#include "lpm.h"
#include "sys-ctrl.h"
#include "dev/nvic.h"

#define PKA_BASE                0x44004000  /**< PKA base point */
#define PKA_RAM_BASE            0x44006000  /**< SRAM_PKA */

#if !defined(WITH_CONTIKI) && defined(HAVE_ASSERT_H)
#include <assert.h>
#else
#define assert(condition) do{} while(0)
#endif

/*
 * Macro definition for NULL (from TI needed?)
 */
#ifndef NULL
#define NULL                    ((void*)0)
#endif

/** \brief Define for the maximum curve size supported by the PKA module in 32
 *         bit word.
 *  \note PKA hardware module can support upto 384 bit curve size due to the
 *        2K of PKA RAM.
 */
#define PKA_MAX_CURVE_SIZE_32_BIT_WORD \
                                12

/** \brief Define for the maximum length of the big number supported by the 
 *         PKA module in 32 bit word.
 */
#define PKA_MAX_LEN_IN_32_BIT_WORD \
                                PKA_MAX_CURVE_SIZE_32_BIT_WORD

/** \brief Define for the PKA RAM size.
 */
#define PKA_RAM_SIZE            2000

static volatile struct process *notification_process = NULL;
/*---------------------------------------------------------------------------*/
/** \brief The ECC / RSA cryptoprocessor ISR
 *
 *        This is the interrupt service routine for the ECC / RSA
 *        cryptoprocessor.
 *
 *        This ISR is called at worst from PM0, so lpm_exit() does not need
 *        to be called.
 */
void pka_isr(void)
{
  ENERGEST_ON(ENERGEST_TYPE_IRQ);

  nvic_interrupt_unpend(NVIC_INT_PKA);
  nvic_interrupt_disable(NVIC_INT_PKA);

  if(notification_process != NULL) {
    process_poll((struct process *)notification_process);
    notification_process = NULL;
  }

  ENERGEST_OFF(ENERGEST_TYPE_IRQ);
}
/*---------------------------------------------------------------------------*/
/**
 * \brief function that is used to check if the processor is allowed to go to
 *        lower power mode. That is if no operation is running it is allowed.
 */
static bool
permit_lpm(void)
{
  return (REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) == 0;
}
/*---------------------------------------------------------------------------*/
void
pka_init(void)
{
  volatile int i;

  lpm_register_peripheral(permit_lpm);

  pka_enable();

  /* Reset the PKA cryptoprocessor */
  REG(SYS_CTRL_SRSEC) |= SYS_CTRL_SRSEC_PKA;
  for(i = 0; i < 16; i++);
  REG(SYS_CTRL_SRSEC) &= ~SYS_CTRL_SRSEC_PKA;
}
/*---------------------------------------------------------------------------*/
void
pka_enable(void)
{
  /* Enable the clock for the PKA cryptoprocessor */
  REG(SYS_CTRL_RCGCSEC) |= SYS_CTRL_RCGCSEC_PKA;
  REG(SYS_CTRL_SCGCSEC) |= SYS_CTRL_SCGCSEC_PKA;
  REG(SYS_CTRL_DCGCSEC) |= SYS_CTRL_DCGCSEC_PKA;
}
/*---------------------------------------------------------------------------*/
void
pka_disable(void)
{
  /* Gate the clock for the PKA cryptoprocessor */
  REG(SYS_CTRL_RCGCSEC) &= ~SYS_CTRL_RCGCSEC_PKA;
  REG(SYS_CTRL_SCGCSEC) &= ~SYS_CTRL_SCGCSEC_PKA;
  REG(SYS_CTRL_DCGCSEC) &= ~SYS_CTRL_DCGCSEC_PKA;
}
/*---------------------------------------------------------------------------*/
void
pka_register_process_notification(struct process *p)
{
  notification_process = p;
}
/*---------------------------------------------------------------------------*/
void
PKAEnableInt(void)
{
  /* Enable the PKA interrupt. */
  nvic_interrupt_enable(NVIC_INT_PKA);
}
/*---------------------------------------------------------------------------*/
void
PKADisableInt( void )
{
    /* Disables the PKA interrupt. */
    nvic_interrupt_disable(NVIC_INT_PKA);
}
/*---------------------------------------------------------------------------*/
void
PKAClearInt(void)
{
  /* UnPends the PKA interrupt. */
  nvic_interrupt_unpend(NVIC_INT_PKA);
}
/*---------------------------------------------------------------------------*/
void
PKARegInt(void (*pfnHandler)(void))
{
    /* TODO: Implement or remove
     Register the interrupt handler.
    */
    //IntRegister(INT_PKA, pfnHandler);
}
/*---------------------------------------------------------------------------*/
void
PKAUnRegInt(void)
{
    /*  TODO: Implement or remove
     Unregister the interrupt handler.
    */
    //IntUnregister(INT_PKA);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKAGetOpsStatus(void)
{
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }
    else
    {
        return (PKA_STATUS_OPERATION_NOT_INPRG);
    }
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                  uint32_t* pui32Modulus, uint8_t ui8ModSize,
                  uint32_t* pui32ResultVector)
{
    uint8_t extraBuf;
    uint32_t offset;
    int i;

    /* Check the arguments. */
    assert(NULL != pui32BNum);
    assert(NULL != pui32Modulus);
    assert(NULL != pui32ResultVector);

    /*  make sure no operation is in progress. */
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /*  calculate the extra buffer requirement. */
    extraBuf = 2 + ui8ModSize % 2;

    offset = 0;

    /*  Update the A ptr with the offset address of the PKA RAM location
     where the number will be stored. */
    REG( (PKA_APTR) ) = offset >>2;

    /*  Load the number in PKA RAM */
    for(i = 0; i < ui8BNSize; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = pui32BNum[i];
    }

    /*  determine the offset for the next data input. */
    offset += 4 * (i + ui8BNSize % 2);

    /*  Update the B ptr with the offset address of the PKA RAM location
     where the divisor will be stored. */
    REG( (PKA_BPTR) ) = offset >> 2;

    /*  Load the divisor in PKA RAM. */
    for(i = 0; i < ui8ModSize;  i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = pui32Modulus[i];
    }

    /*  determine the offset for the next data. */
    offset += 4 * (i + extraBuf);

    /*  Copy the result vector address location. */
    *pui32ResultVector = PKA_RAM_BASE + offset;

    /*  Load C ptr with the result location in PKA RAM */
    REG( (PKA_CPTR) ) = offset >> 2;

    /* Load A length registers with Big number length in 32 bit words. */
    REG( (PKA_ALENGTH) ) = ui8BNSize;

    /* Load B length registers  Divisor length in 32-bit words. */
    REG( (PKA_BLENGTH) ) = ui8ModSize;

    /* Start the PKCP modulo operation by setting the PKA Function register. */
    REG( (PKA_FUNCTION) ) = (PKA_FUNCTION_RUN | PKA_FUNCTION_MODULO);

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumModGetResult(uint32_t* pui32ResultBuf,uint8_t ui8Size,
                      uint32_t ui32ResVectorLoc)
{
    uint32_t regMSWVal;
    uint32_t len;
    int i;

    /* Check the arguments. */
    assert(NULL != pui32ResultBuf);
    assert((ui32ResVectorLoc > PKA_RAM_BASE) &&
           (ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE)));

    /* verify that the operation is complete. */    
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /*  Get the MSW register value. */    
    regMSWVal = REG(PKA_DIVMSW);

    /* Check to make sure that the result vector is not all zeroes. */    
    if(regMSWVal & PKA_DIVMSW_RESULT_IS_ZERO)
    {
        return (PKA_STATUS_RESULT_0);
    }

    /* Get the length of the result. */    
    len = ((regMSWVal & PKA_DIVMSW_MSW_ADDRESS_M) + 1) -
          ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

    /* If the size of the buffer provided is less than the result length than
     return error. */    
    if(ui8Size < len)
    {
        return (PKA_STATUS_BUF_UNDERFLOW);
    }

    /* copy the result from vector C into the pResult. */    
    for(i = 0; i < len; i++)
    {
        pui32ResultBuf[i]= REG((ui32ResVectorLoc + 4*i));
    }

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumCmpStart(uint32_t* pui32BNum1, uint32_t* pui32BNum2, uint8_t ui8Size)
{
    uint32_t offset;
    int i;

    /* Check the arguments. */    
    assert(NULL != pui32BNum1);
    assert(NULL != pui32BNum2);
    
    offset = 0;

    /* Make sure no operation is in progress. */
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /* Update the A ptr with the offset address of the PKA RAM location
     where the first big number will be stored. */
    REG( (PKA_APTR) ) = offset >> 2;

    /* Load the first big number in PKA RAM. */    
    for(i = 0; i < ui8Size; i++)
    {
        REG( (PKA_RAM_BASE + offset + 4*i) ) = pui32BNum1[i];
    }

    /* Determine the offset in PKA RAM for the next pointer. */    
    offset += 4 * (i + ui8Size % 2);

    /* Update the B ptr with the offset address of the PKA RAM location
     where the second big number will be stored. */    
    REG((PKA_BPTR)) = offset >> 2;

    /* Load the second big number in PKA RAM. */    
    for(i = 0; i < ui8Size;  i++)
    {
        REG( (PKA_RAM_BASE + offset + 4*i) ) = pui32BNum2[i];
    }

    /* Load length registers in 32 bit word size. */    
    REG( (PKA_ALENGTH) ) = ui8Size;

    /* Set the PKA Function register for the Compare operation
     and start the operation. */    
    REG( (PKA_FUNCTION) ) = (PKA_FUNCTION_RUN | PKA_FUNCTION_COMPARE);

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumCmpGetResult(void)
{
    tPKAStatus status;

    /* verify that the operation is complete. */
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        status = PKA_STATUS_OPERATION_INPRG;
        return (status);
    }

    /* Check the COMPARE register. */
    switch(REG(PKA_COMPARE))
    {
        case PKA_COMPARE_A_EQUALS_B:
            status = PKA_STATUS_SUCCESS;
            break;

        case PKA_COMPARE_A_GREATER_THAN_B:
            status = PKA_STATUS_A_GR_B;
            break;

        case PKA_COMPARE_A_LESS_THAN_B:
            status = PKA_STATUS_A_LT_B;
            break;

        default:
            status = PKA_STATUS_FAILURE;
            break;
    }

    return (status);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumInvModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                     uint32_t* pui32Modulus, uint8_t ui8Size,
                     uint32_t* pui32ResultVector)
{
    uint32_t offset;
    int i;

    /* Check the arguments. */
    assert(NULL != pui32BNum);
    assert(NULL != pui32Modulus);
    assert(NULL != pui32ResultVector);

    offset = 0;

   /* Make sure no operation is in progress. */  
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /* Update the A ptr with the offset address of the PKA RAM location
     where the number will be stored. */
    REG( (PKA_APTR) ) = offset >>2;

    /* Load the \e pui32BNum number in PKA RAM. */    
    for(i = 0; i < ui8BNSize; i++)
    {
        REG( (PKA_RAM_BASE + offset + 4*i) ) = pui32BNum[i];
    }

    /* Determine the offset for next data. */    
    offset += 4 * (i + ui8BNSize % 2);

    /* Update the B ptr with the offset address of the PKA RAM location
     where the modulus will be stored. */    
    REG( (PKA_BPTR) ) = offset >> 2;

    /* Load the \e pui32Modulus divisor in PKA RAM. */    
    for(i = 0; i < ui8Size;  i++)
    {
        REG( (PKA_RAM_BASE + offset + 4*i) ) = pui32Modulus[i];
    }

    /* Determine the offset for result data. */    
    offset += 4 * (i + ui8Size % 2);

    /* Copy the result vector address location. */    
    *pui32ResultVector = PKA_RAM_BASE + offset;

    /* Load D ptr with the result location in PKA RAM. */
    REG( (PKA_DPTR) ) = offset >> 2;

    /* Load the respective length registers. */    
    REG( (PKA_ALENGTH) ) = ui8BNSize;
    REG( (PKA_BLENGTH) ) = ui8Size;

    /* set the PKA function to InvMod operation and the start the operation. */    
    REG( (PKA_FUNCTION) ) = 0x0000F000;

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumInvModGetResult(uint32_t* pui32ResultBuf, uint8_t ui8Size,
                         uint32_t ui32ResVectorLoc)
{
    uint32_t regMSWVal;
    uint32_t len;
    int i;

    /* Check the arguments. */    
    assert(NULL != pui32ResultBuf);
    assert((ui32ResVectorLoc > PKA_RAM_BASE) &&
           (ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE)));

    
    /* Verify that the operation is complete. */    
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    
    /* Get the MSW register value. */    
    regMSWVal = REG(PKA_MSW);

    
    /* Check to make sure that the result vector is not all zeroes. */    
    if(regMSWVal & PKA_MSW_RESULT_IS_ZERO)
    {
        return (PKA_STATUS_RESULT_0);
    }

    
    /* Get the length of the result */    
    len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1) -
          ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

    /* Check if the provided buffer length is adequate to store the result
     data. */    
    if(ui8Size < len)
    {
        return (PKA_STATUS_BUF_UNDERFLOW);
    }
    
    /* Copy the result from vector C into the \e pui32ResultBuf. */
    for(i = 0; i < len; i++)
    {
        pui32ResultBuf[i]= REG( (ui32ResVectorLoc + 4*i) );
    }

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumMultiplyStart(uint32_t* pui32Xplicand, uint8_t ui8XplicandSize,
                       uint32_t* pui32Xplier, uint8_t ui8XplierSize,
                       uint32_t* pui32ResultVector)
{
    uint32_t offset;
    int i;

    /* Check for the arguments. */
    assert(NULL != pui32Xplicand);
    assert(NULL != pui32Xplier);
    assert(NULL != pui32ResultVector);

    offset = 0;

    /* Make sure no operation is in progress. */  
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /* Update the A ptr with the offset address of the PKA RAM location
     where the multiplicand will be stored. */    
    REG( (PKA_APTR) ) = offset >> 2;

     /* Load the multiplicand in PKA RAM. */    
    for(i = 0; i < ui8XplicandSize; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = *pui32Xplicand;
        pui32Xplicand++;
    }

    /* Determine the offset for the next data. */    
    offset += 4 * (i + (ui8XplicandSize % 2));

    /* Update the B ptr with the offset address of the PKA RAM location
     where the multiplier will be stored. */    
    REG( (PKA_BPTR) ) = offset >> 2;

    /* Load the multiplier in PKA RAM. */    
    for(i = 0; i < ui8XplierSize; i++)
    {
        REG( (PKA_RAM_BASE + offset + 4*i) ) = *pui32Xplier;
        pui32Xplier++;
    }

    /* Determine the offset for the next data. */    
    offset += 4 * (i + (ui8XplierSize % 2));
    
    /* Copy the result vector address location. */    
    *pui32ResultVector = PKA_RAM_BASE + offset;

    /* Load C ptr with the result location in PKA RAM. */
    REG( (PKA_CPTR) ) = offset >> 2;

    /* Load the respective length registers. */    
    REG( (PKA_ALENGTH) ) = ui8XplicandSize;
    REG( (PKA_BLENGTH) ) = ui8XplierSize;

    /* Set the PKA function to the multiplication and start it. */    
    REG( (PKA_FUNCTION) ) = (PKA_FUNCTION_RUN | PKA_FUNCTION_MULTIPLY);

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumMultGetResult(uint32_t* pui32ResultBuf, uint32_t* pui32Len,
                       uint32_t ui32ResVectorLoc)
{
    uint32_t regMSWVal;
    uint32_t len;
    int i;

    /* Check for arguments. */
    assert(NULL != pui32ResultBuf);
    assert(NULL != pui32Len);
    assert((ui32ResVectorLoc > PKA_RAM_BASE) &&
           (ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE)));
    
    /* Verify that the operation is complete. */
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /* Get the MSW register value. */    
    regMSWVal = REG(PKA_MSW);

    /* Check to make sure that the result vector is not all zeroes. */    
    if(regMSWVal & PKA_MSW_RESULT_IS_ZERO)
    {
        return (PKA_STATUS_RESULT_0);
    }

    /* Get the length of the result. */    
    len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1) -
          ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

    /* Make sure that the length of the supplied result buffer is adequate
     to store the resultant. */    
    if(*pui32Len < len)
    {
        return (PKA_STATUS_BUF_UNDERFLOW);
    }

    
    /* Copy the resultant length. */    
    *pui32Len = len;

    
    /* Copy the result from vector C into the pResult. */    
    for(i = 0; i < *pui32Len; i++)
    {
        pui32ResultBuf[i]= REG( (ui32ResVectorLoc + 4*i) );
    }

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumAddStart(uint32_t* pui32BN1, uint8_t ui8BN1Size,
                  uint32_t* pui32BN2, uint8_t ui8BN2Size,
                  uint32_t* pui32ResultVector)
{
    uint32_t offset;
    int i;

    /* Check for arguments. */    
    assert(NULL != pui32BN1);
    assert(NULL != pui32BN2);
    assert(NULL != pui32ResultVector);

    offset = 0;

    /* Make sure no operation is in progress. */
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }
    
    /* Update the A ptr with the offset address of the PKA RAM location
     where the big number 1 will be stored. */    
    REG( (PKA_APTR) ) = offset >> 2;

    
    /* Load the big number 1 in PKA RAM. */    
    for(i = 0; i < ui8BN1Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = pui32BN1[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + (ui8BN1Size % 2));

    /* Update the B ptr with the offset address of the PKA RAM location
     where the big number 2 will be stored. */    
    REG( (PKA_BPTR) ) = offset >> 2;

    /* Load the big number 2 in PKA RAM. */    
    for(i = 0; i < ui8BN2Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = pui32BN2[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + (ui8BN2Size % 2));

    /* Copy the result vector address location. */
    *pui32ResultVector = PKA_RAM_BASE + offset;

    /* Load C ptr with the result location in PKA RAM. */    
    REG( (PKA_CPTR) ) = offset >> 2;

    /* Load respective length registers. */    
    REG( (PKA_ALENGTH) ) = ui8BN1Size;
    REG( (PKA_BLENGTH) ) = ui8BN2Size;

    /* Set the function for the add operation and start the operation. */    
    REG( (PKA_FUNCTION) ) = (PKA_FUNCTION_RUN | PKA_FUNCTION_ADD);

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKABigNumAddGetResult(uint32_t* pui32ResultBuf, uint32_t* pui32Len,
                      uint32_t ui32ResVectorLoc)
{
    uint32_t regMSWVal;
    uint32_t len;
    int i;

    /* Check for the arguments. */    
    assert(NULL != pui32ResultBuf);
    assert(NULL != pui32Len);
    assert((ui32ResVectorLoc > PKA_RAM_BASE) &&
           (ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE)));
    
    /* Verify that the operation is complete. */    
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /* Get the MSW register value. */    
    regMSWVal = REG(PKA_MSW);

    /* Check to make sure that the result vector is not all zeroes. */    
    if(regMSWVal & PKA_MSW_RESULT_IS_ZERO)
    {
        return (PKA_STATUS_RESULT_0);
    }

    /* Get the length of the result. */    
    len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1) -
          ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

    /* Make sure that the supplied result buffer is adequate to store the
     resultant data. */    
    if(*pui32Len < len)
    {
        return (PKA_STATUS_BUF_UNDERFLOW);
    }

    /* Copy the length. */    
    *pui32Len = len;

    /* Copy the result from vector C into the provided buffer. */
    for(i = 0; i < *pui32Len; i++)
    {
        pui32ResultBuf[i] = REG( (ui32ResVectorLoc +  4*i) );
    }

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKAECCMultiplyStart(uint32_t* pui32Scalar, tECPt* ptEcPt,
                    tECCCurveInfo* ptCurve, uint32_t* pui32ResultVector)
{
    uint8_t extraBuf;
    uint32_t offset;
    int i;

    /* Check for the arguments. */    
    assert(NULL != pui32Scalar);
    assert(NULL != ptEcPt);
    assert(NULL != ptEcPt->pui32X);
    assert(NULL != ptEcPt->pui32Y);
    assert(NULL != ptCurve);
    assert(ptCurve->ui8Size <= PKA_MAX_CURVE_SIZE_32_BIT_WORD);
    assert(NULL != pui32ResultVector);

    offset = 0;

    
    /* Make sure no PKA operation is in progress. */    
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /* Calculate the extra buffer requirement. */    
    extraBuf = 2 + ptCurve->ui8Size % 2;

    /* Update the A ptr with the offset address of the PKA RAM location
     where the scalar will be stored. */
    REG((PKA_APTR)) = offset >> 2;

    /* Load the scalar in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = *pui32Scalar++;
    }

    /* Determine the offset for the next data. */    
    offset += 4 * (i + (ptCurve->ui8Size % 2));

    /* Update the B ptr with the offset address of the PKA RAM location
     where the curve parameters will be stored. */    
    REG((PKA_BPTR)) = offset >> 2;

    /* Write curve parameter 'p' as 1st part of vector B immediately
     following vector A at PKA RAM */
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) =
            (uint32_t)ptCurve->pui32Prime[i];
    }

    /* Determine the offset for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Copy curve parameter 'a' in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = (uint32_t)ptCurve->pui32A[i];
    }

    /* Determine the offset for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Copy curve parameter 'b' in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = (uint32_t)ptCurve->pui32B[i];
    }

    /* Determine the offset for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Update the C ptr with the offset address of the PKA RAM location
     where the Gx, Gy will be stored. */    
    REG((PKA_CPTR)) = offset >> 2;

    /* Write elliptic curve point x co-ordinate value. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = ptEcPt->pui32X[i];
    }

    /* Determine the offset for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Write elliptic curve point y co-ordinate value. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = ptEcPt->pui32Y[i];
    }

    /* Determine the offset for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Update the result location. */    
    *pui32ResultVector =  PKA_RAM_BASE + offset;

    /* Load D ptr with the result location in PKA RAM. */    
    REG(PKA_DPTR) = offset >> 2;

    /* Load length registers. */    
    REG(PKA_ALENGTH) = ptCurve->ui8Size;
    REG(PKA_BLENGTH) = ptCurve->ui8Size;

    /* set the PKA function to ECC-MULT and start the operation. */    
    REG(PKA_FUNCTION) = 0x0000D000;

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKAECCMultiplyGetResult(tECPt* ptOutEcPt, uint32_t ui32ResVectorLoc)
{
    int i;
    uint32_t addr;
    uint32_t regMSWVal;
    uint32_t len;

    /* Check for the arguments. */
    assert(NULL != ptOutEcPt);
    assert(NULL != ptOutEcPt->pui32X);
    assert(NULL != ptOutEcPt->pui32Y);
    assert((ui32ResVectorLoc > PKA_RAM_BASE) &&
           (ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE)));

    /* Verify that the operation is completed. */
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    if(REG(PKA_SHIFT) == 0x00000000)
    {
        /* Get the MSW register value. */        
        regMSWVal = REG(PKA_MSW);

        /* Check to make sure that the result vector is not all zeroes. */        
        if(regMSWVal & PKA_MSW_RESULT_IS_ZERO)
        {
            return (PKA_STATUS_RESULT_0);
        }

        /* Get the length of the result */        
        len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1) -
              ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

        addr = ui32ResVectorLoc;

        /* copy the x co-ordinate value of the result from vector D into
         the \e ptOutEcPt. */        
        for(i = 0; i < len; i++)
        {
            ptOutEcPt->pui32X[i] = REG(addr + 4*i);
        }

        addr += 4 * (i + 2 + len % 2);

        /* copy the y co-ordinate value of the result from vector D into
         the \e ptOutEcPt. */        
        for(i = 0; i < len; i++)
        {
            ptOutEcPt->pui32Y[i] = REG(addr + 4*i);
        }

        return (PKA_STATUS_SUCCESS);
    }
    else
    {
        return (PKA_STATUS_FAILURE);
    }
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKAECCMultGenPtStart(uint32_t* pui32Scalar, tECCCurveInfo* ptCurve,
                     uint32_t* pui32ResultVector)
{
    uint8_t extraBuf;
    uint32_t offset;
    int i;

    /* Check for the arguments. */
    assert(NULL != pui32Scalar);
    assert(NULL != ptCurve);
    assert(ptCurve->ui8Size <= PKA_MAX_CURVE_SIZE_32_BIT_WORD);
    assert(NULL != pui32ResultVector);
    
    offset = 0;

    /* Make sure no operation is in progress. */
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /* Calculate the extra buffer requirement. */
    extraBuf = 2 + ptCurve->ui8Size % 2;

    /* Update the A ptr with the offset address of the PKA RAM location
     where the scalar will be stored. */
    REG(PKA_APTR) = offset >> 2;

    /* Load the scalar in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = *pui32Scalar++;
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + (ptCurve->ui8Size % 2));

    /* Update the B ptr with the offset address of the PKA RAM location
     where the curve parameters will be stored. */    
    REG(PKA_BPTR) = offset >> 2;

    /* Write curve parameter 'p' as 1st part of vector B. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) =
            (uint32_t)ptCurve->pui32Prime[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Write curve parameter 'a' in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = (uint32_t)ptCurve->pui32A[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + extraBuf);

    /* write curve parameter 'b' in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = (uint32_t)ptCurve->pui32B[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Update the C ptr with the offset address of the PKA RAM location
     where the Gx, Gy will be stored. */    
    REG(PKA_CPTR) = offset >> 2;

    /* Write x co-ordinate value of the Generator point in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = (uint32_t)ptCurve->pui32Gx[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Write y co-ordinate value of the Generator point in PKA RAM. */
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = (uint32_t)ptCurve->pui32Gy[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Update the result location. */    
    *pui32ResultVector =  PKA_RAM_BASE + offset;

    /* Load D ptr with the result location in PKA RAM. */    
    REG(PKA_DPTR) = offset >> 2;

    /* Load length registers. */    
    REG(PKA_ALENGTH) = ptCurve->ui8Size;
    REG(PKA_BLENGTH) = ptCurve->ui8Size;

    /* Set the PKA function to ECC-MULT and start the operation. */    
    REG( (PKA_FUNCTION) ) = 0x0000D000;

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKAECCMultGenPtGetResult(tECPt* ptOutEcPt, uint32_t ui32ResVectorLoc)
{
    int i;
    uint32_t regMSWVal;
    uint32_t addr;
    uint32_t len;

    /* Check for the arguments. */
    assert(NULL != ptOutEcPt);
    assert(NULL != ptOutEcPt->pui32X);
    assert(NULL != ptOutEcPt->pui32Y);
    assert((ui32ResVectorLoc > PKA_RAM_BASE) &&
           (ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE)));

    /* Verify that the operation is completed. */
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    if(REG(PKA_SHIFT) == 0x00000000)
    {
        /* Get the MSW register value. */        
        regMSWVal = REG(PKA_MSW);

        
        /* Check to make sure that the result vector is not all zeroes. */        
        if(regMSWVal & PKA_MSW_RESULT_IS_ZERO)
        {
            return (PKA_STATUS_RESULT_0);
        }

        /* Get the length of the result. */        
        len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1) -
              ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

        addr = ui32ResVectorLoc;

        /* Copy the x co-ordinate value of the result from vector D into the
         EC point. */        
        for(i = 0; i < len; i++)
        {
            ptOutEcPt->pui32X[i] = REG( (addr + 4*i) );
        }

        addr += 4 * (i + 2 + len % 2);

        /* Copy the y co-ordinate value of the result from vector D into the
         EC point. */        
        for(i = 0; i < len; i++)
        {
            ptOutEcPt->pui32Y[i] = REG( (addr + 4*i) );
        }

        return (PKA_STATUS_SUCCESS);
    }
    else
    {
        return (PKA_STATUS_FAILURE);
    }
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKAECCAddStart(tECPt* ptEcPt1, tECPt* ptEcPt2,tECCCurveInfo* ptCurve,
               uint32_t* pui32ResultVector)
{
    uint8_t extraBuf;
    uint32_t offset;
    int i;

    /* Check for the arguments. */
    assert(NULL != ptEcPt1);
    assert(NULL != ptEcPt1->pui32X);
    assert(NULL != ptEcPt1->pui32Y);
    assert(NULL != ptEcPt2);
    assert(NULL != ptEcPt2->pui32X);
    assert(NULL != ptEcPt2->pui32Y);
    assert(NULL != ptCurve);
    assert(NULL != pui32ResultVector);

    offset = 0;

    /* Make sure no operation is in progress. */    
    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    /* Calculate the extra buffer requirement. */    
    extraBuf = 2 + ptCurve->ui8Size % 2;

    /* Update the A ptr with the offset address of the PKA RAM location
     where the first ecPt will be stored. */    
    REG(PKA_APTR) = offset >> 2;

    /* Load the x co-ordinate value of the first EC point in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = ptEcPt1->pui32X[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Load the y co-ordinate value of the first EC point in PKA RAM. */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = ptEcPt1->pui32Y[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Update the B ptr with the offset address of the PKA RAM location
     where the curve parameters will be stored. */    
    REG(PKA_BPTR) = offset >> 2;

    /* Write curve parameter 'p' as 1st part of vector B */    
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) =
            (uint32_t)ptCurve->pui32Prime[i];
    }

    /* Determine the offset in PKA RAM for the next data. */    
    offset += 4 * (i + extraBuf);

    /* Write curve parameter 'a'. */
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = (uint32_t)ptCurve->pui32A[i];
    }

    /* Determine the offset in PKA RAM for the next data. */
    offset += 4 * (i + extraBuf);

    /* Update the C ptr with the offset address of the PKA RAM location
     where the ecPt2 will be stored. */
    REG(PKA_CPTR) = offset >> 2;

    /* Load the x co-ordinate value of the second EC point in PKA RAM. */
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = ptEcPt2->pui32X[i];
    }

    /* Determine the offset in PKA RAM for the next data. */
    offset += 4 * (i + extraBuf);

    /* Load the y co-ordinate value of the second EC point in PKA RAM. */
    for(i = 0; i < ptCurve->ui8Size; i++)
    {
        REG((PKA_RAM_BASE + offset + 4*i)) = ptEcPt2->pui32Y[i];
    }

    /* Determine the offset in PKA RAM for the next data. */
    offset += 4 * (i + extraBuf);

    /* Copy the result vector location. */
    *pui32ResultVector = PKA_RAM_BASE + offset;

    /* Load D ptr with the result location in PKA RAM. */
    REG(PKA_DPTR) = offset >> 2;

    /* Load length registers. */
    REG(PKA_BLENGTH) = ptCurve->ui8Size;

    /* Set the PKA Function to ECC-ADD and start the operation. */
    REG( (PKA_FUNCTION) ) = 0x0000B000;

    return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
tPKAStatus
PKAECCAddGetResult(tECPt* ptOutEcPt, uint32_t ui32ResVectorLoc)
{
    uint32_t regMSWVal;
    uint32_t addr;
    int i;
    uint32_t len;

    /* Check for the arguments. */
    assert(NULL != ptOutEcPt);
    assert(NULL != ptOutEcPt->pui32X);
    assert(NULL != ptOutEcPt->pui32Y);
    assert((ui32ResVectorLoc > PKA_RAM_BASE) &&
           (ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE)));

    if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0)
    {
        return (PKA_STATUS_OPERATION_INPRG);
    }

    if(REG(PKA_SHIFT) == 0x00000000)
    {
        /* Get the MSW register value.*/
        regMSWVal = REG(PKA_MSW);

        /* Check to make sure that the result vector is not all zeroes. */
        if(regMSWVal & PKA_MSW_RESULT_IS_ZERO)
        {
            return (PKA_STATUS_RESULT_0);
        }
        
        /*Get the length of the result. */
        len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1) -
              ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

        addr = ui32ResVectorLoc;
        
         /* Copy the x co-ordinate value of result from vector D into the
         the output EC Point. */
        for(i = 0; i < len; i++)
        {
            ptOutEcPt->pui32X[i] = REG((addr + 4*i));
        }

        addr += 4 * (i + 2 + len % 2);

        /* Copy the y co-ordinate value of result from vector D into the
        the output EC Point. */
        for(i = 0; i < len; i++)
        {
            ptOutEcPt->pui32Y[i] = REG((addr + 4*i));
        }

        return (PKA_STATUS_SUCCESS);
    }
    else
    {
        return (PKA_STATUS_FAILURE);
    }
}

/** @} */
