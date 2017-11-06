/* Driver for the PKA HW module
 * 
 * Original file:
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Copyright (c) 2015, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
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

#ifndef PKA_H_
#define	PKA_H_

#include "reg.h"
#include "ecc-curve-info.h"

/*---------------------------------------------------------------------------*/
/** \name PKA function return values
 * @{
 */
#define PKA_STATUS_SUCCESS             0 /**< Success */
#define PKA_STATUS_FAILURE             1 /**< Failure */
#define PKA_STATUS_INVALID_PARAM       2 /**< Invalid parameter */
#define PKA_STATUS_BUF_UNDERFLOW       3 /**< Buffer underflow */
#define PKA_STATUS_RESULT_0            4 /**< Result is all zeros */
#define PKA_STATUS_A_GR_B              5 /**< Big number compare return status if
                                         the first big num is greater than
                                         the second. */
#define PKA_STATUS_A_LT_B              6 /**< Big number compare return status if
                                         the first big num is less than the
                                         second. */
#define PKA_STATUS_OPERATION_INPRG     7 /**< PKA operation is in progress. */
#define PKA_STATUS_OPERATION_NOT_INPRG 8 /**< No PKA operation is in progress. */
/** @} */

/**
 * \brief A structure containing the pointers to the values of x and y 
 * co-ordinates of the Elliptical Curve point.
 */
typedef struct _ECPt
{
  /* Pointer to value of the x co-ordinate of the ec point. */
  uint32_t* pui32X;

  /* Pointer to value of the y co-ordinate of the ec point. */
  uint32_t* pui32Y;
} tECPt;

/** 
 * \brief PKA function return type. 
 */
typedef uint8_t tPKAStatus;

/*---------------------------------------------------------------------------*/
/** \name Prototypes for the APIs.
 * @{
 */

/** \brief This function enables the PKA interrupt.
 *  \return None. */
extern void PKAEnableInt(void);

/** \brief This function disables the PKA interrupt.
 *  \return None. */
extern void PKADisableInt(void);

/** \brief This function unpends PKA interrupt.  This will cause any previously
 *  generated PKA interrupts that have not been handled yet to be discarded.
 *  \return None. */
extern void PKAClearInt(void);

/** \brief Registers an interrupt handler for PKA interrupt.
 * \param pfnHandler is a pointer to the function to be called when the
 * PKA interrupt occurs.
 * 
 * \note This function does the actual registering of the interrupt handler.  
 * This will not enable the PKA interrupt in the interrupt controller, a call to
 * the function \sa PKAEnableInt() is needed to enable the PKA interrupt.
 * 
 * \sa IntRegister() for important information about registering interrupt handlers.
 * \return None. */
extern void PKARegInt(void(*pfnHandler)(void));

/** \brief Unregisters an interrupt handler for the PKA interrupt.
 * 
 *  \note This function deregisters the interrupt service routine.  This function
 *  will not disable the interrupt and an explicit call to \sa PKADisableInt()
 *  is needed.
 * 
 *  \return None. */
extern void PKAUnRegInt(void);

/** \brief Provides the PKA operation status.
 * 
 * \note This function provides information on whether any PKA operation is in
 * progress or not. This function allows to check the PKA operation status
 * before starting any new PKA operation.
 * 
 * \return Returns: 
 * - \b PKA_STATUS_INPRG if the PKA operation is in progress.
 * - \b PKA_STATUS_OPERATION_NOT_INPRG if the PKA operation is not in progress.
 */
extern tPKAStatus PKAGetOpsStatus(void);

/** \brief Starts the big number modulus operation.
 * \param pui32BNum is the pointer to the big number on which modulo operation
 * needs to be carried out.
 * \param ui8BNSize is the size of the big number \sa pui32BNum in 32-bit
 * word.
 * \param pui32Modulus is the pointer to the divisor.
 * \param ui8ModSize is the size of the divisor \sa pui32Modulus.
 * \param pui32ResultVector is the pointer to the result vector location
 * which will be set by this function.
 * 
 * \note This function starts the modulo operation on the big num \sa pui32BNum
 * using the divisor \sa pui32Modulus.  The PKA RAM location where the result
 * will be available is stored in \sa pui32ResultVector.
 * 
 * /return Returns: 
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.  
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *   some other operation. */
extern tPKAStatus PKABigNumModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                                    uint32_t* pui32Modulus, uint8_t ui8ModSize,
                                    uint32_t* pui32ResultVector);

/** \brief Gets the result of the big number modulus operation.
 * 
 * \param pui32ResultBuf is the pointer to buffer where the result needs to
 * be stored.
 * \param ui8Size is the size of the provided buffer in 32 bit size word.
 * \param ui32ResVectorLoc is the address of the result location which
 * was provided by the start function \sa PKABigNumModStart().
 * 
 * \note This function gets the result of the big number modulus operation 
 * which was previously started using the function \sa PKABigNumModStart().
 * 
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if successful.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_BUF_UNDERFLOW, if the \e ui8Size is less than the length
 *      of the result. */
extern tPKAStatus PKABigNumModGetResult(uint32_t* pui32ResultBuf,
                                        uint8_t ui8Size,
                                        uint32_t ui32ResVectorLoc);

/** \brief Starts the comparison of two big numbers.
 * 
 * \param pui32BNum1 is the pointer to the first big number.
 * \param pui32BNum2 is the pointer to the second big number.
 * \param ui8Size is the size of the big number in 32 bit size word.
 *
 * \note This function starts the comparison of two big numbers pointed by
 * \e pui32BNum1 and \e pui32BNum2.
 * Note this function expects the size of the two big numbers equal.
 *
 * \return Returns: 
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.  
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 * some other operation. */
extern tPKAStatus PKABigNumCmpStart(uint32_t* pui32BNum1, uint32_t* pui32BNum2,
                                    uint8_t ui8Size);

/** \brief Gets the result of the comparison operation of two big numbers.
 *
 * \note This function provides the results of the comparison of two big numbers
 * which was started using the \sa PKABigNumCmpStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_OPERATION_INPRG if the operation is in progress.
 * - \b PKA_STATUS_SUCCESS if the two big numbers are equal.
 * - \b PKA_STATUS_A_GR_B  if the first number is greater than the second.
 * - \b PKA_STATUS_A_LT_B if the first number is less than the second. */
extern tPKAStatus PKABigNumCmpGetResult(void);

/** \brief Starts the big number inverse modulo operation.
 *
 * \param pui32BNum is the pointer to the buffer containing the big number
 * (dividend).
 * \param ui8BNSize is the size of the \e pui32BNum in 32 bit word.
 * \param pui32Modulus is the pointer to the buffer containing the divisor.
 * \param ui8Size is the size of the divisor in 32 bit word.
 * \param pui32ResultVector is the pointer to the result vector location
 * which will be set by this function.
 *
 * \note This function starts the the inverse modulo operation on \e pui32BNum
 * using the divisor \e pui32Modulus.
 *
 *\return Returns: 
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.  
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 * some other operation. */
extern tPKAStatus PKABigNumInvModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                                       uint32_t* pui32Modulus, uint8_t ui8Size,
                                       uint32_t* pui32ResultVector);

/** \brief Gets the result of the big number inverse modulo operation.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result needs to be
 * stored.
 * \param ui8Size is the size of the provided buffer in 32 bit ui8Size
 * word.
 * \param ui32ResVectorLoc is the address of the result location which
 * was provided by the start function \sa PKABigNumInvModStart().
 *
 * \note This function gets the result of the big number inverse modulo operation
 * previously started using the function \sa PKABigNumInvModStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful. 
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing 
 * the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_BUF_UNDERFLOW if the length of the provided buffer is less
 * then the result. */
extern tPKAStatus PKABigNumInvModGetResult(uint32_t* pui32ResultBuf,
                                           uint8_t ui8Size,
                                           uint32_t ui32ResVectorLoc);

/** \brief Starts the big number multiplication.
 *
 * \param pui32Xplicand is the pointer to the buffer containing the big
 * number multiplicand.
 * \param ui8XplicandSize is the size of the multiplicand in 32-bit word.
 * \param pui32Xplier is the pointer to the buffer containing the big
 * number multiplier.
 * \param ui8XplierSize is the size of the multiplier in 32-bit word.
 * \param pui32ResultVector is the pointer to the result vector location
 * which will be set by this function.
 *
 * \note This function starts the multiplication of the two big numbers.
 *
 *\return Returns: 
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.  
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 * some other operation. */
extern tPKAStatus PKABigNumMultiplyStart(uint32_t* pui32Xplicand,
                                         uint8_t ui8XplicandSize,
                                         uint32_t* pui32Xplier,
                                         uint8_t ui8XplierSize,
                                         uint32_t* pui32ResultVector);

/** \brief Gets the results of the big number multiplication.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result needs to be
 * stored.
 * \param pui32Len is the address of the variable containing the length of the
 * buffer.  After the operation, the actual length of the resultant is stored
 * at this address.
 * \param ui32ResVectorLoc is the address of the result location which
 * was provided by the start function \sa PKABigNumMultiplyStart().
 *
 * \note This function gets the result of the multiplication of two big numbers
 * operation previously started using the function \sa
 * PKABigNumMultiplyStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful. 
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing 
 * the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful.
 * - \b PKA_STATUS_BUF_UNDERFLOW if the length of the provided buffer is less
 * then the length of the result. */
extern tPKAStatus PKABigNumMultGetResult(uint32_t* pui32ResultBuf,
                                         uint32_t* pui32Len,
                                         uint32_t ui32ResVectorLoc);
//*****************************************************************************
//
/** \breif Starts the addition of two big number.
 *
 * \param pui32BN1 is the pointer to the buffer containing the first
 * big mumber.
 * \param ui8BN1Size is the size of the first big number in 32-bit word.
 * \param pui32BN2 is the pointer to the buffer containing the second
 * big number.
 * \param ui8BN2Size is the size of the second big number in 32-bit word.
 * \param pui32ResultVector is the pointer to the result vector location
 * which will be set by this function.
 *
 * \note This function starts the addition of the two big numbers.
 *
 *\return Returns: 
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.  
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 * some other operation. */
extern tPKAStatus PKABigNumAddStart(uint32_t* pui32BN1, uint8_t ui8BN1Size,
                                    uint32_t* pui32BN2, uint8_t ui8BN2Size,
                                    uint32_t* pui32ResultVector);

/** Gets the result of the addition operation on two big number.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result
 * needs to be stored.
 * \param pui32Len is the address of the variable containing the length of
 * the buffer.  After the operation the actual length of the resultant is
 * stored at this address.
 * \param ui32ResVectorLoc is the address of the result location which
 * was provided by the start function \sa PKABigNumAddStart().
 *
 * \note This function gets the result of the addition operation on two big 
 * numbers, previously started using the function \sa PKABigNumAddStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful. 
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing 
 * the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful.
 * - \b PKA_STATUS_BUF_UNDERFLOW if the length of the provided buffer is less
 * then the length of the result. */
extern tPKAStatus PKABigNumAddGetResult(uint32_t* pui32ResultBuf,
                                        uint32_t* pui32Len,
                                        uint32_t ui32resVectorLoc);

/** \brief Starts ECC Multiplication.
 *
 * \param pui32Scalar is pointer to the buffer containing the scalar
 * value to be multiplied.
 * \param ptEcPt is the pointer to the structure containing the
 * elliptic curve point to be multiplied.  The point should be on the given
 * curve.
 * \param ptCurve is the pointer to the structure containing the curve
 * info.
 * \param pui32ResultVector is the pointer to the result vector location
 * which will be set by this function.
 *
 * \note This function starts the Elliptical curve cryptography (ECC) point
 * multiplication operation on the EC point and the scalar value.
 *
 *\return Returns: 
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.  
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 * some other operation.  */
extern tPKAStatus PKAECCMultiplyStart(uint32_t* pui32Scalar,
                                      tECPt* ptEcPt,
                                      tECCCurveInfo* ptCurve,
                                      uint32_t* pui32ResultVector);

/** \brief Gets the result of ECC Multiplication
 *
 * \param ptOutEcPt is the pointer to the structure where the resultant EC
 * point will be stored.  The callee is responsible to allocate the space for
 * the ec point structure and the x and y co-ordinate as well.
 * \param ui32ResVectorLoc is the address of the result location which
 * was provided by the start function \sa PKAECCMultiplyStart().
 *
 * \note This function gets the result of ecc point multiplication operation on the
 * ec point and the scalar value, previously started using the function
 * \sa PKAECCMultiplyStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful. 
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing 
 * the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful. */
extern tPKAStatus PKAECCMultiplyGetResult(tECPt* ptOutEcPt,
                                          uint32_t ui32ResVectorLoc);

/** \brief Starts the ECC Multiplication with Generator point.
 *
 * \param pui32Scalar is the to pointer to the buffer containing the scalar
 * value.
 * \param ptCurve is the pointer to the structure containing the curve
 * info.
 * \param pui32ResultVector is the pointer to the result vector location
 * which will be set by this function.
 *
 * \note This function starts the ecc point multiplication operation of the
 * scalar value with the well known generator point of the given curve.
 *
 *\return Returns: 
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.  
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 * some other operation. */
extern tPKAStatus PKAECCMultGenPtStart(uint32_t* pui32Scalar,
                                       tECCCurveInfo* ptCurve,
                                       uint32_t* pui32ResultVector);

/** \brief Gets the result of ECC Multiplication with Generator point.
 *
 * \param ptOutEcPt is the pointer to the structure where the resultant EC
 * point will be stored.  The callee is responsible to allocate the space for
 * the ec point structure and the x and y co-ordinate as well.
 * \param ui32ResVectorLoc is the address of the result location which
 * was provided by the start function \sa PKAECCMultGenPtStart().
 *
 * \note This function gets the result of ecc point multiplication operation 
 * on the scalar point and the known generator point on the curve, previously 
 * started using the function \sa PKAECCMultGenPtStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful. 
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing 
 * the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful.  */
extern tPKAStatus PKAECCMultGenPtGetResult(tECPt* ptOutEcPt,
                                           uint32_t pui32ResVectorLoc);

/** \brief Starts the ECC Addition.
 *
 * \param ptEcPt1 is the pointer to the structure containing the first
 * ecc point.
 * \param ptEcPt2 is the pointer to the structure containing the
 * second ecc point.
 * \param ptCurve is the pointer to the structure containing the curve
 * info.
 * \param pui32ResultVector is the pointer to the result vector location
 * which will be set by this function.
 *
 * \note This function starts the ecc point addition operation on the
 * two given ec points and generates the resultant ecc point.
 *
 *\return Returns: 
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.  
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 * some other operation.  */
extern tPKAStatus PKAECCAddStart(tECPt* ptEcPt1, tECPt* ptEcPt2,
                                 tECCCurveInfo* ptCurve,
                                 uint32_t* pui32ResultVector);

/** \brief Gets the result of the ECC Addition
 *
 * \param ptOutEcPt is the pointer to the structure where the resultant
 *        point will be stored. The callee is responsible to allocate memory,
 *        for the ec point structure including the memory for x and y
 *        co-ordinate values.
 * \param ui32ResVectorLoc is the address of the result location which
 *        was provided by the function \sa PKAECCAddStart().
 *
 * \note This function gets the result of ecc point addition operation on the
 * on the two given ec points, previously started using the function \sa
 * PKAECCAddStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful. 
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing 
 * the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful.  */
extern tPKAStatus PKAECCAddGetResult(tECPt* ptOutEcPt, uint32_t ui32ResultLoc);

/** @} */
/*---------------------------------------------------------------------------*/
/** \name PKA functions
 * @{
 */
/**
 * \brief Enables and resets the public key accelerator driver (PKA)
 */
void pka_init(void);

/**
 * \brief Enables the PKA driver
 */
void pka_enable(void);

/**
 * \brief Disables the PKA driver
 * \note Call this function to save power when the driver is unused
 */
void pka_disable(void);

/** \brief Registers a process to be notified of the completion of a PKA
 * operation
 * \param p Process to be polled upon IRQ
 * \note This function is only supposed to be called by the PKA driver.
 */
void pka_register_process_notification(struct process *p);

/** @} */

#endif	/* PKA_H_ */
