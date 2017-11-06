/*
 * Original file:
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Contiki port:
 * Copyright (C) 2015 Swedish ICT - SICS - http://www.sics.se
 * Runar Mar Magnusson 
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
 * 3. Neither the name of Texas Instruments Incorporated nor the names of
 *    its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef ECC_CURVE_INFO_H_
#define ECC_CURVE_INFO_H_

#include "reg.h"

//*****************************************************************************
//
// A structure which contains the necessary elements of the
// Elliptical curve cryptography's (ECC) prime curve.
//
//*****************************************************************************
typedef struct _curveInfo
{
  char*       name; /* Name of the curve. */
  uint8_t     ui8Size; /* Size of the curve in 32-bit word. */
  uint32_t*   pui32Prime; /* The prime that defines the field of the curve. */
  uint32_t*   pui32N; /* Order of the curve. */
  uint32_t*   pui32A; /* Co-efficient a of the equation.*/
  uint32_t*   pui32B; /*  co-efficient b of the equation. */
  uint32_t*   pui32Gx; /* x co-ordinate value of the generator point. */
  uint32_t*   pui32Gy; /* y co-ordinate value of the generator point. */
} tECCCurveInfo;

#endif	/* ECC_CURVE_INFO_H_ */

