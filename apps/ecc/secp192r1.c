/*
 * Copyright (c) SICS
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */
/**
 * \file
 *    192-bit secp192r1 curve parameters
 * \author
 *		Oriol Piñol <oriol@sics.se>
 *    Runar Mar Magnusson <rmma@kth.se>
 *
 */

#include "ecc.h"

void
get_curve_parameters(ecc_param *param)
{

#ifdef WORDS_16_BITS

  param->p[11] = 0xFFFF;
  param->p[10] = 0xFFFF;
  param->p[9] = 0xFFFF;
  param->p[8] = 0xFFFF;
  param->p[7] = 0xFFFF;
  param->p[6] = 0xFFFF;
  param->p[5] = 0xFFFF;
  param->p[4] = 0xFFFE;
  param->p[3] = 0xFFFF;
  param->p[2] = 0xFFFF;
  param->p[1] = 0xFFFF;
  param->p[0] = 0xFFFF;

  param->curve.a[11] = 0xFFFF;
  param->curve.a[10] = 0xFFFF;
  param->curve.a[9] = 0xFFFF;
  param->curve.a[8] = 0xFFFF;
  param->curve.a[7] = 0xFFFF;
  param->curve.a[6] = 0xFFFF;
  param->curve.a[5] = 0xFFFF;
  param->curve.a[4] = 0xFFFE;
  param->curve.a[3] = 0xFFFF;
  param->curve.a[2] = 0xFFFF;
  param->curve.a[1] = 0xFFFF;
  param->curve.a[0] = 0xFFFC;

  param->curve.b[11] = 0x6421;
  param->curve.b[10] = 0x0519;
  param->curve.b[9] = 0xE59C;
  param->curve.b[8] = 0x80E7;
  param->curve.b[7] = 0x0FA7;
  param->curve.b[6] = 0xE9AB;
  param->curve.b[5] = 0x7224;
  param->curve.b[4] = 0x3049;
  param->curve.b[3] = 0xFEB8;
  param->curve.b[2] = 0xDEEC;
  param->curve.b[1] = 0xC146;
  param->curve.b[0] = 0xB9B1;

  param->point.x[11] = 0x188D;
  param->point.x[10] = 0xA80E;
  param->point.x[9] = 0xB030;
  param->point.x[8] = 0x90F6;
  param->point.x[7] = 0x7CBF;
  param->point.x[6] = 0x20EB;
  param->point.x[5] = 0x43A1;
  param->point.x[4] = 0x8800;
  param->point.x[3] = 0xF4FF;
  param->point.x[2] = 0x0AFD;
  param->point.x[1] = 0x82FF;
  param->point.x[0] = 0x1012;

  param->point.y[11] = 0x0719;
  param->point.y[10] = 0x2B95;
  param->point.y[9] = 0xFFC8;
  param->point.y[8] = 0xDA78;
  param->point.y[7] = 0x6310;
  param->point.y[6] = 0x11ED;
  param->point.y[5] = 0x6B24;
  param->point.y[4] = 0xCDD5;
  param->point.y[3] = 0x73F9;
  param->point.y[2] = 0x77A1;
  param->point.y[1] = 0x1E79;
  param->point.y[0] = 0x4811;

  param->order[12] = 0x0;
  param->order[11] = 0xFFFF;
  param->order[10] = 0xFFFF;
  param->order[9] = 0xFFFF;
  param->order[8] = 0xFFFF;
  param->order[7] = 0xFFFF;
  param->order[6] = 0xFFFF;
  param->order[5] = 0x99DE;
  param->order[4] = 0xF836;
  param->order[3] = 0x146B;
  param->order[2] = 0xC9B1;
  param->order[1] = 0xB4D2;
  param->order[0] = 0x2831;

#endif

#ifdef WORDS_32_BITS

  param->p[5] = 0xFFFFFFFF;
  param->p[4] = 0xFFFFFFFF;
  param->p[3] = 0xFFFFFFFF;
  param->p[2] = 0xFFFFFFFE;
  param->p[1] = 0xFFFFFFFF;
  param->p[0] = 0xFFFFFFFF;

  param->curve.a[5] = 0xFFFFFFFF;
  param->curve.a[4] = 0xFFFFFFFF;
  param->curve.a[3] = 0xFFFFFFFF;
  param->curve.a[2] = 0xFFFFFFFE;
  param->curve.a[1] = 0xFFFFFFFF;
  param->curve.a[0] = 0xFFFFFFFC;

  param->curve.b[5] = 0x64210519;
  param->curve.b[4] = 0xE59C80E7;
  param->curve.b[3] = 0x0FA7E9AB;
  param->curve.b[2] = 0x72243049;
  param->curve.b[1] = 0xFEB8DEEC;
  param->curve.b[0] = 0xC146B9B1;

  param->point.x[5] = 0x188DA80E;
  param->point.x[4] = 0xB03090F6;
  param->point.x[3] = 0x7CBF20EB;
  param->point.x[2] = 0x43A18800;
  param->point.x[1] = 0xF4FF0AFD;
  param->point.x[0] = 0x82FF1012;

  param->point.y[5] = 0x07192B95;
  param->point.y[4] = 0xFFC8DA78;
  param->point.y[3] = 0x631011ED;
  param->point.y[2] = 0x6B24CDD5;
  param->point.y[1] = 0x73F977A1;
  param->point.y[0] = 0x1E794811;

  param->order[6] = 0x0;
  param->order[5] = 0xFFFFFFFF;
  param->order[4] = 0xFFFFFFFF;
  param->order[3] = 0xFFFFFFFF;
  param->order[2] = 0x99DEF836;
  param->order[1] = 0x146BC9B1;
  param->order[0] = 0xB4D22831;

#endif
}
