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
 *    256-bit SECP256R1 curve parameters
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

  param->p[15] = 0xFFFF;
  param->p[14] = 0xFFFF;
  param->p[13] = 0x0000;
  param->p[12] = 0x0001;
  param->p[11] = 0x0000;
  param->p[10] = 0x0000;
  param->p[9] = 0x0000;
  param->p[8] = 0x0000;
  param->p[7] = 0x0000;
  param->p[6] = 0x0000;
  param->p[5] = 0xFFFF;
  param->p[4] = 0xFFFF;
  param->p[3] = 0xFFFF;
  param->p[2] = 0xFFFF;
  param->p[1] = 0xFFFF;
  param->p[0] = 0xFFFF;

  param->curve.a[15] = 0xFFFF;
  param->curve.a[14] = 0xFFFF;
  param->curve.a[13] = 0x0000;
  param->curve.a[12] = 0x0001;
  param->curve.a[11] = 0x0000;
  param->curve.a[10] = 0x0000;
  param->curve.a[9] = 0x0000;
  param->curve.a[8] = 0x0000;
  param->curve.a[7] = 0x0000;
  param->curve.a[6] = 0x0000;
  param->curve.a[5] = 0xFFFF;
  param->curve.a[4] = 0xFFFF;
  param->curve.a[3] = 0xFFFF;
  param->curve.a[2] = 0xFFFF;
  param->curve.a[1] = 0xFFFF;
  param->curve.a[0] = 0xFFFC;

  param->curve.b[15] = 0x5AC6;
  param->curve.b[14] = 0x35D8;
  param->curve.b[13] = 0xAA3A;
  param->curve.b[12] = 0x93E7;
  param->curve.b[11] = 0xB3EB;
  param->curve.b[10] = 0xBD55;
  param->curve.b[9] = 0x7698;
  param->curve.b[8] = 0x86BC;
  param->curve.b[7] = 0x651D;
  param->curve.b[6] = 0x06B0;
  param->curve.b[5] = 0xCC53;
  param->curve.b[4] = 0xB0F6;
  param->curve.b[3] = 0x3BCE;
  param->curve.b[2] = 0x3C3E;
  param->curve.b[1] = 0x27D2;
  param->curve.b[0] = 0x604B;

  param->point.x[15] = 0x6B17;
  param->point.x[14] = 0xD1F2;
  param->point.x[13] = 0xE12C;
  param->point.x[12] = 0x4247;
  param->point.x[11] = 0xF8BC;
  param->point.x[10] = 0xE6E5;
  param->point.x[9] = 0x63A4;
  param->point.x[8] = 0x40F2;
  param->point.x[7] = 0x7703;
  param->point.x[6] = 0x7D81;
  param->point.x[5] = 0x2DEB;
  param->point.x[4] = 0x33A0;
  param->point.x[3] = 0xF4A1;
  param->point.x[2] = 0x3945;
  param->point.x[1] = 0xD898;
  param->point.x[0] = 0xC296;

  param->point.y[15] = 0x4FE3;
  param->point.y[14] = 0x42E2;
  param->point.y[13] = 0xFE1A;
  param->point.y[12] = 0x7F9B;
  param->point.y[11] = 0x8EE7;
  param->point.y[10] = 0xEB4A;
  param->point.y[9] = 0x7C0F;
  param->point.y[8] = 0x9E16;
  param->point.y[7] = 0x2BCE;
  param->point.y[6] = 0x3357;
  param->point.y[5] = 0x6B31;
  param->point.y[4] = 0x5ECE;
  param->point.y[3] = 0xCBB6;
  param->point.y[2] = 0x4068;
  param->point.y[1] = 0x37BF;
  param->point.y[0] = 0x51F5;

  param->order[16] = 0x0;
  param->order[15] = 0xFFFF;
  param->order[14] = 0xFFFF;
  param->order[13] = 0x0000;
  param->order[12] = 0x0000;
  param->order[11] = 0xFFFF;
  param->order[10] = 0xFFFF;
  param->order[9] = 0xFFFF;
  param->order[8] = 0xFFFF;
  param->order[7] = 0xBCE6;
  param->order[6] = 0xFAAD;
  param->order[5] = 0xA717;
  param->order[4] = 0x9E84;
  param->order[3] = 0xF3B9;
  param->order[2] = 0xCAC2;
  param->order[1] = 0xFC63;
  param->order[0] = 0x2551;

#endif

#ifdef WORDS_32_BITS

  param->p[7] = 0xFFFFFFFF;
  param->p[6] = 0X00000001;
  param->p[5] = 0x00000000;
  param->p[4] = 0x00000000;
  param->p[3] = 0x00000000;
  param->p[2] = 0xFFFFFFFF;
  param->p[1] = 0xFFFFFFFF;
  param->p[0] = 0xFFFFFFFF;

  param->curve.a[7] = 0xFFFFFFFF;
  param->curve.a[6] = 0x00000001;
  param->curve.a[5] = 0x00000000;
  param->curve.a[4] = 0x00000000;
  param->curve.a[3] = 0x00000000;
  param->curve.a[2] = 0xFFFFFFFF;
  param->curve.a[1] = 0xFFFFFFFF;
  param->curve.a[0] = 0xFFFFFFFC;

  param->curve.b[7] = 0x5AC635D8;
  param->curve.b[6] = 0xAA3A93E7;
  param->curve.b[5] = 0xB3EBBD55;
  param->curve.b[4] = 0x769886BC;
  param->curve.b[3] = 0x651D06B0;
  param->curve.b[2] = 0xCC53B0F6;
  param->curve.b[1] = 0x3BCE3C3E;
  param->curve.b[0] = 0x27D2604B;

  param->point.x[7] = 0x6B17D1F2;
  param->point.x[6] = 0xE12C4247;
  param->point.x[5] = 0xF8BCE6E5;
  param->point.x[4] = 0x63A440F2;
  param->point.x[3] = 0x77037D81;
  param->point.x[2] = 0x2DEB33A0;
  param->point.x[1] = 0xF4A13945;
  param->point.x[0] = 0xD898C296;

  param->point.y[7] = 0x4FE342E2;
  param->point.y[6] = 0xFE1A7F9B;
  param->point.y[5] = 0x8EE7EB4A;
  param->point.y[4] = 0x7C0F9E16;
  param->point.y[3] = 0x2BCE3357;
  param->point.y[2] = 0x6B315ECE;
  param->point.y[1] = 0xCBB64068;
  param->point.y[0] = 0x37BF51F5;

  param->order[8] = 0x0;
  param->order[7] = 0xFFFFFFFF;
  param->order[6] = 0x00000000;
  param->order[5] = 0xFFFFFFFF;
  param->order[4] = 0xFFFFFFFF;
  param->order[3] = 0xBCE6FAAD;
  param->order[2] = 0xA7179E84;
  param->order[1] = 0xF3B9CAC2;
  param->order[0] = 0xFC632551;

#endif
}
