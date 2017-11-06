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
 *    160-bit brainpool curve parameters
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

  param->p[9] = 0xE95E;
  param->p[8] = 0x4A5F;
  param->p[7] = 0x7370;
  param->p[6] = 0x59DC;
  param->p[5] = 0x60DF;
  param->p[4] = 0xC7AD;
  param->p[3] = 0x95B3;
  param->p[2] = 0xD813;
  param->p[1] = 0x9515;
  param->p[0] = 0x620F;

  param->curve.a[9] = 0x340E;
  param->curve.a[8] = 0x7BE2;
  param->curve.a[7] = 0xA280;
  param->curve.a[6] = 0xEB74;
  param->curve.a[5] = 0xE2BE;
  param->curve.a[4] = 0x61BA;
  param->curve.a[3] = 0xDA74;
  param->curve.a[2] = 0x5D97;
  param->curve.a[1] = 0xE8F7;
  param->curve.a[0] = 0xC300;

  param->curve.b[9] = 0x1E58;
  param->curve.b[8] = 0x9A85;
  param->curve.b[7] = 0x9542;
  param->curve.b[6] = 0x3412;
  param->curve.b[5] = 0x134F;
  param->curve.b[4] = 0xAA2D;
  param->curve.b[3] = 0xBDEC;
  param->curve.b[2] = 0x95C8;
  param->curve.b[1] = 0xD867;
  param->curve.b[0] = 0x5E58;

  param->point.x[9] = 0xBED5;
  param->point.x[8] = 0xAF16;
  param->point.x[7] = 0xEA3F;
  param->point.x[6] = 0x6A4F;
  param->point.x[5] = 0x6293;
  param->point.x[4] = 0x8C46;
  param->point.x[3] = 0x31EB;
  param->point.x[2] = 0x5AF7;
  param->point.x[1] = 0xBDBC;
  param->point.x[0] = 0xDBC3;

  param->point.y[9] = 0x1667;
  param->point.y[8] = 0xCB47;
  param->point.y[7] = 0x7A1A;
  param->point.y[6] = 0x8EC3;
  param->point.y[5] = 0x38F9;
  param->point.y[4] = 0x4741;
  param->point.y[3] = 0x669C;
  param->point.y[2] = 0x9763;
  param->point.y[1] = 0x16DA;
  param->point.y[0] = 0x6321;

  param->order[10] = 0x0;
  param->order[9] = 0xE95E;
  param->order[8] = 0x4A5F;
  param->order[7] = 0x7370;
  param->order[6] = 0x59DC;
  param->order[5] = 0x60DF;
  param->order[4] = 0x5991;
  param->order[3] = 0xD450;
  param->order[2] = 0x2940;
  param->order[1] = 0x9E60;
  param->order[0] = 0xFC09;

#endif

#ifdef WORDS_32_BITS

  param->p[4] = 0xE95E4A5F;
  param->p[3] = 0x737059DC;
  param->p[2] = 0x60DFC7AD;
  param->p[1] = 0x95B3D813;
  param->p[0] = 0x9515620F;

  param->curve.a[4] = 0x340E7BE2;
  param->curve.a[3] = 0xA280EB74;
  param->curve.a[2] = 0xE2BE61BA;
  param->curve.a[1] = 0xDA745D97;
  param->curve.a[0] = 0xE8F7C300;

  param->curve.b[4] = 0x1E589A85;
  param->curve.b[3] = 0x95423412;
  param->curve.b[2] = 0x134FAA2D;
  param->curve.b[1] = 0xBDEC95C8;
  param->curve.b[0] = 0xD8675E58;

  param->point.x[4] = 0xBED5AF16;
  param->point.x[3] = 0xEA3F6A4F;
  param->point.x[2] = 0x62938C46;
  param->point.x[1] = 0x31EB5AF7;
  param->point.x[0] = 0xBDBCDBC3;

  param->point.y[4] = 0x1667CB47;
  param->point.y[3] = 0x7A1A8EC3;
  param->point.y[2] = 0x38F94741;
  param->point.y[1] = 0x669C9763;
  param->point.y[0] = 0x16DA6321;

  param->order[5] = 0x0;
  param->order[4] = 0xE95E4A5F;
  param->order[3] = 0x737059DC;
  param->order[2] = 0x60DF5991;
  param->order[1] = 0xD4502940;
  param->order[0] = 0x9E60FC09;
#endif
}