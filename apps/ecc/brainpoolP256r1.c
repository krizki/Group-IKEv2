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
 *    256-bit brainpool curve parameters
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

  param->p[15] = 0xA9FB;
  param->p[14] = 0x57DB;
  param->p[13] = 0xA1EE;
  param->p[12] = 0xA9BC;
  param->p[11] = 0x3E66;
  param->p[10] = 0x0A90;
  param->p[9] = 0x9D83;
  param->p[8] = 0x8D72;
  param->p[7] = 0x6E3B;
  param->p[6] = 0xF623;
  param->p[5] = 0xD526;
  param->p[4] = 0x2028;
  param->p[3] = 0x2013;
  param->p[2] = 0x481D;
  param->p[1] = 0x1F6E;
  param->p[0] = 0x5377;

  param->curve.a[15] = 0x7D5A;
  param->curve.a[14] = 0x0975;
  param->curve.a[13] = 0xFC2C;
  param->curve.a[12] = 0x3057;
  param->curve.a[11] = 0xEEF6;
  param->curve.a[10] = 0x7530;
  param->curve.a[9] = 0x417A;
  param->curve.a[8] = 0xFFE7;
  param->curve.a[7] = 0xFB80;
  param->curve.a[6] = 0x55C1;
  param->curve.a[5] = 0x26DC;
  param->curve.a[4] = 0x5C6C;
  param->curve.a[3] = 0xE94A;
  param->curve.a[2] = 0x4B44;
  param->curve.a[1] = 0xF330;
  param->curve.a[0] = 0xB5D9;

  param->curve.b[15] = 0x26DC;
  param->curve.b[14] = 0x5C6C;
  param->curve.b[13] = 0xE94A;
  param->curve.b[12] = 0x4B44;
  param->curve.b[11] = 0xF330;
  param->curve.b[10] = 0xB5D9;
  param->curve.b[9] = 0xBBD7;
  param->curve.b[8] = 0x7CBF;
  param->curve.b[7] = 0x9584;
  param->curve.b[6] = 0x1629;
  param->curve.b[5] = 0x5CF7;
  param->curve.b[4] = 0xE1CE;
  param->curve.b[3] = 0x6BCC;
  param->curve.b[2] = 0xDC18;
  param->curve.b[1] = 0xFF8C;
  param->curve.b[0] = 0x07B6;

  param->point.x[15] = 0x8BD2;
  param->point.x[14] = 0xAEB9;
  param->point.x[13] = 0xCB7E;
  param->point.x[12] = 0x57CB;
  param->point.x[11] = 0x2C4B;
  param->point.x[10] = 0x482F;
  param->point.x[9] = 0xFC81;
  param->point.x[8] = 0xB7AF;
  param->point.x[7] = 0xB9DE;
  param->point.x[6] = 0x27E1;
  param->point.x[5] = 0xE3BD;
  param->point.x[4] = 0x23C2;
  param->point.x[3] = 0x3A44;
  param->point.x[2] = 0x53BD;
  param->point.x[1] = 0x9ACE;
  param->point.x[0] = 0x3262;

  param->point.y[15] = 0x547E;
  param->point.y[14] = 0xF835;
  param->point.y[13] = 0xC3DA;
  param->point.y[12] = 0xC4FD;
  param->point.y[11] = 0x97F8;
  param->point.y[10] = 0x461A;
  param->point.y[9] = 0x1461;
  param->point.y[8] = 0x1DC9;
  param->point.y[7] = 0xC277;
  param->point.y[6] = 0x4513;
  param->point.y[5] = 0x2DED;
  param->point.y[4] = 0x8E54;
  param->point.y[3] = 0x5C1D;
  param->point.y[2] = 0x54C7;
  param->point.y[1] = 0x2F04;
  param->point.y[0] = 0x6997;

  param->order[16] = 0x0;
  param->order[15] = 0xA9FB;
  param->order[14] = 0x57DB;
  param->order[13] = 0xA1EE;
  param->order[12] = 0xA9BC;
  param->order[11] = 0x3E66;
  param->order[10] = 0x0A90;
  param->order[9] = 0x9D83;
  param->order[8] = 0x8D71;
  param->order[7] = 0x8C39;
  param->order[6] = 0x7AA3;
  param->order[5] = 0xB561;
  param->order[4] = 0xA6F7;
  param->order[3] = 0x901E;
  param->order[2] = 0x0E82;
  param->order[1] = 0x9748;
  param->order[0] = 0x56A7;

#endif

#ifdef WORDS_32_BITS

  param->p[7] = 0xA9FB57DB;
  param->p[6] = 0xA1EEA9BC;
  param->p[5] = 0x3E660A90;
  param->p[4] = 0x9D838D72;
  param->p[3] = 0x6E3BF623;
  param->p[2] = 0xD5262028;
  param->p[1] = 0x2013481D;
  param->p[0] = 0x1F6E5377;

  param->curve.a[7] = 0x7D5A0975;
  param->curve.a[6] = 0xFC2C3057;
  param->curve.a[5] = 0xEEF67530;
  param->curve.a[4] = 0x417AFFE7;
  param->curve.a[3] = 0xFB8055C1;
  param->curve.a[2] = 0x26DC5C6C;
  param->curve.a[1] = 0xE94A4B44;
  param->curve.a[0] = 0xF330B5D9;

  param->curve.b[7] = 0x26DC5C6C;
  param->curve.b[6] = 0xE94A4B44;
  param->curve.b[5] = 0xF330B5D9;
  param->curve.b[4] = 0xBBD77CBF;
  param->curve.b[3] = 0x95841629;
  param->curve.b[2] = 0x5CF7E1CE;
  param->curve.b[1] = 0x6BCCDC18;
  param->curve.b[0] = 0xFF8C07B6;

  param->point.x[7] = 0x8BD2AEB9;
  param->point.x[6] = 0xCB7E57CB;
  param->point.x[5] = 0x2C4B482F;
  param->point.x[4] = 0xFC81B7AF;
  param->point.x[3] = 0xB9DE27E1;
  param->point.x[2] = 0xE3BD23C2;
  param->point.x[1] = 0x3A4453BD;
  param->point.x[0] = 0x9ACE3262;

  param->point.y[7] = 0x547EF835;
  param->point.y[6] = 0xC3DAC4FD;
  param->point.y[5] = 0x97F8461A;
  param->point.y[4] = 0x14611DC9;
  param->point.y[3] = 0xC2774513;
  param->point.y[2] = 0x2DED8E54;
  param->point.y[1] = 0x5C1D54C7;
  param->point.y[0] = 0x2F046997;

  param->order[8] = 0x0;
  param->order[7] = 0xA9FB57DB;
  param->order[6] = 0xA1EEA9BC;
  param->order[5] = 0x3E660A90;
  param->order[4] = 0x9D838D71;
  param->order[3] = 0x8C397AA3;
  param->order[2] = 0xB561A6F7;
  param->order[1] = 0x901E0E82;
  param->order[0] = 0x974856A7;

#endif
}