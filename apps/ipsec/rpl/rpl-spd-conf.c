/*
 * Copyright (c) 2015, SICS.
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

#include "spd.h"
#include "rpl-sa.h"
#include "rpl-spd-conf.h"
#include "spd-conf.h"
#include "rpl-ike-conf.h"

/**
 * RPL proposal (change size to include more transforms)
 */
const spd_proposal_tuple_t my_rpl_proposal[3] =
{
  /* RPL proposal */
  { SA_CTRL_NEW_PROPOSAL, SA_PROTO_RPL },
#ifdef RPL_ENCR
  { SA_CTRL_TRANSFORM_TYPE_ENCR, RPL_ENCR },
#else
  { SA_CTRL_TRANSFORM_TYPE_ENCR, RPL_ENCR_DEFAULT },
#endif

#ifdef RPL_INTEG
  { SA_CTRL_TRANSFORM_TYPE_INTEG, RPL_INTEG },
#endif

  /* Terminate the offer */
  { SA_CTRL_END_OF_OFFER, 0 }
};

