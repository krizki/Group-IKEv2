/**
 * \addtogroup ipsec
 * @{
 */

/**
 * \file
 *    Special malloc used in IPsec for debugging and profiling
 * \author
 *		Vilhelm Jutvik <ville@imorgon.se>
 *
 */

/*
 * Copyright (c) 2012, Vilhelm Jutvik.
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

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ipsec.h"
#include "common-ipsec.h"

#if IPSEC_MEM_STATS
uint32_t allocated = 0;
#endif

/*---------------------------------------------------------------------------*/
void *
ipsec_malloc(size_t size)
{
  void *ptr = NULL;
#ifdef USE_HEAP
  ptr = malloc(size);
#else
#warning USE_HEAP not defined add to project makefile with CFLAGS += -DUSE_HEAP
  IPSEC_PRINTF(IPSEC_ERROR "malloc() not defined or USE_HEAP not defined\n");
#endif
  if(ptr == NULL) {
    IPSEC_PRINTF(IPSEC_ERROR "malloc() out of memory (%u bytes requested)\n", size);
    return NULL;
  }
#if IPSEC_MEM_STATS
  allocated += size;
  IPSEC_PRINTF(IPSEC "Allocating %u bytes at %p. IPsec now has allocated %u B memory\n", size, ptr, allocated);
#else
  IPSEC_PRINTF(IPSEC "Allocating %u bytes at %p\n", size, ptr);
#endif
  return ptr;
}
/*---------------------------------------------------------------------------*/
void
ipsec_free(void *ptr)
{
  if(ptr != NULL) {
    IPSEC_PRINTF(IPSEC "Freeing memory at %p\n", ptr);
#ifdef USE_HEAP
    free(ptr);
#else
    IPSEC_PRINTF(IPSEC_ERROR "malloc() not defined or USE_HEAP not defined\n");
#endif
  }
}
/*---------------------------------------------------------------------------*/
/** @} */
