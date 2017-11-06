CONTIKI = ../../../../../openmote-ike

ifndef TARGET
TARGET=cooja
endif

CONTIKI_ECC_DIR = ..

all: alice bob


ifeq ($(TARGET),cooja)
#  CPU_ARCH = THIRTYTWO_BIT_PROCESSOR
  CPU_ARCH = SIXTEEN_BIT_PROCESSOR
  CPU = x86
endif

ifeq ($(TARGET),micaz)
  CPU_ARCH = EIGHT_BIT_PROCESSOR
  CPU = avr
endif

ifeq ($(TARGET),sky)
  CPU_ARCH = SIXTEEN_BIT_PROCESSOR
  CPU = msp430
endif

ifeq ($(TARGET),openmote)
#  CPU_ARCH = THIRTYTWO_BIT_PROCESSOR
  CPU_ARCH = SIXTEEN_BIT_PROCESSOR
  CPU = cc2538
endif

ifeq ($(TARGET),cc2538dk)
#  CPU_ARCH = THIRTYTWO_BIT_PROCESSOR
  CPU_ARCH = SIXTEEN_BIT_PROCESSOR
  CPU = cc2538
endif

DOMAIN_PARAMS = SECP160R1

PROJECT_SOURCEFILES += messages.c
include $(CONTIKI_ECC_DIR)/Makefile.contikiecc

include $(CONTIKI)/Makefile.include
