CONTIKI=../../../../..
#DTLS=../

all: parser-test

CFLAGS += -DPROJECT_CONF_H=\"project-config.h\"
CFLAGS+= -DUIP_CONF_IPV6 #-DUIP_CONF_TCP=0

WITH_UIP6=1
UIP_CONF_RPL=0

CURVE_PARAMS = SECP256R1

# check if relic library is present
#$(if $(wildcard $(DTLS)/relic/librelic_s.a),,$(error "relic library is missing."))
#$(if $(wildcard $(DTLS)/relic/include/relic.h),,$(error "relic library is missing."))

# support for relic-toolkit library
#PROJECT_LIBRARIES+= $(DTLS)/relic/librelic_s.a

CFLAGS+= -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__


PROJECT_SOURCEFILES += ../cert-parser.c

include $(CONTIKI)/Makefile.include
