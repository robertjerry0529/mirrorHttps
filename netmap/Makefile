# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
LIB = netmap

root = /home/plainssl/v0.1

#include ${root}/Makefile.inc


#OPENSSL =  /GmSSL_app/usr/local/include
OPENSSL =  /GmSSL/include
#OPENSSL = /openssl-dev/include

RTE_SDK =  /dpdk/usr/local/share/dpdk

# all source are stored in SRCS-y
SRCS-y := kni_packet_io.c netmap.c netmap_packet_io.c netmap_parse_pkt.c 

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, detect a build directory, by looking for a path with a .config
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(CONFIG_RTE_EXEC_ENV_LINUX),y)
$(error This application can only operate in a linux environment, \
please change the definition of the RTE_TARGET environment variable)
endif

#CFLAGS += -O3
CFLAGS += -g -DALLOW_EXPERIMENTAL_API -D__LITTLE_ENDIAN_BITFIELD
CFLAGS += $(WERROR_FLAGS)


CFLAGS += -I${root}/public/include 	-I${root}/include -I${root}/iface  -I${root}/conn  -I${root}/ippool -I${root}/parse  -I${root}/utils  -I${root}/timewheel -I${root}/publib


include $(RTE_SDK)/mk/rte.extlib.mk

