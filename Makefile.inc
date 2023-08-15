
export TMPDIR = .
HOST_CC=gcc
HOST_CFLAGS= -O 

MFLAGS= -j4

CPPFLAGS=
CFLAGS= -g -ggdb -Wall -W -Wno-format -Wpointer-arith -Wcast-align 

CPPFLAGS += -DOS_PLATFORM_LINUX -DGNU -D__LITTLE_ENDIAN_BITFIELD

# Uncomment to build with DEBUG turned on
CPPFLAGS+= -DDEBUG

# Uncomment to build for releases (no debugging, etc.)
#CPPFLAGS+=  -DRELEASE


ifneq (,$(findstring -DGDB,${CPPFLAGS}))
    CFLAGS+= -Wno-unused
else
#     CFLAGS+= -O2
    #CFLAGS+= -Werror -O2
endif

CFLAGS+= -Wno-unused


TOOLCHAIN =
UNAME := $(shell uname -sr)
	CC      = ${TOOLCHAIN}gcc
	LD      = ${TOOLCHAIN}ld
	AR      = ${TOOLCHAIN}ar
	AS      = ${TOOLCHAIN}as
	NM      = ${TOOLCHAIN}nm
	SZ      = ${TOOLCHAIN}size
	OBJCOPY = ${TOOLCHAIN}objcopy
	CPP     = ${TOOLCHAIN}cpp
	STRIP   = ${TOOLCHAIN}strip

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $<
.S.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $<
%.d: %.c
	$(CC) -MM $(CPPFLAGS) $< | sed 's%$(*F).o:%$*.o $@:%' > $@
%.d: %.S
	$(CC) -MM $(CPPFLAGS) $< | sed 's%$(*F).o:%$*.o $@:%' > $@

