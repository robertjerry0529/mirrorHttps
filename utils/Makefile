
root = ..
include ${root}/Makefile.inc


ifneq (,$(findstring GMSSL,${CPPFLAGS}))
OPENSSL =  ${GMDIR}		

else
OPENSSL = /openssl-dev/include
endif

CPPFLAGS += -I${root}/include 

OSLIBS = 
 
TARG	= utils
SRCS	=  \
	split.c utils.c
	



OBJS	= $(SRCS:.c=.o)

.PHONY:	all
all:	${TARG}

.PHONY:	clean
clean:
	rm -f *.o ${TARG} *.lob *.err *.lint *.d 

${TARG}:${OBJS}
	${LD} -r -o $@ ${OBJS}  
	

	

-include $(SRCS:.c=.d)
