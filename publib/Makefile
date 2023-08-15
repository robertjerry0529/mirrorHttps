
root = ..
include ${root}/Makefile.inc

ifneq (,$(findstring GMSSL,${CPPFLAGS}))
OPENSSL =  ${GMDIR}		

else
OPENSSL = /openssl-dev/include
endif


CPPFLAGS += -I${root}/include -I${root}/utils -I${root}/gc -I${root}/config -I${root}/syslog 
CPPFLAGS += -fPIC


OSLIBS = 
 
TARG	= publib
SRCS	=  \
	hashtab.c base64.c kfifo.c  block.c iputils.c \



OBJS	= $(SRCS:.c=.o)

.PHONY:	all
all:	${TARG}

.PHONY:	clean
clean:
	rm -f *.o ${TARG} *.lob *.err *.lint *.d 

${TARG}:${OBJS}
	${LD} -r -o $@ ${OBJS}  
#	${CC}  -o $@ ${OBJS}  -fPIC -shared  ${CPPFLAGS} 
#
#	cp $@ ../obj/

	

-include $(SRCS:.c=.d)
