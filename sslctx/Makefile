
root = ..
include ${root}/Makefile.inc

ifneq (,$(findstring GMSSL,${CPPFLAGS}))
OPENSSL =  ${GMDIR}		

else
OPENSSL = /openssl-dev/include
endif


CPPFLAGS += -I${root}/include -I/usr/local/hiredis -I${root}/utils -I${root}/publib -I${root}/syslog -I${root}/service -I${OPENSSL}
CPPFLAGS += -fPIC


OSLIBS = 
 
TARG	= sslctx
SRCS	=  \
	sslctx_post_domain.c  \



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
