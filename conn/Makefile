
root = ..
include ${root}/Makefile.inc


CPPFLAGS += -I./ -I${root}/include -I${root}/ippool -I${root}/timewheel -I${root}/sslctx -I${root}/utils



OSLIBS = 
 
TARG	= conn
SRCS	=  \
	conn.c



OBJS	= $(SRCS:.c=.o)

.PHONY:	all
all:	${TARG}

.PHONY:	clean
clean:
	rm -f *.o ${TARG} *.lob *.err *.lint *.d 

${TARG}:${OBJS}
	${LD} -r -o $@ ${OBJS}  
	rm conn.o

	
	

-include $(SRCS:.c=.d)
