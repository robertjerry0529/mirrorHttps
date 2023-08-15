
root = ..
include ${root}/Makefile.inc


CPPFLAGS += -I./ -I${root}/include -I${root}/utils -I${root}/syslog



OSLIBS = 
 
TARG	= init
SRCS	=  \
	init.c kickoff.c



OBJS	= $(SRCS:.c=.o)

.PHONY:	all
all:	${TARG}

.PHONY:	clean
clean:
	rm -f *.o ${TARG} *.lob *.err *.lint *.d 

${TARG}:${OBJS}
	${LD} -r -o $@ ${OBJS}  

	
	

-include $(SRCS:.c=.d)
