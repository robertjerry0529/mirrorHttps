
root = ..
include ${root}/Makefile.inc


CPPFLAGS += -I${root}/include -I${root}/config \
-I${root}/utils -I${root}/publib

CPPFLAGS += -fPIC


OSLIBS = 
 
TARG	= timewheel
SRCS	=  \
	timewheel.c 


OBJS	= $(SRCS:.c=.o)

.PHONY:	all
all:	${TARG}

.PHONY:	clean
clean:
	rm -f *.o ${TARG} *.lob *.err *.lint *.d 

${TARG}:${OBJS} 
	${LD} -r -o $@ ${OBJS}  
#	${CC}  -o $@ ${OBJS}  -fPIC -shared  ${CPPFLAGS} 
#	cp $@ ../obj/
	
	
-include $(SRCS:.c=.d)
