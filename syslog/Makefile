
root = ..
include ${root}/Makefile.inc


CPPFLAGS += -I${root}/include -I${root}/epoll_agent -I${root}/config \
-I${root}/utils -I${root}/publib

CPPFLAGS += -fPIC


OSLIBS = 
 
TARG	= syslog
SRCS	=  \
	plat_log.c 


OBJS	= $(SRCS:.c=.o)

.PHONY:	all
all:	${TARG}

.PHONY:	clean
clean:
	rm -f *.o ${TARG} *.lob *.err *.lint *.d 

${TARG}:${OBJS} clear_log
	${LD} -r -o $@ ${OBJS}  
#	${CC}  -o $@ ${OBJS}  -fPIC -shared  ${CPPFLAGS} 
#	cp $@ ../obj/
	
clear_log:clear_log.c
	${CC} -o clear_log clear_log.c
	
-include $(SRCS:.c=.d)
