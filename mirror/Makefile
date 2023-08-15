
root = ..
include ${root}/Makefile.inc


CFLAGS += -DMIRROR  -fPIC
CPPFLAGS += -I${root}/include -I${root}/publib -I${root}/conn -I${root}/timewheel -I${root}/netmap -I${root}/ippool -I${root}/sslctx

OSLIBS = 
 
TARG	= libmirror.so
SRCS	=  \
	pktout.c ${root}/conn/conn.c 
	



OBJS	= $(SRCS:.c=.o)

.PHONY:	all test
all:	${TARG}

.PHONY:	clean
clean:
	rm -f *.o ${TARG} *.lob *.err *.lint *.d 

${TARG}:${OBJS}
	gcc -shared -o $@  pktout.o conn.o  ${root}/publib/publib -g -lpcap -lpthread
	rm ${root}/conn/conn.o -rf
	
test:${OBJS} test.o
	gcc -o tpcap  pktout.o conn.o test.o ${root}/publib/publib -g -lpcap -lpthread -lcrypto -L${openssl-dev}/lib/

-include $(SRCS:.c=.d)
