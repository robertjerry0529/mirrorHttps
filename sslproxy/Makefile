root=..

CPPFLAGS += 



OSLIBS = 
 
TARG	= sslproxy
SRCS	=  \
	



OBJS	= $(SRCS:.c=.o)

.PHONY:	all
all:	${TARG}

.PHONY:	clean
clean:
	rm -f *.o ${TARG} *.lob *.err *.lint *.d 

${TARG}:${OBJS}
	go build 
	cp ${root}/mirror/libmirror.so ./ -rf

	
	

-include $(SRCS:.c=.d)
