export TMPDIR = .
export VERSION = V1.0.1.1
export ROOTDIR = $(shell pwd)

BMSSLBLKS = iface netmap init conn ippool utils  sslctx syslog parse publib conn timewheel



ALLDIRS = $(BMSSLBLKS) obj mirror sslproxy

all:	
	@for i in $(ALLDIRS); do \
	    ( cd $$i; $(MAKE) $(MFLAGS); ); \
	    if [ $$? -ne 0 ]; then exit; fi \
	done 
	if [ $$? -ne 0 ]; then exit; fi 



clean:
	@for i in $(ALLDIRS); do \
	    (cd $$i; $(MAKE) $(MFLAGS) clean); \
	done
	
	rm -f *.err *.lint 
	rm -f *.bin 

package:all
	@cp obj/bmsslvpn ./install/package/bin
	@cp syslog/clear_log ./install/package/bin
	@tar cvf ./install/package_${VERSION}.tar ./install/package
	@gzip ./install/package_${VERSION}.tar
	@echo "Package complete"
	
clean-d:
	@for i in $(ALLDIRS); do \
	    (cd $$i; rm *.d); \
	done
	rm -f *.err *.lint *.d
	rm -f *.bin *.d



