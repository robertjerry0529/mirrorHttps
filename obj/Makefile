
root	= ..
include ${root}/Makefile.inc

CURRENT_TIME=$(date "+%Y%m%d%H%M%S")

ifneq (,$(findstring GMSSL,${CPPFLAGS}))
	OPENSSLLIB =${GMLIB}
else
	OPENSSLLIB = /openssl-dev/lib
endif



CPPFLAGS +=  -I${root}/init   -I${root}/include


TARG	= plainssl
BLOCKS	=  \
	${root}/init/init \
	${root}/conn/conn \
	${root}/iface/build/iface \
	${root}/netmap/build/netmap \
	${root}/ippool/ippool \
	${root}/utils/utils \
	${root}/parse/parse \
	${root}/publib/publib \
	${root}/syslog/syslog \
	${root}/sslctx/sslctx \
	${root}/timewheel/timewheel \
	
	
	#	${root}/service/service \

	
PC_FILE := $(shell pkg-config  libdpdk)
	CFLAGS += $(shell pkg-config --cflags libdpdk) -I /dpdk/usr/local/include
	LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk) -I /dpdk/usr/local/include
	LDFLAGS_STATIC = -Wl,-Bstatic $(shell pkg-config --static --libs libdpdk) -L/dpdk/usr/local/lib -Wl,-dy
	

	
DPDK-LDLBAS = -Wl,--whole-archive -lrte_eal  -lrte_kvargs -lrte_ring -lrte_mempool -lrte_mbuf -lrte_pci -lrte_cryptodev -lrte_net -lrte_meter -lrte_ethdev -lrte_hash -lrte_timer -lrte_common_dpaax -lrte_eventdev -lrte_rawdev -lrte_bus_dpaa -lrte_bus_fslmc -lrte_bus_pci -lrte_common_octeontx -lrte_common_octeontx2 -lrte_stack -lrte_mempool_dpaa2 -lrte_bus_vdev -lrte_sched -lrte_ip_frag -lrte_mempool_dpaa -lrte_vhost -lrte_security -lrte_kni -lrte_bus_vmbus -lrte_mempool_octeontx -lrte_mempool_octeontx2 -lrte_port -lrte_lpm -lrte_acl -lrte_table -lrte_pipeline -lrte_gso -lrte_common_cpt -lrte_reorder -lrte_compressdev -lrte_pmd_dpaa -lrte_pmd_dpaa_sec -lrte_pmd_dpaa2 -lrte_pmd_dpaa2_sec -lrte_pmd_octeontx2 -lrte_pmd_octeontx -lrte_bbdev -lrte_rib -lrte_metrics -lrte_bus_ifpga -lrte_mempool_bucket -lrte_mempool_ring -lrte_mempool_stack -lrte_rawdev_dpaa2_cmdif -lrte_rawdev_dpaa2_qdma -lrte_rawdev_ioat -lrte_rawdev_ntb -lrte_rawdev_octeontx2_dma -lrte_rawdev_skeleton -lrte_pmd_af_packet -lrte_pmd_ark -lrte_pmd_atlantic -lrte_pmd_avp -lrte_pmd_axgbe -lrte_pmd_bond -lrte_pmd_bnxt -lrte_pmd_cxgbe -lrte_pmd_e1000 -lrte_pmd_ena -lrte_pmd_enetc -lrte_pmd_enic -lrte_pmd_failsafe -lrte_pmd_fm10k -lrte_pmd_i40e -lrte_pmd_hinic -lrte_pmd_hns3 -lrte_pmd_iavf -lrte_pmd_ice -lrte_pmd_ifc -lrte_pmd_ixgbe -lrte_pmd_kni  -lrte_pmd_memif -lrte_pmd_netvsc -lrte_pmd_nfp -lrte_pmd_null  -lrte_pmd_qede -lrte_pmd_ring  -lrte_pmd_softnic -lrte_pmd_tap  -lrte_pmd_vdev_netvsc -lrte_pmd_vmxnet3_uio -lrte_pmd_vhost -lrte_pmd_virtio  -lrte_pmd_caam_jr  -lrte_pmd_nitrox -lrte_pmd_null_crypto -lrte_pmd_octeontx_crypto -lrte_pmd_octeontx2_crypto  -lrte_pmd_crypto_scheduler -lrte_pmd_virtio_crypto  -lrte_pmd_qat  -lrte_pmd_dpaa_event -lrte_pmd_dpaa2_event -lrte_pmd_octeontx2_event -lrte_pmd_opdl_event -lrte_pmd_skeleton_event -lrte_pmd_sw_event -lrte_pmd_dsw_event  -lrte_pmd_bbdev_null -lrte_pmd_bbdev_turbo_sw -lrte_pmd_bbdev_fpga_lte_fec -lrte_bpf -lrte_flow_classify -lrte_fib -lrte_ipsec -lrte_rcu -lrte_pdump -lrte_power -lrte_member -lrte_latencystats -lrte_jobstats -lrte_gro -lrte_efd -lrte_distributor -lrte_cfgfile -lrte_bitratestats -lrte_cmdline -lm -lnuma -Wl,-no-whole-archive -ldl   -L/dpdk/usr/local/lib -Wl,-dy


	
OSLIBS = -Wl,-Bstatic /usr/local/lib/libhiredis.a -Wl,-Bstatic -Wl,-dy  -ldl -lc -lnuma -lpthread -lpcap

#/lib64/libcrypto.so.1.1

all:	$(TARG)
.PHONY:checksym

.PHONY:	clean
clean:
	rm -f *.o  *.so ${TARG} *.d 
	
$(TARG): ${BLOCKS} Makefile main.o ${MODULE_SO}
	${CC} -o $@  main.o ${BLOCKS} ${LIBS}    ${MODULE_SO} ${OSLIBS}  ${CFLAGS} ${DPDK-LDLBAS}
	
	
#	$(LDFLAGS_STATIC)

main.o:main.c
	${CC} -c ${CFLAGS} -o $@ main.c  ${CPPFLAGS} 
