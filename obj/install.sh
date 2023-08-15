#!/bin/sh
export RTE_ARCH="x86_64"
export RTE_SDK="/home/dpdk-19.11"
export RTE_TARGET="x86_64-native-linux-gcc"
dpdk_root="/dpdk"
ifname=ens33

export T=x86_64-native-linux-gcc 

##none numa system，update the huge page number
echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
#echo 1 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages



#
if [ ! -d "/mnt/huge" ]; then
 mkdir /mnt/huge
fi

mount -t hugetlbfs nodev /mnt/huge
#exit 0
##
sudo modprobe uio_pci_generic

sudo modprobe uio

sudo insmod $dpdk_root/lib/modules/$(uname -r)/extra/dpdk/igb_uio.ko
sudo insmod $dpdk_root/lib/modules/$(uname -r)/extra/dpdk/rte_kni.ko
i=0
while [ $i -lt 50 ]
	do
		
		if0=`ifconfig -a | grep $ifname`
		if [ -n "$if0" ]; then
			break
		else
			echo "wait for interface load"
			sleep 3
		fi
	i=$i+1	
	done
	
if0=`ifconfig -a | grep $ifname`
if [ -n "$if0" ]; then
	ifconfig $ifname down >> /dev/null
fi
	

    $dpdk_root/usr/local/sbin/dpdk-devbind --bind=igb_uio $ifname
#	$dpdk_root/usr/local/sbin/dpdk-devbind --bind=igb_uio 0000:02:02.0

echo "DPDK Setup Successfully!"
