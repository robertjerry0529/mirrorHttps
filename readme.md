# MirrorHttps 

Traditional devices monitor HTTPS content, and the information they can collect is very limited. In this project, local HTTPS is decrypted through HTTPS proxy, and plaintext content is mirrored to other devices to facilitate content analysis and content collection, the mirrored packet carry the original address information.

# deploy
MIrrorHttps uses the switch mirroring interface to mirror the message to MirrorHttps. MirrorHttps returns the response message to the network through the re-injection interface. The returned message is considered to be the response message of the original target server. The text is returned to the requesting host. Looking at the IP level, the requesting host will think that this is the reply message of the original target host, thereby establishing a tcp connection, but actually establishing a communication link between the requesting host and MirrorHttps.
After MirrorHttps obtains the link, it implements https message service, parses the client request, and initiates a request to the real target server through the local client proxy, and returns the obtained response content to the original requesting client.

deploy:![alt 部署图](https://github.com/robertjerry0529/mirrorHttps/blob/main/mirrorhttps.png?raw=true)

# Compile：
## install dpdk
cd /home
wget http://fast.dpdk.org/rel/dpdk-19.11.14.tar.xz
tar xvf dpdk-19.11.14.tar.xz
cd dpdk-19.11.14
yum install -y make gcc gcc-c++  kernel-devel kernel-headers kernel.x86_64 net-tools
yum install -y numactl-devel.x86_64 numactl-libs.x86_64
yum install -y libpcap.x86_64 libpcap-devel.x86_64
yum install -y pciutils wget xz 
reboot

cd /home/dpdk-19.11.14
export RTE_SDK=/home/dpdk-19.11.14
export DESTDIR=/dpdk
make config T=x86_64-native-linuxapp-gcc prefix=/dpdk 
make j=4
make install

## install redis
yum install -y redis
systemctl enable redis
systemctl start redis

## install mirrorHttps
git clone https://github.com/robertjerry0529/mirrorHttps.git
cd mirrorHttps
make 

# configuration:
obj/install.sh中，instruct mirror interface and inject interface，which will be taken over by dpdk；
netmap use private ip pool whick may not conflict with your local network，generally not need modify。
service config ：give mirrorHttps a ip address
netmap reinject gateway : reject packet to network via the gateway


whiteItem.txt:   domain list which need to bypass for mirrorhttps. 
whiteAddr.txt :  IP list which need to bypass for mirrorhttps.

newwhiteItem.txt :add new domain when running, mirrorhttps checks it every 2 minitues,and delete this file when add complete.


sslproxy/conf/config.ini:

root_cert_file,root_key_file:  Your CA root, You can make it via mkCert.exe
		in sslproxy/cert direcrotry.
inside_mirror_iface=<ifname>, such as ens33 ,eth0 etc,
inside_mirror_mac=<mac>, mirror packet to the device
outside_mirror_iface=<ifname>,  such as ens33 ,eth0 etc,
outside_mirror_mac=<mac>, mirror packet to the device



author: robertjerry0529@gmail.com
License: Apache license 3.0


