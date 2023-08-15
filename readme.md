#MIrrorHttps 说明

传统设备对https的内容进行监控，可采集的信息非常有限；本项目将本地https进行解密，通过https代理，实现内容解析，将明文内容镜像给其他设备，方便其他设备进行内容分析和内容采集。


#部署
MIrrorHttps采用交换机镜像接口，将报文镜像到MirrorHttps中，MirrorHttps通过回注接口，将回应报文返回到网络中，返回的报文被认为是原目标服务器的响应报文，Gateway通过交换机将该报文返回给请求主机，请求主机在IP层面看，会认为这是原目标主机的回复报文，从而建立tcp连接，但是实际是在请求主机与MirrorHttps之间建立通信链接。
MirrorHttps获得该链接后，实现https报文服务，解析客户端请求，并且通过本地客户端代理向真正的目标服务器发起请求，并且将获得的响应内容返回给原始请求客户端。

部署图:![alt 部署图](https://www.coonote.com)

#使用：
git clone  .....

make dpdk
make netmap
make service

配置:
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


