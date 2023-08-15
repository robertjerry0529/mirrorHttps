package services

/*这个功能没有用到了，因为自己伪造的证书，浏览器不认，主动关闭连接了*/
import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

type accessInfo struct {
	LocalIp    string //本地socket Ip
	LocalPort  int    //
	RemoteIp   string //nat 后的请求IP
	RemotePort int    //请求端口
	Domain     string
	Raw_lip    string //原始的本地IP
	Raw_fip    string //原始的请求者IP
}

var maplock sync.RWMutex
var tlsmap map[string](*tls.Config)
var logger = log.New(os.Stderr, "httpsproxy:", log.Llongfile|log.LstdFlags)
var certlock sync.RWMutex

func Https_start() int {

	if !cert_init() {
		return 0
	}
	fmt.Println("Welcone any access proxy..")

	listen, err := net.Listen("tcp", "0.0.0.0:443")
	if err != nil {
		fmt.Println("Listen() failed, err: ", err)
		return 0
	}
	tlsmap = make(map[string]*tls.Config, 512)

	for {
		conn, err := listen.Accept() // 监听客户端的连接请求
		if err != nil {
			fmt.Println("Accept() failed, err: ", err)
			continue
		}
		go process(conn) // 启动一个goroutine来处理客户端的连接请求
	}
}

func process(clientConn net.Conn) {

	//
	var crtfile string
	var keyfile string
	var tlscfg tls.Config
	var tlsConn *tls.Conn

	remote := clientConn.RemoteAddr().String()

	defer clientConn.Close()

	destInfo, err := remote_access_get(remote)
	if err != nil {
		fmt.Printf("find nothing from redis for remote access %s\n", remote)
		return
	}

	log.Printf("domain:%s,localip:%s,localport:%d, remoteip:%s,remoteport:%d",
		destInfo.Domain, destInfo.LocalIp, destInfo.LocalPort, destInfo.RemoteIp, destInfo.RemotePort)
	/*  for test
	var destInfo accessInfo
	destInfo.RemoteIp = "47.242.187.105"
	destInfo.RemotePort = 443
	destInfo.Domain = "www.junzhenggroup.com"
	*/
	//var remote = "some string"
	//check cert if exist
	certlock.RLock()
	exist, crtfile, keyfile, subdir := cert_check_exists(destInfo.Domain)
	certlock.RUnlock()

	if exist {
		//find cert
		fmt.Printf("find cert for remote access %s, try load from map\n", destInfo.Domain)
		maplock.RLock()
		val, ok := tlsmap[destInfo.Domain]
		maplock.RUnlock()
		if ok {
			tlsConn = tls.Server(clientConn, val)
		}
	} else {

		fmt.Printf("Not find cert for remote access %s, subidr:%s,make new one\n", destInfo.Domain, subdir)
		certlock.Lock()
		exist, _, _, _ = cert_check_exists(destInfo.Domain)
		if !exist {
			fmt.Printf("Again Not find cert for remote access %s,make new one\n", destInfo.Domain)
			err := cert_product_for_domain(destInfo.Domain, subdir, crtfile, keyfile)
			if err != nil {
				fmt.Printf("cert_product_for_domain %s failed,error:%s\n", destInfo.Domain, err)
				certlock.Unlock()
				return
			}
			fmt.Printf("make cert file for %s\n", destInfo.Domain)
		}
		certlock.Unlock()
	}

	if tlsConn == nil {
		var index int
		certs := []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		}

		tlscfg.InsecureSkipVerify = true
		tlscfg.CipherSuites = make([]uint16, len(certs))
		for index = 0; index < len(certs); index++ {
			tlscfg.CipherSuites[index] = certs[index]
		}

		//

		tlsCert, err := tls.LoadX509KeyPair(crtfile, keyfile)
		if err != nil {
			log.Printf("tls.LoadX509KeyPair failed, %s", err)
			return
		}
		tslarr := make([]tls.Certificate, 1)
		tslarr[0] = tlsCert
		tlscfg.Certificates = tslarr

		tlscfg.MinVersion = tls.VersionTLS10
		tlscfg.MaxVersion = tls.VersionTLS13
		tlscfg.InsecureSkipVerify = true
		maplock.Lock()
		tlsmap[destInfo.Domain] = &tlscfg
		maplock.Unlock()
		tlsConn = tls.Server(clientConn, &tlscfg)
	}

	if tlsConn == nil {
		log.Printf("prepair tlsServer failed")
		return
	}
	/*for debug just use domain , resolve get ip for ip rewrite*/
	destAddr := fmt.Sprintf("%s:%d", destInfo.Domain, destInfo.LocalPort)
	//destAddr := fmt.Sprintf("%s:%d", destInfo.LocalIp, destInfo.LocalPort)

	outConn, err := tls.Dial("tcp", destAddr, &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,
		// InsecureSkipVerify means to accept whatever cert you get from the server
		// Subject to man-in-the-middle attacks. Golang docs say only for testing.
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("out conn to %s failed, %s", destAddr, err)
		return
	}

	//for {
	// Read an HTTP request from the client; the request is sent over TLS that
	// connReader is configured to serve. The read will run a TLS handshake in
	// the first invocation (we could also call tlsConn.Handshake explicitly
	// before the loop, but this isn't necessary).
	// Note that while the client believes it's talking across an encrypted
	// channel with the target, the proxy gets these requests in "plain text"
	// because of the MITM setup.

	go tlsCopy(tlsConn, outConn, 0, destInfo.Raw_fip, uint16(destInfo.RemotePort), destInfo.Raw_lip, uint16(destInfo.LocalPort))
	tlsCopy(outConn, tlsConn, 1, destInfo.Raw_fip, uint16(destInfo.RemotePort), destInfo.Raw_lip, uint16(destInfo.LocalPort))
	//}
	log.Printf("https proxy session close")
}

func tlsCopy(sconn *tls.Conn, oconn *tls.Conn, dir int, sip string, sport uint16, dip string, dport uint16) {
	buf := make([]byte, 4096)
	defer sconn.Close()
	for {
		n, err := sconn.Read(buf)
		if err != nil && err == io.EOF {
			log.Printf("tls copy exit with io.EOF")
			return
		} else if err != nil {
			log.Printf("tls copy end with err:%v", err)
			break
		}
		if n > 0 {
			//fmt.Printf(string(buf))
			oconn.Write(buf[0:n])
		}
		if dir == 0 {
			mirror_pkt_send(buf[0:n], len(buf[0:n]), dir, sip, sport, dip, 80)
		} else {
			mirror_pkt_send(buf[0:n], len(buf[0:n]), dir, dip, 80, sip, sport)
		}
	}

	if dir == 0 {
		mirror_connection_end(dir, sip, sport, dip, dport)
	} else {
		mirror_connection_end(dir, dip, dport, sip, sport)
	}
}
