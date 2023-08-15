package services

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"sslproxy/conf"
)

// mitmProxy is a type implementing http.Handler that serves as a MITM proxy
// for CONNECT tunnels. Create new instances of mitmProxy using createMitmProxy.
type mitmProxy struct {
	caCert *x509.Certificate
	caKey  any
}

var rootCA *mitmProxy

func cert_init() bool {

	rootCA = createMitmProxy(conf.Root_cert_file, conf.Root_key_file)

	return rootCA != nil
}

/*desc:
检查改证书是否存在，路径domain 前2个字符作为目录，查找该目录下证书文件名

*/
func cert_check_exists(domain string) (bool, string, string, string) {
	var par string
	var cert string
	//var key string
	if strings.Count(domain, ".") >= 2 {
		pos := strings.Index(domain, ".")
		par = domain[pos+1:]
		if len(par) > 2 {
			par = par[0:2]
		}
	} else if len(domain) >= 2 {
		par = domain[0:2]
	} else {
		par = domain
	}

	cert = par + "/" + domain + "_cert.pem"
	key := par + "/" + domain + "_key.pem"
	if _, err := os.Stat(cert); err != nil {
		if os.IsNotExist(err) {
			return false, cert, key, par
		} else {
			return false, cert, key, par
		}
	}

	return true, cert, key, par
}

// createCert creates a new certificate/private key pair for the given domains,
// signed by the parent/parentKey certificate. hoursValid is the duration of
// the new certificate's validity.
func createCert(dnsNames []string, parent *x509.Certificate, parentKey crypto.PrivateKey, hoursValid int) (cert []byte, priv []byte) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Wanxin Https Proxy"},
		},
		DNSNames:  dnsNames,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(hoursValid) * time.Hour * 24),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, parentKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		log.Fatal("failed to encode certificate to PEM")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemCert == nil {
		log.Fatal("failed to encode key to PEM")
	}

	return pemCert, pemKey
}

// loadX509KeyPair loads a certificate/key pair from files, and unmarshals them
// into data structures from the x509 package. Note that private key types in Go
// don't have a shared named interface and use `any` (for backwards
// compatibility reasons).
func loadX509KeyPair(certFile, keyFile string) (cert *x509.Certificate, key any, err error) {
	cf, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}

	kf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(cf)
	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(kf)
	key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// createMitmProxy creates a new MITM proxy. It should be passed the filenames
// for the certificate and private key of a certificate authority trusted by the
// client's machine.
func createMitmProxy(caCertFile, caKeyFile string) *mitmProxy {
	caCert, caKey, err := loadX509KeyPair(caCertFile, caKeyFile)
	if err != nil {
		log.Fatal("Error loading CA certificate/key:", err)
		return nil
	}
	log.Printf("loaded CA certificate and key; IsCA=%v\n", caCert.IsCA)

	return &mitmProxy{
		caCert: caCert,
		caKey:  caKey,
	}
}
func cert_mkdir_parent(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		os.Mkdir(path, 0755)
	} else if info.IsDir() {
		return nil
	} else {
		os.Mkdir(path, 0755)
	}
	return nil
}

func cert_write_file(path string, data []byte) error {
	// 创建预存的文件
	out, createErr := os.Create(path)
	if createErr != nil {
		return errors.New("创建本地文件失败！")
	}
	defer out.Close()
	out.Write(data)
	return nil
}
func cert_product_for_domain(domain string, par string, cert string, key string) error {

	cert_mkdir_parent(par)

	// Create a fake TLS certificate for the target host, signed by our CA. The
	// certificate will be valid for 10 days - this number can be changed.
	pemCert, pemKey := createCert([]string{domain}, rootCA.caCert, rootCA.caKey, 3650)

	err := cert_write_file(cert, pemCert)
	if err != nil {
		return err
	}
	err = cert_write_file(key, pemKey)
	if err != nil {
		return err
	}

	return nil
}
