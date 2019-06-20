package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"github.com/iikira/certbot-go/certclient"
	"github.com/iikira/certbot-go/certutil"
	"github.com/iikira/certbot-go/internal/certcfg"
	"github.com/iikira/ippush/syncip"
	"github.com/iikira/ippush/syncrunner"
	"io/ioutil"
	"log"
	"os"
	"time"
)

var (
	domains         []string
	csrPath         string
	privKeyPath     string
	outCertPath     string
	outCaBundlePath string
	outCsrPath      string
	outPrivKeyPath  string
	cfMode          bool
)

func init() {
	flag.StringVar(&csrPath, "csr", "", "path to CSR file")
	flag.StringVar(&privKeyPath, "priv_key", "", "path to private key file")
	flag.StringVar(&outCertPath, "out_cert", "certificate.crt", "path to certificate output")
	flag.StringVar(&outCaBundlePath, "out_ca_bundle", "ca_bundle.crt", "path to ca_bundle output")
	flag.StringVar(&outCsrPath, "out_csr", "csr.pem", "path to csr output if not have own CSR")
	flag.StringVar(&outPrivKeyPath, "out_priv_key", "private.key", "path to private key output if not have own CSR")
	flag.BoolVar(&cfMode, "mod_cf", false, "using Cloudflare's API to deploy TXT record")
	flag.Parse()

	domains = flag.Args()
	if len(domains) == 0 {
		flag.Usage()
		os.Exit(1)
	}
}

func main() {
	var (
		c *certclient.CertClient
	)

	// Prepare csr
	if csrPath == "" {
		var (
			priv *ecdsa.PrivateKey
			err  error
		)

		// 默认随机生成椭圆曲线密钥
		if privKeyPath == "" {
			priv = certutil.NewEcdsaSinger()
		} else {
			// 读取
			priv, err = certutil.ReadPrivateKey(privKeyPath)
			checkErr(err)
		}

		// 创建CSR
		csr, err := certutil.CreateCertificateRequestByDomain(domains, priv)
		checkErr(err)

		// 保存随机生成的 private key
		if privKeyPath == "" {
			err = certcfg.StorePrivateKey(outPrivKeyPath, priv)
			checkErr(err)
			log.Printf("private key file stored: %s\n", outPrivKeyPath)
		}

		// 保存CSR
		err = certcfg.StoreCSR(outCsrPath, csr)
		checkErr(err)
		log.Printf("CSR file stored: %s\n", outCsrPath)

		c, err = certclient.NewCertClient(domains, csr)
		checkErr(err)
	} else {
		// red csr pem
		csrPem, err := ioutil.ReadFile(csrPath)
		checkErr(err)

		csrBlock, err := certutil.ParsePem(csrPem)
		checkErr(err)

		c, err = certclient.NewCertClient(domains, csrBlock.Bytes)
		checkErr(err)
	}

	// get key
	priv, err := certcfg.GetAccountPrivKey()
	checkErr(err)

	// register account
	err = c.PrepareAccount(priv)
	checkErr(err)

	if !cfMode {
		err = c.PrepareDNS(confirm)
		checkErr(err)

	} else {
		r, err := syncrunner.NewRunner()
		checkErr(err)

		s, err := syncip.NewSyncIP(r.APIKey, r.APIEmail)
		checkErr(err)

		err = c.PrepareDNS(func(domain, dnsValue string) error {
			// 自动从域名推断ZoneName
			e := s.SetZone(certutil.GetSubDomain(domain))
			if e != nil {
				return e
			}

			e = s.SetTXTRecord(certutil.GetRecordName(domain), dnsValue)

			// Sleep 30s, 防止dns缓存未刷新
			time.Sleep(30 * time.Second)
			return e
		})
		checkErr(err)
	}

	cert, caBundle, err := c.CreateCert()
	checkErr(err)

	err = ioutil.WriteFile(outCertPath, cert, 0600)
	checkErr(err)

	log.Printf("certificate file stored: %s\n", outCertPath)

	err = ioutil.WriteFile(outCaBundlePath, caBundle, 0600)
	checkErr(err)

	log.Printf("ca_bundle file stored: %s\n", outCaBundlePath)

}

func confirm(domain, dnsValue string) error {
	fmt.Printf("update %s TXT record: %s\n", certutil.GetRecordName(domain), dnsValue)
	var confirm int
	fmt.Printf("Press ENTER to continue: ")
	fmt.Scanf("%d", &confirm)
	return nil
}

func checkErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
