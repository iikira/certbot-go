package certutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
)

// ParsePem 解析pem
func ParsePem(pemData []byte) (*pem.Block, error) {
	p, r := pem.Decode(pemData)
	if len(r) != 0 {
		return nil, ErrPemParse
	}
	return p, nil
}

// ParseEC 解析 EC private key
func ParseEC(pemData []byte) (*ecdsa.PrivateKey, error) {
	b, err := ParsePem(pemData)
	if err != nil {
		return nil, err
	}

	k, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// CreateCertificateRequest 创建csr
func CreateCertificateRequest(template *x509.CertificateRequest, priv interface{}) (csr []byte, err error) {
	csr, err = x509.CreateCertificateRequest(rand.Reader, template, priv)
	return
}

// CreateCertificateRequestByDomain 通过域名创建csr
func CreateCertificateRequestByDomain(domains []string, priv interface{}) (csr []byte, err error) {
	if len(domains) == 0 {
		return nil, ErrNotSetDomain
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domains[0],
		},
		DNSNames: domains[1:],
	}
	return CreateCertificateRequest(template, priv)
}

func NewEcdsaSinger() *ecdsa.PrivateKey {
	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}

	return akey
}

func ReadECPrivateKey(privKeyPath string) (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}
	return ParseEC(data)
}

func CertificatesEncodeToPem(certificates []*x509.Certificate) (cert, caBundle, fullChain []byte, err error) {
	if len(certificates) == 0 {
		err = ErrUnexpectedDer
		return
	}

	b := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificates[0].Raw,
	}
	buf := bytes.NewBuffer(nil)
	err = pem.Encode(buf, &b)
	if err != nil {
		return
	}

	cert = buf.Bytes()

	buf = bytes.NewBuffer(nil) // reset
	for i := 1; i < len(certificates); i++ {
		b.Bytes = certificates[i].Raw
		err = pem.Encode(buf, &b)
		if err != nil {
			return
		}
	}

	caBundle = buf.Bytes()
	fullChain = append(cert, caBundle...)
	return
}
