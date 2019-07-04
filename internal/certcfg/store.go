package certcfg

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func privKeyToPemBlock(priv *ecdsa.PrivateKey) (*pem.Block, error) {
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	return &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}, nil
}

// StoreECPrivateKey 保存EC私钥到 outPrivKeyPath
func StoreECPrivateKey(outPrivKeyPath string, priv *ecdsa.PrivateKey) error {
	b, err := privKeyToPemBlock(priv)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(outPrivKeyPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	return pem.Encode(f, b)
}

// StoreCSR 保存 CSR 到 outCsrPath
func StoreCSR(outCsrPath string, csr []byte) error {
	f, err := os.OpenFile(outCsrPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
}
