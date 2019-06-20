package certcfg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/iikira/certbot-go/certutil"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	AccountPrivKeyType = "EC PRIVATE KEY"
	KeyAccountPrivKey  = "AccountPrivKey"
)

func newAccountPrivKey() (*ecdsa.PrivateKey, error) {
	priv := certutil.NewEcdsaSinger()

	b, err := privKeyToPemBlock(priv)
	if err != nil {
		panic(err)
	}

	p := pem.EncodeToMemory(b)

	err = Put(KeyAccountPrivKey, p)
	if err != nil {
		return nil, err
	}
	return priv, err
}

func GetAccountPrivKey() (crypto.Signer, error) {
	v, err := Get(KeyAccountPrivKey)
	if err != nil {
		if err != leveldb.ErrNotFound {
			return nil, err
		}

		return newAccountPrivKey()
	}

	b, r := pem.Decode(v)
	if len(r) != 0 {
		return newAccountPrivKey()
	}

	priv, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, err
}
