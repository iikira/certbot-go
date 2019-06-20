package certclient

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"github.com/eggsampler/acme/v2"
)

type (
	CertClient struct {
		Client  *acme.Client
		Domains []string
		CSR     []byte

		ctx     context.Context
		account *acme.Account
		order   *acme.Order
	}

	ChangeDNSFunc func(domain, dnsValue string) error
)

// NewCertClient 初始化 CertClient, csr 为解析后的pem
func NewCertClient(domains []string, csr []byte) (*CertClient, error) {
	client, err := acme.NewClient(acme.LetsEncryptProduction)
	if err != nil {
		return nil, err
	}

	c := &CertClient{
		Client:  &client,
		Domains: domains,
		CSR:     csr,
	}
	return c, nil
}

func (c *CertClient) lazyInit() {
	if c.ctx == nil {
		c.ctx = context.Background()
	}
}

func (c *CertClient) check() error {
	c.lazyInit()
	if c.Client == nil {
		return ErrNotSetClient
	}
	if len(c.Domains) == 0 {
		return ErrNotSetDomain
	}

	return nil
}

func (c *CertClient) PrepareAccount(privateKey crypto.Signer) (err error) {
	c.lazyInit()

	// Register
	account, err := c.Client.NewAccount(privateKey, true, true)
	if err != nil {
		pb, ok := err.(acme.Problem)
		if !ok {
			return
		}

		// 帐户不存在才继续注册新帐户
		if pb.Type != "urn:ietf:params:acme:error:accountDoesNotExist" {
			return
		}

		// 全新注册
		account, err = c.Client.NewAccount(privateKey, false, true)
		if err != nil {
			return
		}
	}

	c.account = &account
	return
}

func (c *CertClient) PrepareDNS(cfunc ChangeDNSFunc) (err error) {
	if cfunc == nil {
		return ErrNilArguments
	}

	err = c.check()
	if err != nil {
		return
	}

	if c.account == nil {
		err = ErrNotSetAccount
		return
	}

	order, err := c.Client.NewOrderDomains(*c.account, c.Domains...)
	if err != nil {
		return
	}

	c.order = &order

	// Authorize
	for k, authURL := range order.Authorizations {
		authz, err := c.Client.FetchAuthorization(*c.account, authURL)
		if err != nil {
			return err
		}

		if authz.Status == "valid" {
			// Already authorized
			continue
		}

		// dns-01 challenge
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == acme.ChallengeTypeDNS01 {
				chal = &c
				break
			}
		}

		if chal == nil {
			return ErrUnsupportDNS01
		}

		// change TXT value func
		err = cfunc(c.Domains[k], acme.EncodeDNS01KeyAuthorization(chal.KeyAuthorization))
		if err != nil {
			return err
		}

		// Let CA know we're ready
		_, err = c.Client.UpdateChallenge(*c.account, *chal)
		if err != nil {
			return err
		}
	}

	return
}

// CreateCert 返回pem格式的证书
func (c *CertClient) CreateCert() (cert, caBundle []byte, err error) {
	c.lazyInit()
	if c.order == nil {
		err = ErrNotSetOrder
		return
	}

	order, err := c.Client.FinalizeOrder(*c.account, *c.order, &x509.CertificateRequest{
		Raw: c.CSR,
	})
	if err != nil {
		return
	}

	c.order = &order

	der, err := c.Client.FetchCertificates(*c.account, order.Certificate)
	if err != nil {
		return
	}

	if len(der) < 2 {
		err = ErrUnexpectedDer
		return
	}

	b := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der[0].Raw,
	}

	// 一般情况下
	// der[0] 为cert
	cert = pem.EncodeToMemory(&b)
	if cert == nil {
		err = ErrParseCert
		return
	}

	// der[1] 为ca_bundle
	b.Bytes = der[1].Raw
	caBundle = pem.EncodeToMemory(&b)
	if caBundle == nil {
		err = ErrParseCert
		return
	}

	return
}
