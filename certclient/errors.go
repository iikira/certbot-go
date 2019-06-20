package certclient

import (
	"errors"
)

var (
	ErrNotSetDomain      = errors.New("domain not set")
	ErrNotSetClient      = errors.New("acme client not set")
	ErrNotSetAccount     = errors.New("account not set")
	ErrNotSetOrder       = errors.New("acme order not set")
	ErrAlreadyAuthorized = errors.New("already authorized")
	ErrUnsupportDNS01    = errors.New("unsupport challenge dns-01")
	ErrNilArguments      = errors.New("arguments should not be nil")
	ErrUnexpectedDer     = errors.New("unexpected der")
	ErrParseCert         = errors.New("cert parse error")
)
