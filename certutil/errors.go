package certutil

import (
	"errors"
)

var (
	ErrPemParse        = errors.New("pem parse error")
	ErrLookupTXTRecord = errors.New("lookup txt record error")
	ErrNotSetDomain    = errors.New("domain not set")
	ErrUnexpectedDer   = errors.New("unexpected der")
	ErrParseCert       = errors.New("cert parse error")
)
