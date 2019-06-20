package certutil_test

import (
	"github.com/iikira/certbot-go/certutil"
	"testing"
)

func TestParseEC(t *testing.T) {
	priv, err := certutil.ParseEC([]byte(`-----BEGIN EC PRIVATE KEY-----
	MHcCAQEEIACBW/uPjNcnPJZE8DAKiv3qMgfTm7UXRFCKBWSIY3LroAoGCCqGSM49
	AwEHoUQDQgAEMzba3XZkWc/DcSPrQ35cXKDZ4E+cP6iCeEv546TKuvjnCelnxyZC
	16m5OPOsTeZ+fSHXA+dzYyXgpGdujH9bUg==
-----END EC PRIVATE KEY-----`))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s\n", priv)
}
