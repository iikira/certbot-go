# certbot-go
Automatically obtain certs from Let's Encrypt.

Only support `dns-01` challenge.

Only support Cloudflare's API v4 to deploy TXT record.

Only support `EC PRIVATE KEY`.

# Usage
```
Usage of certbot-go:
  -csr string
    	path to CSR file
  -mod_cf
    	using Cloudflare's API to deploy TXT record
  -out_ca_bundle string
    	path to ca_bundle output (default "ca_bundle.crt")
  -out_cert string
    	path to certificate output (default "certificate.crt")
  -out_csr string
    	path to csr output if not have own CSR (default "csr.pem")
  -out_priv_key string
    	path to private key output if EC PRIVATE KEY has not specified (default "private.key")
  -priv_key string
    	path to private key file
```

## Using Cloudflare's API
```
certbot-go -mod_cf example.com
```
Must set environments `CF_API_KEY` (for Cloudflare's API key) and `CF_API_EMAIL`.

See: https://api.cloudflare.com/

## Manual deploy TXT record, private key would be generated
```
certbot-go example.com
```

## Have own private key
```
certbot-go -priv_key secp256r1.key example.com
```

## Have own CSR
```
certbot-go -csr csr.pem example.com
```