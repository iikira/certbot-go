# certbot-go
Automatically obtain certs from Let's Encrypt.

Only support dns-01 challenge.

Only support Cloudflare's API v4 to deploy TXT record.

# Usage
```
<?php
passthru("certbot-go");
?>
```

## Using Cloudflare's API
```
certbot-go -mod_cf example.com
```
Must set environments CF_API_KEY (for Cloudflare's API key) and CF_API_EMAIL.

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