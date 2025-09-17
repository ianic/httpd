#!/bin/bash
set -e

# supported ciphers
curl https://localhost:8443/favicon.svg -v --cacert site/ca/cert.pem --tls13-ciphers TLS_CHACHA20_POLY1305_SHA256
curl https://localhost:8443/favicon.svg -v --cacert site/ca/cert.pem --tls13-ciphers TLS_AES_256_GCM_SHA384
curl https://localhost:8443/favicon.svg -v --cacert site/ca/cert.pem --tls13-ciphers TLS_AES_128_GCM_SHA256

exit 0

export SSLKEYLOGFILE=/tmp/ssl_key_log

# using curl build with mbedtls
# ./configure --with-mbedtls
while curl https://localhost:8443/favicon.svg -i --cacert site/ca/cert.pem --tlsv1.3; do true; done
