#!/bin/bash

# supported ciphers
curl https://localhost:8443/pero.txt -i --cacert ~/Code/tls.zig/example/cert/minica.pem --tls13-ciphers TLS_CHACHA20_POLY1305_SHA256
curl https://localhost:8443/pero.txt -i --cacert ~/Code/tls.zig/example/cert/minica.pem --tls13-ciphers TLS_AES_256_GCM_SHA384
curl https://localhost:8443/pero.txt -i --cacert ~/Code/tls.zig/example/cert/minica.pem --tls13-ciphers TLS_AES_128_GCM_SHA256

# fails
curl https://localhost:8443/pero.tx -i --cacert ~/Code/tls.zig/example/cert/minica.pem --tlsv1.2 --tls-max 1.2
curl https://localhost:8443/pero.tx -i --cacert ~/Code/tls.zig/example/cert/minica.pem --tls13-ciphers TLS_AES_128_CCM_SHA256

exit 0

export SSLKEYLOGFILE=/tmp/ssl_key_log

# using curl build with mbedtls
# ./configure --with-mbedtls
while ~/Code/curl/curl/src/curl https://localhost:8443/pero.txt -i --cacert ~/Code/tls.zig/example/cert/minica.pem --tlsv1.3; do true; done
