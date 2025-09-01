#!/bin/bash

# supported ciphers
curl https://localhost:8443/pero_zdero123 -i -k --tls13-ciphers TLS_CHACHA20_POLY1305_SHA256
curl https://localhost:8443/pero_zdero123 -i -k --tls13-ciphers TLS_AES_256_GCM_SHA384
curl https://localhost:8443/pero_zdero123 -i -k --tls13-ciphers TLS_AES_128_GCM_SHA256

# fails
curl https://localhost:8443/pero_zdero123 -i -k --tlsv1.2 --tls-max 1.2
curl https://localhost:8443/pero_zdero123 -i -k --tls13-ciphers TLS_AES_128_CCM_SHA256
