#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)

zig0151=~/.build/zig/zig-x86_64-linux-0.15.1/zig

if [ ! -f $zig0151 ]; then
    echo missing path to zig 0.15.1, needed to build www.ziglang.org
    exit 1
fi

mkdir -p site
cd site

# Get and build Zig site.
# Static site is in www.ziglang.org/zig-out after build.
if [ ! -d "www.ziglang.org" ]; then
    git clone git@github.com:ziglang/www.ziglang.org.git
    cd www.ziglang.org
    $zig0151 build
    cd ..
fi

# Create ca and site certificates.
# ca            - certificate authority
# localhost_ec  - localhost eliptic curve certificate
# localhost_rsa - localhost site rsa certificate
if [ ! -d "ca" ]; then
    mkdir -p ca
    mkdir -p localhost_ec
    mkdir -p localhost_rsa

    # certificate authority
    cd ca
    # generate ca private key
    # openssl genrsa -out key.pem 2048
    openssl ecparam -name prime256v1 -genkey -noout -out key.pem

    # self signed ca certificate
    openssl req -x509 -new -nodes -key key.pem -sha256 -days 3650 -out cert.pem \
        -subj "/C=US/ST=State/L=Locality/O=MyOrg/CN=MyRootCA"

    # EC key
    cd ../localhost_ec

    # localhost certificate request
    cat <<EOF >localhost.csr.conf
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = US
ST = State
L = Locality
O = MyOrg
CN = localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

    cat <<EOF >localhost.cert.conf
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

    # private key
    openssl ecparam -name prime256v1 -genkey -noout -out key.pem
    # certificate
    openssl req -new -key key.pem -out localhost.csr -config localhost.csr.conf
    openssl x509 -req -in localhost.csr -CA ../ca/cert.pem -CAkey ../ca/key.pem -CAcreateserial \
        -out cert.pem -days 825 -sha256 -extfile localhost.cert.conf

    # RSA key
    cd ../localhost_rsa
    openssl genrsa -out key.pem 2048
    openssl req -new -key key.pem -out localhost.csr -config ../localhost_ec/localhost.csr.conf
    openssl x509 -req -in localhost.csr -CA ../ca/cert.pem -CAkey ../ca/key.pem -CAcreateserial \
        -out cert.pem -days 825 -sha256 -extfile ../localhost_ec/localhost.cert.conf
    cd ..
fi

echo start server
cd ..
zig build
zig-out/bin/httpd --root=./site/www.ziglang.org/zig-out/ --cert=./site/localhost_ec/

exit

# Notes

# curl usage:
curl --cacert ./site/ca/cert.pem https://localhost:8443
curl http://localhost:8080

# supported ciphers
curl https://localhost:8443/favicon.svg -v --cacert site/ca/cert.pem --tls13-ciphers TLS_CHACHA20_POLY1305_SHA256
curl https://localhost:8443/favicon.svg -v --cacert site/ca/cert.pem --tls13-ciphers TLS_AES_256_GCM_SHA384
curl https://localhost:8443/favicon.svg -v --cacert site/ca/cert.pem --tls13-ciphers TLS_AES_128_GCM_SHA256

# add ca to the trusted, browser will not complain after that
sudo cp site/ca/cert.pem /etc/ca-certificates/trust-source/anchors/localhost-ca.pem
cd /etc/ca-certificates/trust-source/anchors
sudo trust anchor localhost-ca.pem
sudo update-ca-trust extract

# curl loop
while curl https://localhost:8443/favicon.svg -i --cacert site/ca/cert.pem --tlsv1.3; do true; done

# site files by size
cd site/www.ziglang.org/zig-out && find . -type f -exec ls -lSh {} + && cd -

# enable kernel tls module
# check if module is enabled
lsmod | grep tls
# enable moduel
sudo modprobe tls
# enable permanently
cat /etc/modules-load.d/gnutls.conf
echo tls | sudo tee /etc/modules-load.d/gnutls.conf

zig build -Dtarget=x86_64-linux -Doptimize=ReleaseFast && valgrind --tool=callgrind zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec
zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec
valgrind --tool=callgrind zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec
