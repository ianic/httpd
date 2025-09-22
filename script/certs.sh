#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)
cd site
host=$(hostname)

if [ -d "ca" ]; then
    echo site/ca aready exists
    exit 1
fi

alt_names() {
    file_name=$1

    echo "DNS.1 = localhost" >>"$file_name"
    echo "DNS.2 = $(hostname)" >>"$file_name"
    echo "DNS.3 = www.$(hostname)" >>"$file_name"
    echo "IP.1 = 127.0.0.1" >>"$file_name"
    idx=1
    for ip in $(hostname -i); do
        ((idx += 1))
        echo IP."$idx" = "$ip" >>"$file_name"
    done
}

# Create ca and site certificates.
# ca        - certificate authority
# "cert_ec  - eliptic curve certificate
# "cert_rsa - site rsa certificate
mkdir -p ca
mkdir -p cert_ec
mkdir -p cert_rsa

# certificate authority
cd ca
# generate ca private key
# openssl genrsa -out key.pem 2048
openssl ecparam -name prime256v1 -genkey -noout -out key.pem

# self signed ca certificate
openssl req -x509 -new -nodes -key key.pem -sha256 -days 3650 -out cert.pem \
    -subj "/C=US/ST=State/L=Locality/O=MyOrg/CN=MyRootCA"

cd ..
# certificate signing request configuration
csr_conf="csr.conf"
cat <<EOF >"$csr_conf"
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
CN = $host

[req_ext]
subjectAltName = @alt_names

[alt_names]
EOF
alt_names "$csr_conf"

# certificate external configuration
cert_conf="cert.conf"
cat <<EOF >"$cert_conf"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
EOF
alt_names "$cert_conf"

# EC
cd cert_ec
# private key
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
# certificate
openssl req -new -key key.pem -out cert_req -config ../"$csr_conf"
openssl x509 -req -in cert_req -CA ../ca/cert.pem -CAkey ../ca/key.pem -CAcreateserial \
    -out cert.pem -days 825 -sha256 -extfile ../"$cert_conf"

# RSA
cd ../cert_rsa
# private key
openssl genrsa -out key.pem 2048
# certificate
openssl req -new -key key.pem -out cert_req -config ../"$csr_conf"
openssl x509 -req -in cert_req -CA ../ca/cert.pem -CAkey ../ca/key.pem -CAcreateserial \
    -out cert.pem -days 825 -sha256 -extfile ../"$cert_conf"
cd ..
