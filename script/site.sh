#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)

mkdir -p site
cd site

if [ ! -d "ziglang.org" ]; then
    git clone git@github.com:ianic/ziglang.org.git
fi

# update
# cd ziglang.org
# git pull
# cd ..

# some other sites
# git clone --branch gh-pages --single-branch --depth 1 git@github.com:twbs/bootstrap.git
# git clone --branch gh-pages --single-branch --depth 1 git@github.com:jekyll/jekyll.git

rm root && true
ln -s ziglang.org root

# Create ca and certificates.
if [ ! -d "ca" ]; then
    ../script/certs.sh
fi

(lsmod | grep tls >>/dev/null) || (echo "enable ktls" && sudo modprobe tls)

cd ..
zig build
echo -e "\nBrowse http://localhost:8080 or https://localhost:8443"
zig-out/bin/httpd --root=./site/root --cert=./site/cert_ec/
