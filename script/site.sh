#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)

mkdir -p site
cd site

if [ ! -d "ziglang.org" ]; then
    git clone git@github.com:ianic/ziglang.org.git
fi
cd ziglang.org
git pull
cd ..

# some other sites
# git clone --branch gh-pages --single-branch --depth 1 git@github.com:twbs/bootstrap.git
# git clone --branch gh-pages --single-branch --depth 1 git@github.com:jekyll/jekyll.git

rm root && true
ln -s ziglang.org root

# Create ca and certificates.
if [ ! -d "ca" ]; then
    ../script/certs.sh
fi

cd ..
echo "start server; http on port 8080, https on port 8443"
zig build
zig-out/bin/httpd --root=./site/root --cert=./site/cert_ec/

exit 0

# list site files by size
cd site/root && find . -type f -exec ls -lSh {} + && cd -
