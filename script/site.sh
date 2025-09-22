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

# Create ca and certificates.
if [ ! -d "ca" ]; then
    ../script/certs.sh
fi

cd ..
echo "start server; http on port 8080, https on port 8443"
zig build
zig-out/bin/httpd --root=./site/www.ziglang.org/zig-out/ --cert=./site/cert_ec/

exit 0

# list site files by size
cd site/www.ziglang.org/zig-out && find . -type f -exec ls -lSh {} + && cd -
