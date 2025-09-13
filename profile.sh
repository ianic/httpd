#!/bin/bash -e
set -e

cwd="$(pwd)"

# create vegeta targets file with all files from the site
targets() {
    protocol=$1
    port=$2
    cd site/www.ziglang.org/zig-out
    # Skip huge mp4 file because it dominates in benchmark
    # $ find . -type f -exec ls -lS {} + | head
    find . -type f ! -path "*/facebook_bot.mp4" -exec echo -e "GET $protocol://localhost:$port/{}\n" \; >"$cwd/site/targets"
    cd "$cwd"
}

zig build -Dtarget=x86_64-linux -Doptimize=ReleaseFast

valgrind --tool=callgrind zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec &
pid=$!

workers=128
keepalive=true

echo
echo https
targets https 8443
vegeta attack -targets=site/targets -duration=10s -rate=0 -max-workers=$workers -keepalive=$keepalive -session-tickets=false -root-certs site/ca/cert.pem | vegeta report

kill $pid
