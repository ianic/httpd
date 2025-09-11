#!/bin/bash -e
set -e

if ! command -v vegeta >/dev/null 2>&1; then
    echo "vegeta not found in PATH"
    exit 1
fi

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

# start nginx listening on 8081 http and 8444 https
mkdir -p tmp
nginx -p "$cwd" -c nginx.conf -g 'daemon off;' &
nginx_pid=$!

# start httpz listening on 8080 http and 8443 https
zig build -Doptimize=ReleaseFast
zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec &
pid=$!

workers=128
keepalive=false

# number of files in static site
cd site/www.ziglang.org/zig-out
echo files count: "$(find . -type f | wc -l)"
cd - >>/dev/null

echo
echo http
targets http 8080
vegeta attack -targets=site/targets -duration=10s -rate=0 -max-workers=$workers -keepalive=$keepalive | vegeta report
kill -USR1 $pid
sleep 0.1

echo
echo http nginx
targets http 8081
vegeta attack -targets=site/targets -duration=10s -rate=0 -max-workers=$workers -keepalive=$keepalive | vegeta report

echo
echo https
targets https 8443
vegeta attack -targets=site/targets -duration=10s -rate=0 -max-workers=$workers -keepalive=$keepalive -session-tickets=false -root-certs site/ca/cert.pem | vegeta report
kill -USR1 $pid
sleep 0.1

echo
echo https nginx
targets https 8444
vegeta attack -targets=site/targets -duration=10s -rate=0 -max-workers=$workers -keepalive=$keepalive -session-tickets=false -root-certs site/ca/cert.pem | vegeta report

kill $nginx_pid
kill $pid
# killall nginx httpd
