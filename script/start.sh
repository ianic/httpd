#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)

# start httpd listening on 8080 http and 8443 https with limits raised
ulimit -n 65535
zig build -Doptimize=ReleaseFast
zig-out/bin/httpd compress --root site/root
zig-out/bin/httpd --root site/root --cert site/cert_ec --fds 65535 --buf-count 16 --sqes 32768 &
pid=$!

# start nginx listening on 8081 http and 8444 https
mkdir -p tmp
nginx -p "$(pwd)" -c script/nginx.conf -g 'daemon off;' &
nginx_pid=$!

trap ctrl_c_handler INT

function clean_exit() {
    echo "Waiting for httpd to stop..."
    wait $pid
    exit 0
}

function ctrl_c_handler() {
    echo "ctrl-c"
    clean_exit
}

read -n 1 -s -r -p "Press any key to stop httpd..."
echo
kill $pid
kill $nginx_pid
clean_exit

# stress test with
ulimit -n 65535
script/targets.sh http 8080 && oha -z 60s --urls-from-file site/targets-oha -c 10000 -w --cacert site/ca/cert.pem
pkill --signal USR1 httpd
