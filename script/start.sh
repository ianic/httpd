#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)

zig build -Doptimize=ReleaseFast

ulimit -n 65535                                                                                                     # rise open files limit
zig-out/bin/httpd compress --root site/root --cache site/cache                                                      # precompress files
zig-out/bin/httpd --root site/root --cache site/cache --cert site/cert_ec --fds 65535 --buf-count 16 --sqes 32768 & # start server http: 8080 https: 8443
pid=$!

# start nginx listening on http: 8081 https: 8444
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
