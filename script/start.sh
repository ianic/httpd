#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)

# start httpd listening on 8080 http and 8443 https
zig build #-Doptimize=ReleaseFast
zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec &
pid=$!

# # start nginx listening on 8081 http and 8444 https
# mkdir -p tmp
# nginx -p "$(pwd)" -c script/nginx.conf -g 'daemon off;' &

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
clean_exit
