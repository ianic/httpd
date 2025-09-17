#!/bin/bash -e
set -e
cd $(git rev-parse --show-toplevel)

zig build -Dtarget=x86_64-linux -Doptimize=ReleaseFast

valgrind --tool=callgrind zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec &
pid=$!

script/targets.sh http 8080
oha -z 10s --no-tui --urls-from-file site/targets-oha -c 100 -w --cacert site/ca/cert.pem | grep Requests

kill -USR1 $pid
sleep 0.2
kill $pid
wait $pid
