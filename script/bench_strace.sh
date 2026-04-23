#!/bin/bash -e
set -e

ulimit -n 65535

conns=1
secs=1

zig build -Doptimize=ReleaseFast
strace -c zig-out/bin/httpd --root site/root --cert site/cert_ec --fds 65535 &

script/targets.sh http 8080 localhost testing
oha -z "$secs"s --no-tui --urls-from-file site/targets-oha -c $conns -w --cacert site/ca/cert.pem
pkill -USR1 httpd && pkill httpd

exit 0

nginx -p "$(pwd)" -c script/nginx.conf -g 'daemon off;' &
nginx_pid=$!
sleep 0.2

worker_pid=$(ps --ppid $nginx_pid -o pid=)
sudo strace -c -p $worker_pid &

script/targets.sh http 8081 localhost testing
oha -z "$secs"s --no-tui --urls-from-file site/targets-oha -c $conns -w --cacert site/ca/cert.pem
kill $worker_pid
kill $nginx_pid
sleep 0.2
