#!/bin/bash -e
set -e

ulimit -n 65535

conns=100
secs=2

nginx_strace=0
httpd_strace=1
httpd_valgrind=0
httpd_fg=0

if [ $httpd_fg -eq 1 ]; then
    zig build -Doptimize=ReleaseFast
    sudo samply record zig-out/bin/httpd --root site/root --cert site/cert_ec --fds 65535 &
    script/targets.sh http 8080 localhost testing
    oha -z "$secs"s --no-tui --urls-from-file site/targets-oha -c $conns -w --cacert site/ca/cert.pem
    sudo pkill -USR1 httpd && sudo pkill httpd
fi

if [ $httpd_valgrind -eq 1 ]; then
    zig build -Doptimize=ReleaseSafe
    valgrind --tool=callgrind --dump-instr=yes --collect-jumps=yes zig-out/bin/httpd --root site/root --cert site/cert_ec --fds 65535 &
    script/targets.sh http 8080 localhost testing
    oha -z "$secs"s --no-tui --urls-from-file site/targets-oha -c $conns -w --cacert site/ca/cert.pem
    #pkill -USR1 httpd && pkill httpd

    pkill -f 'zig-out/bin/httpd'
fi

if [ $httpd_strace -eq 1 ]; then
    zig build -Doptimize=ReleaseFast
    strace -c zig-out/bin/httpd --root site/root --cert site/cert_ec --fds 65535 &
    script/targets.sh http 8080 localhost testing
    oha -z "$secs"s --no-tui --urls-from-file site/targets-oha -c $conns -w --cacert site/ca/cert.pem
    pkill -USR1 httpd && pkill httpd
fi

if [ $nginx_strace -eq 1 ]; then

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
fi
