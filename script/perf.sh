#!/bin/bash
set -e

cd "$(git rev-parse --show-toplevel)"

zig build -Doptimize=ReleaseFast

# if perf is not working run this:
# sudo sysctl kernel.perf_event_paranoid=-1
# find /sys/kernel/tracing/events/io_uring -type f -exec sudo chmod a+r {} \;

{
        perf stat \
                -e io_uring:io_uring_complete \
                -e io_uring:io_uring_cqe_overflow \
                -e io_uring:io_uring_cqring_wait \
                -e io_uring:io_uring_create \
                -e io_uring:io_uring_defer \
                -e io_uring:io_uring_fail_link \
                -e io_uring:io_uring_file_get \
                -e io_uring:io_uring_link \
                -e io_uring:io_uring_local_work_run \
                -e io_uring:io_uring_poll_arm \
                -e io_uring:io_uring_queue_async_work \
                -e io_uring:io_uring_register \
                -e io_uring:io_uring_req_failed \
                -e io_uring:io_uring_short_write \
                -e io_uring:io_uring_submit_req \
                -e io_uring:io_uring_task_add \
                -e io_uring:io_uring_task_work_run \
                -- zig-out/bin/httpd --root site/root --cache site/cache --cert site/cert_ec
} &
perf_pid=$!
sleep 0.2
pid=$(pidof httpd)

script/targets.sh http 8080
oha -z 2s --no-tui --urls-from-file site/targets-oha -c 100 -w --cacert site/ca/cert.pem | grep Requests #--disable-compression #| grep Requests
# oha -z 2s --no-tui --urls-from-file site/targets-oha -c 1 -w --cacert site/ca/cert.pem --disable-keepalive | grep Requests
script/targets.sh https 8443
#oha -z 2s --no-tui --urls-from-file site/targets-oha -c 400 -w --cacert site/ca/cert.pem | grep Requests
# oha -z 2s --no-tui --urls-from-file site/targets-oha -c 1 -w --cacert site/ca/cert.pem --disable-keepalive | grep Requests

# show number of threads
# ps -o thcount $pid

# httpd metric
kill -USR1 "$pid"
sleep 0.5

kill "$pid"
wait $perf_pid

#sudo bpftrace -e "tracepoint:syscalls:sys_enter_io_uring_enter {@c[tid] = count();}"
