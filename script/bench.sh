#!/bin/bash -e
set -e
cd $(git rev-parse --show-toplevel)

results=()

oha-tests() {
    rs=()

    oha -z 2s --no-tui --urls-from-file site/targets-oha -c 1 -w --cacert site/ca/cert.pem --disable-keepalive > tmp/oha-out
    r=$(grep Requests tmp/oha-out | awk '{print $NF}')
    rs+=($r)
    echo 1 connection disable-keepalive $r

    oha -z 2s --no-tui --urls-from-file site/targets-oha -c 1 -w --cacert site/ca/cert.pem > tmp/oha-out
    r=$(grep Requests tmp/oha-out | awk '{print $NF}')
    rs+=($r)
    echo 1 connection $r

    oha -z 5s --no-tui --urls-from-file site/targets-oha -c 100 -w --cacert site/ca/cert.pem > tmp/oha-out
    r=$(grep Requests tmp/oha-out | awk '{print $NF}')
    rs+=($r)
    echo 100 connections $r

    oha -z 5s --no-tui --urls-from-file site/targets-oha -c 500 -w --cacert site/ca/cert.pem  > tmp/oha-out
    r=$(grep Requests tmp/oha-out | awk '{print $NF}')
    rs+=($r)
    echo 500 connections $r

    results+=( "${rs[@]}" )
    results+=( "" )
}

vegeta-tests() {
    echo vegeta 1 connection disable-keepalive
    vegeta attack -targets=site/targets -duration=2s -rate=0 -max-workers=1 -keepalive=false -root-certs site/ca/cert.pem | vegeta report | grep Requests
    echo vegeta 1 connection
    vegeta attack -targets=site/targets -duration=2s -rate=0 -max-workers=1 -root-certs site/ca/cert.pem | vegeta report | grep Requests
    echo vegeta 100 connections
    vegeta attack -targets=site/targets -duration=5s -rate=0 -max-workers=100 -root-certs site/ca/cert.pem | vegeta report | grep Requests
    echo vegeta 500 connections
    vegeta attack -targets=site/targets -duration=5s -rate=0 -max-workers=500 -root-certs site/ca/cert.pem | vegeta report | grep Requests
}

# start httpd listening on 8080 http and 8443 https
zig build -Doptimize=ReleaseFast
zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec &
pid=$!

# start nginx listening on 8081 http and 8444 https
mkdir -p tmp
nginx -p "$(pwd)" -c script/nginx.conf -g 'daemon off;' &
nginx_pid=$!
sleep 0.2

# number of files in static site
cd site/www.ziglang.org/zig-out
echo site files count: "$(find . -type f | wc -l)"
cd - >>/dev/null

echo -e "\nhttp"
script/targets.sh http 8080
oha-tests

echo -e "\nhttp nginx"
script/targets.sh http 8081
oha-tests

echo -e "\nhttps"
script/targets.sh https 8443
oha-tests

echo -e "\nhttps nginx"
script/targets.sh https 8444
oha-tests

echo
for r in "${results[@]}"; do
    if [ -z "$r" ]; then
        printf "\n"
    else
        printf "%12s" $r
    fi
done

kill $(jobs -p)
kill $nginx_pid
kill $pid

exit 0
# killall nginx httpd

# list files in folder sorted by size
# $ find . -type f -exec ls -lS {} + | head

# see what Nginx id doing
worker=$(pgrep nginx | tail -n1)
sudo strace -p $worker

# something like:
, [{events=EPOLLIN, data=0x7ff8935fc108}], 512, -1) = 1
accept4(7, {sa_family=AF_INET, sin_port=htons(52678), sin_addr=inet_addr("127.0.0.1")}, [112 => 16], SOCK_NONBLOCK) = 8
epoll_ctl(10, EPOLL_CTL_ADD, 8, {events=EPOLLIN|EPOLLRDHUP|EPOLLET, data=0x7ff8935fc2f8}) = 0
epoll_wait(10, [{events=EPOLLIN, data=0x7ff8935fc2f8}], 512, 60000) = 1
recvfrom(8, "GET /index.html HTTP/1.1\r\nHost: "..., 1024, 0, NULL, NULL) = 88
newfstatat(AT_FDCWD, "/home/ianic/Code/httpz/site/www.ziglang.org/zig-out/index.html", {st_mode=S_IFREG|0644, st_size=20076, ...}, 0) = 0
openat(AT_FDCWD, "/home/ianic/Code/httpz/site/www.ziglang.org/zig-out/index.html", O_RDONLY|O_NONBLOCK) = 13
fstat(13, {st_mode=S_IFREG|0644, st_size=20076, ...}) = 0
writev(8, [{iov_base="HTTP/1.1 200 OK\r\nServer: nginx/1"..., iov_len=241}], 1) = 241
sendfile(8, 13, [0] => [20076], 20076)  = 20076
write(4, "127.0.0.1 - - [13/Sep/2025:23:39"..., 98) = 98
close(13)                               = 0
setsockopt(8, SOL_TCP, TCP_NODELAY, [1], 4) = 0
epoll_wait(10, [{events=EPOLLIN|EPOLLRDHUP, data=0x7ff8935fc2f8}], 512, 75000) = 1
recvfrom(8, "", 1024, 0, NULL, NULL)    = 0
close(8)
