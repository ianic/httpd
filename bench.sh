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

    # # all files
    # find . -type f -exec echo -e "GET $protocol://localhost:$port/{}\n" \; >"$cwd/site/targets"

    # Skip huge mp4 file because it dominates in benchmark
    find . -type f ! -path "*/facebook_bot.mp4" -exec echo -e "GET $protocol://localhost:$port/{}\n" \; >"$cwd/site/targets"
    find . -type f ! -path "*/facebook_bot.mp4" -exec echo -e "$protocol://localhost:$port/{}" \; >"$cwd/site/targets-oha"

    # # only x largest(head)/smalles(tail) files
    # rm "$cwd/site/targets"
    # find . -type f ! -path "*/facebook_bot.mp4" -exec ls -S {} + | head -n 10 | while IFS= read -r file; do
    #     echo -e "GET $protocol://localhost:$port/$file\n" >>"$cwd/site/targets"
    # done
    cd "$cwd"
}

oha-tests() {
    echo oha 1 connection disable-keepalive
    oha -z 2s  --no-tui  --urls-from-file site/targets-oha -c 1 -w --cacert site/ca/cert.pem --disable-keepalive | grep Requests
    echo oha 1 connection
    oha -z 2s  --no-tui  --urls-from-file site/targets-oha -c 1 -w --cacert site/ca/cert.pem  | grep Requests
    echo oha 100 connections
    oha -z 5s  --no-tui  --urls-from-file site/targets-oha -c 100 -w --cacert site/ca/cert.pem  | grep Requests
    echo oha 500 connections
    oha -z 5s  --no-tui  --urls-from-file site/targets-oha -c 500 -w --cacert site/ca/cert.pem  | grep Requests
}

# start nginx listening on 8081 http and 8444 https
mkdir -p tmp
nginx -p "$cwd" -c nginx.conf -g 'daemon off;' &
nginx_pid=$!

# start httpz listening on 8080 http and 8443 https
zig build -Doptimize=ReleaseFast
zig-out/bin/httpd --root site/www.ziglang.org/zig-out --cert site/localhost_ec &
pid=$!
sleep 0.2

workers=1
keepalive=false

# number of files in static site
cd site/www.ziglang.org/zig-out
echo files count: "$(find . -type f | wc -l)"
cd - >>/dev/null

echo
echo http
targets http 8080
#vegeta attack -targets=site/targets -duration=2s -rate=0 -max-workers=$workers -keepalive=$keepalive | vegeta report
#kill -USR1 $pid && sleep 0.1
oha-tests

echo
echo http nginx
targets http 8081
# vegeta attack -targets=site/targets -duration=10s -rate=0 -max-workers=$workers -keepalive=$keepalive | vegeta report
oha-tests

echo
echo https
targets https 8443
# vegeta attack -targets=site/targets -duration=5s -rate=0 -max-workers=$workers -keepalive=$keepalive -session-tickets=false -root-certs site/ca/cert.pem | vegeta report
oha-tests


echo
echo https nginx
targets https 8444
# vegeta attack -targets=site/targets -duration=5s -rate=0 -max-workers=$workers -keepalive=$keepalive -session-tickets=false -root-certs site/ca/cert.pem | vegeta report
oha-tests


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
