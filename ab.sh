#!/bin/bash -e

targets() {
    protocol=$1
    port=$2
    cd ~/Code/www.ziglang.org/zig-out
    find . -type f -exec echo -e "GET $protocol://localhost:$port/{}\n" \; >~/Code/httpz/targets
    cd - >>/dev/null
}

cd ~/Code/www.ziglang.org/zig-out
echo files count: $(find . -type f | wc -l)
cd - >>/dev/null

echo https httpz
targets https 8443
vegeta attack -targets=targets -duration=10s -rate=0 -max-workers=1024 | vegeta report

echo https nginx
targets https 8444
vegeta attack -targets=targets -duration=10s -rate=0 -max-workers=1024 | vegeta report

echo
echo http httpz
targets http 8080
vegeta attack -targets=targets -duration=10s -rate=0 -max-workers=1024 | vegeta report

echo http nginx
targets http 8081
vegeta attack -targets=targets -duration=10s -rate=0 -max-workers=1024 | vegeta report

exit

# notes
ab -n 100 -c 1 https://localhost:8443/index.html 2>&1 | grep "Requests per second:"
ab -n 100 -c 1 http://localhost:8081/index.html 2>&1 | grep "Requests per second:"

exit

1131479 Sep 5 16:26 ./documentation/0.10.1/index.html
216058 Sep 5 16:26 ./download/index.html
20074 Sep 5 16:26 ./index.html
13880 Sep 5 16:26 ./learn/index.html
298 Sep 5 16:13 ./favicon.png

# find all index.html file sizes
cd ~/Code/www.ziglang.org/zig-out
find . -type f -exec ls -lS {} + | grep index.html
cd -

find . -type f echo "GET http://localhost:8080/" $\{{}:2\} "\n\n" \;
