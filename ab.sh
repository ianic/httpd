#!/bin/bash -e

cd ~/Code/www.ziglang.org/zig-out
echo files count: $(find . -type f | wc -l)
echo vegeta httpz
find . -type f -exec echo -e "GET http://localhost:8080/{}\n" \; >~/Code/httpz/targets
cd - >>/dev/null
vegeta attack -targets=targets -duration=10s -rate=0 -max-workers=1024 | vegeta report

echo nginx
cd ~/Code/www.ziglang.org/zig-out
find . -type f -exec echo -e "GET http://localhost:8081/{}\n" \; >~/Code/httpz/targets
cd - >>/dev/null
vegeta attack -targets=targets -duration=10s -rate=0 -max-workers=1024 | vegeta report

exit

ab -n 50000 -c 1 http://localhost:8080/index.html 2>&1 | grep "Requests per second:"
ab -n 50000 -c 1 http://localhost:8081/index.html 2>&1 | grep "Requests per second:"

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
