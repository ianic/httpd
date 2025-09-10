# HTTP/HTTPS static file server in Zig with io_uring, kernel TLS

# Known issues

- handling of overshot read when switching to ktsl
test with curl build with wolfssl and buffer size of 4096 with incremental buffer consumption, you will not wait long for having partial tls record in overshot data

- curl (and other clients) with openssl sometimes fail with wrong signature problem [ref](https://github.com/curl/curl/issues/11434), curl with wolfssl (and probably other tls libraries) works fine  
signature is created with code from Zig std library 

- forcibly closing tls connection, not sending close notify tls message


# Notes 

[ktls](https://docs.kernel.org/networking/tls.html)  
[curl and tls libraries](https://everything.curl.dev/build/tls.html)  


$ nginx -c ~/Code/httpz/nginx.conf -g 'daemon off;'
$ ab -n 5000 -c 100  http://localhost:8080/zig-out/bin/httpd

Server Software:
Server Hostname:        localhost
Server Port:            8080

Document Path:          /zig-out/bin/httpd
Document Length:        5702976 bytes

Concurrency Level:      100
Time taken for tests:   5.036 seconds
Complete requests:      5000
Failed requests:        0
Total transferred:      28515395000 bytes
HTML transferred:       28514880000 bytes
Requests per second:    992.82 [#/sec] (mean)
Time per request:       100.723 [ms] (mean)
Time per request:       1.007 [ms] (mean, across all concurrent requests)
Transfer rate:          5529423.19 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.2      0       2
Processing:    50  100  43.0     91     201
Waiting:        0   17  17.5     15      92
Total:         50  100  42.9     91     201

Percentage of the requests served within a certain time (ms)
  50%     91
  66%    118
  75%    140
  80%    147
  90%    162
  95%    174
  98%    179
  99%    185
 100%    201 (longest request)


Server Software:        nginx/1.28.0
Server Hostname:        localhost
Server Port:            8080

Document Path:          /zig-out/bin/httpd
Document Length:        5702976 bytes

Concurrency Level:      100
Time taken for tests:   4.277 seconds
Complete requests:      5000
Failed requests:        0
Total transferred:      28516085000 bytes
HTML transferred:       28514880000 bytes
Requests per second:    1169.02 [#/sec] (mean)
Time per request:       85.542 [ms] (mean)
Time per request:       0.855 [ms] (mean, across all concurrent requests)
Transfer rate:          6510904.90 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.1      0       1
Processing:     1   85   7.8     86      96
Waiting:        0   84   7.9     85      96
Total:          2   85   7.8     86      96

Percentage of the requests served within a certain time (ms)
  50%     86
  66%     87
  75%     88
  80%     88
  90%     90
  95%     91
  98%     93
  99%     94
 100%     96 (longest request)
 
 
Server Software:        nginx/1.28.0
Server Hostname:        localhost
Server Port:            8443
SSL/TLS Protocol:       TLSv1.3,TLS_AES_256_GCM_SHA384,384,256
TLS Server Name:        localhost

Document Path:          /zig-out/bin/httpd
Document Length:        5702976 bytes

Concurrency Level:      100
Time taken for tests:   12.942 seconds
Complete requests:      5000
Failed requests:        0
Total transferred:      28516085000 bytes
HTML transferred:       28514880000 bytes
Requests per second:    386.33 [#/sec] (mean)
Time per request:       258.844 [ms] (mean)
Time per request:       2.588 [ms] (mean, across all concurrent requests)
Transfer rate:          2151702.58 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        1  248  35.3    258     273
Processing:     3    8  22.1      5     214
Waiting:        0    4   8.7      3     113
Total:        105  256  19.6    263     285

Percentage of the requests served within a certain time (ms)
  50%    263
  66%    266
  75%    268
  80%    268
  90%    270
  95%    271
  98%    273
  99%    275
 100%    285 (longest request)
 
 
Server Software:
Server Hostname:        localhost
Server Port:            8443
SSL/TLS Protocol:       TLSv1.3,TLS_AES_256_GCM_SHA384,384,256
Server Temp Key:        X25519 253 bits
TLS Server Name:        localhost

Document Path:          /zig-out/bin/httpd
Document Length:        5702976 bytes

Concurrency Level:      100
Time taken for tests:   21.894 seconds
Complete requests:      5000
Failed requests:        19
   (Connect: 0, Receive: 0, Length: 19, Exceptions: 0)
Total transferred:      28515395000 bytes
HTML transferred:       28514880000 bytes
Requests per second:    228.37 [#/sec] (mean)
Time per request:       437.877 [ms] (mean)
Time per request:       4.379 [ms] (mean, across all concurrent requests)
Transfer rate:          1271911.98 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0  159  63.3    191     230
Processing:    12  276  63.7    245     455
Waiting:        0   52  63.6     19     221
Total:         12  435  23.1    434     468

Percentage of the requests served within a certain time (ms)
  50%    434
  66%    439
  75%    441
  80%    443
  90%    449
  95%    453
  98%    466
  99%    466
 100%    468 (longest request)


vegeta

$ echo "GET https://localhost:8443/zig-out/bin/httpd" | vegeta attack -duration=30s -rate=0 -max-workers=100 -root-certs ~/Code/tls.zig/example/cert/minica.pem |  vegeta report
Requests      [total, rate, throughput]         7135, 237.81, 237.66
Duration      [total, attack, wait]             30.009s, 30.003s, 5.883ms
Latencies     [min, mean, 50, 90, 95, 99, max]  111.67µs, 9.706ms, 5.142ms, 9.61ms, 11.838ms, 185.979ms, 368.652ms
Bytes In      [total, mean]                     40692339200, 5703201.01
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           99.96%
Status Codes  [code:count]                      0:3  200:7132
Error Set:
Get "https://localhost:8443/zig-out/bin/httpd": dial tcp 0.0.0.0:0->[::1]:8443: connect: connection refused

$ echo "GET https://localhost:8443/zig-out/bin/httpd" | vegeta attack -duration=30s -rate=0 -max-workers=100 -root-certs ~/Code/tls.zig/example/cert/minica.pem |  vegeta report
Requests      [total, rate, throughput]         6607, 220.22, 219.17
Duration      [total, attack, wait]             30.008s, 30.002s, 6.372ms
Latencies     [min, mean, 50, 90, 95, 99, max]  968.501µs, 15.811ms, 11.033ms, 17.661ms, 21.774ms, 273.34ms, 315.358ms
Bytes In      [total, mean]                     37525731200, 5679692.93
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           99.55%
Status Codes  [code:count]                      0:30  200:6577
Error Set:
Get "https://localhost:8443/zig-out/bin/httpd": dial tcp 0.0.0.0:0->[::1]:8443: connect: connection refused
Get "https://localhost:8443/zig-out/bin/httpd": tls: invalid signature by the server certificate: ECDSA verification failure




### https with rsa certificate
 ./ab.sh
files count: 197
https httpz
Requests      [total, rate, throughput]         1573, 157.13, 55.24
Duration      [total, attack, wait]             28.473s, 10.011s, 18.462s
Latencies     [min, mean, 50, 90, 95, 99, max]  455.789ms, 12.467s, 14.115s, 18.541s, 18.584s, 18.618s, 18.644s
Bytes In      [total, mean]                     196680867, 125035.52
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:1573
Error Set:
https nginx
Requests      [total, rate, throughput]         14631, 1462.96, 963.40
Duration      [total, attack, wait]             15.187s, 10.001s, 5.186s
Latencies     [min, mean, 50, 90, 95, 99, max]  72.989ms, 747.424ms, 376.722ms, 410.271ms, 1.779s, 11.288s, 15.118s
Bytes In      [total, mean]                     1845214245, 126116.76
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:14631
Error Set:
info(main): time spend in tls handshake: 28394726234ns 28394ms

### https with ec certificate 
./ab.sh
files count: 197
https httpz
Requests      [total, rate, throughput]         5967, 596.62, 493.82
Duration      [total, attack, wait]             12.083s, 10.001s, 2.082s
Latencies     [min, mean, 50, 90, 95, 99, max]  79.036ms, 1.887s, 2.066s, 2.11s, 2.117s, 2.126s, 2.134s
Bytes In      [total, mean]                     749094277, 125539.51
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:5967
Error Set:
https nginx
Requests      [total, rate, throughput]         24315, 2431.51, 1713.25
Duration      [total, attack, wait]             14.192s, 10s, 4.192s
Latencies     [min, mean, 50, 90, 95, 99, max]  51.825ms, 444.278ms, 218.863ms, 249.482ms, 842.448ms, 11.242s, 14.138s
Bytes In      [total, mean]                     3067603203, 126160.94
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:24315
Error Set:
info(main): time spend in tls handshake: 11910666255ns 11910ms

### http 
 ./ab.sh
files count: 197
http httpz
Requests      [total, rate, throughput]         77626, 7762.36, 7761.49
Duration      [total, attack, wait]             10.001s, 10s, 1.114ms
Latencies     [min, mean, 50, 90, 95, 99, max]  63.435µs, 1.113ms, 291.855µs, 3.439ms, 5.268ms, 8.871ms, 14.408ms
Bytes In      [total, mean]                     9816084846, 126453.57
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:77626
Error Set:
http nginx
Requests      [total, rate, throughput]         53234, 5322.65, 5321.20
Duration      [total, attack, wait]             10.004s, 10.001s, 2.721ms
Latencies     [min, mean, 50, 90, 95, 99, max]  63.518µs, 1.203ms, 539.859µs, 2.893ms, 5.278ms, 9.083ms, 15.427ms
Bytes In      [total, mean]                     6727748288, 126380.66
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:53234


### with keep alive
files count: 197
https httpz
Requests      [total, rate, throughput]         34531, 3453.05, 3438.90
Duration      [total, attack, wait]             10.041s, 10s, 41.168ms
Latencies     [min, mean, 50, 90, 95, 99, max]  70.963µs, 35.135ms, 40.944ms, 42.185ms, 45.703ms, 55.7ms, 167.743ms
Bytes In      [total, mean]                     4361555168, 126308.39
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:34531
Error Set:
https nginx
Requests      [total, rate, throughput]         72215, 7221.54, 7215.58
Duration      [total, attack, wait]             10.008s, 10s, 8.258ms
Latencies     [min, mean, 50, 90, 95, 99, max]  27.037µs, 8.136ms, 8.914ms, 15.157ms, 17.109ms, 22.919ms, 38.269ms
Bytes In      [total, mean]                     9123273855, 126334.89
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:72215
Error Set:

http httpz
Requests      [total, rate, throughput]         85044, 8503.73, 8478.95
Duration      [total, attack, wait]             10.03s, 10.001s, 29.224ms
Latencies     [min, mean, 50, 90, 95, 99, max]  30.476µs, 1.428ms, 241.364µs, 4.461ms, 5.923ms, 8.859ms, 53.608ms
Bytes In      [total, mean]                     10744070024, 126335.43
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:85044
Error Set:
http nginx
Requests      [total, rate, throughput]         70439, 7043.53, 7042.99
Duration      [total, attack, wait]             10.001s, 10.001s, 768.785µs
Latencies     [min, mean, 50, 90, 95, 99, max]  27.297µs, 1.632ms, 532.394µs, 4.717ms, 6.482ms, 9.675ms, 18.332ms
Bytes In      [total, mean]                     8898796568, 126333.37
Bytes Out     [total, mean]                     0, 0.00
Success       [ratio]                           100.00%
Status Codes  [code:count]                      200:70439
Error Set:
info(main): time spend in tls handshake: 937317880ns 937ms
