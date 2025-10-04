# httpd 

HTTP/HTTPS static file server in Zig 

- Linux only, uses Linux specific io_uring and kernel TLS
- min Linux kernel version is 6.12. io_uring is not supported at old kernels, and features are added in each version, httpd depends on features added in kernel 6.12 (bind/listen, incremental buffer consumption). 
- should be build with latest master Zig
- single threaded

## Precompress files

httpd can serve compressed files if they exists on the disk. To compress site files run: 
```sh
$ httpd compress --root site/root --cache site/cache
```
where root is `root` of the site and `cache` folder for storing compressed files. Each compressible file will be compressed by gzip, brotli and zstd.

To use precompressed files start httpd with the same cache argument:
```sh
$ httpd --root site/root --cache site/cache --cert site/cert_ec
```
Client will be served with best match. Shortest file in format which is supported by the client. 

## Kernel TLS

```sh
# check if module is enabled
lsmod | grep tls

# enable module
sudo modprobe tls

# enable permanently
# cat /etc/modules-load.d/gnutls.conf
echo tls | sudo tee /etc/modules-load.d/gnutls.conf
```

## Example

Run `script/site.sh`, that will checkout an example site (ziglang.org), create https authority and site certificate, build project and start httpd listening for http on port 8080 and for https on port 8443.

To run httpd in release mode with some higher resources and precompressed site files run `script/start.sh`. You can stress test with something like: 

```sh
ulimit -n 65535
script/targets.sh http 8080 && oha -z 60s --urls-from-file site/targets-oha -c 10000 -w --cacert site/ca/cert.pem
```
`script/targets.sh` will create oha targets file for all files in site/root so requests are made for each file in the site. 


## Benchmark

Benchmarking using [oha](https://github.com/hatoo/oha) and comparing requests
per second of httpd with Nginx. Nginx is using single worker thread, configured
to my best knowledge similar to httpd: sendfile and ktls enabled.

Testing with different number of concurrent connections 1/100/500. '1 close'
is  single concurrent  connection without  keep-alive; closing  connection after
each request. Forces tls handshake on each https request.

Example of `script/bench.sh` results running both server and oha benchmark tool on the same host:

HTTP
|      | 1 close   | 1         | 100       | 500       |
| :--- | ---:      | ---:      | ---:      | ---:      |
|httpd | 15984     | 25325     |130578     | 87364     |
|Nginx | 20077     | 31750     | 55177     | 53746     |
                                           
HTTPS                                      
|      | 1 close   | 1         | 100       | 500       |
| :--- | ---:      | ---:      | ---:      | ---:      |
|httpd |  1719     | 12016     | 72463     | 53671     | 
|Nginx |  1860     | 13935     | 18391     | 17822     |


<!--
https://atlarge-research.com/pdfs/2024-bingimarsson-msc_thesis.pdf  
https://blog.cloudflare.com/missing-manuals-io_uring-worker-pool/  

cd site/root && find . -type f -exec ls -lSh {} + && cd -
-->
