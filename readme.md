# HTTP/HTTPS static file server in Zig with io_uring, kernel TLS

# Known issues

- handling of overshot read when switching to ktsl
test with curl build with wolfssl and buffer size of 4096 with incremental buffer consumption, you will not wait long for having partial tls record in overshot data

- curl (and other clients) with openssl sometimes fail with wrong signature problem [ref](https://github.com/curl/curl/issues/11434), curl with wolfssl (and probably other tls libraries) works fine  
signature is created with code from Zig std library 

- forcibly closing tls connection, not sending close notify tls message




