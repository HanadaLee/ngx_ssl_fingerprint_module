# ngx_ssl_fingerprint_module

A high performance nginx module for ja4, ja3, and http2 fingerprint.

## Patches
 - [nginx - save ja3/http2 fingerprint](patches)
 - [openssl - save clienthello data](patches)

### Support Matrix

|              | openssl-3.5.4 |
| -------------| ------------- |
| nginx-1.29.3 | ✅            |

## Configuration

### HTTP/Stream module variables

| Name                     | Default Value | Comments                 |
| ------------------------ | ------------- | ------------------------ |
| ssl_greased              | 0             | TLS greased flag.        |
| ssl_fingerprint_ja3      | NULL          | The ja3 fingerprint.     |
| ssl_fingerprint_ja3_hash | NULL          | The ja3 fingerprint hash.|
| ssl_fingerprint_ja4_r    | NULL          | The ja4 raw fingerprint. |
| ssl_fingerprint_ja4      | NULL          | The ja4 fingerprint.     |
| ssl_fingerprint_ja4_ro   | NULL          | The ja4 original raw fingerprint. |
| ssl_fingerprint_ja4_o    | NULL          | The ja4 original fingerprint.     |

#### Example

```nginx
http {
    server {
        listen                 127.0.0.1:4433 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 200 "ja4: $ssl_fingerprint_ja4\nja3: $ssl_fingerprint_ja3";
    }
}
stream {
    server {
        listen                 127.0.0.1:4444 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 "ja4: $ssl_fingerprint_ja4\nja3: $ssl_fingerprint_ja3\n";
    }
}
```


## Quick Start

```bash

# Clone

$ git clone -b release-1.29.3 --depth=1 https://github.com/nginx/nginx
$ cd nginx
$ git clone -b openssl-3.5.5 --depth=1 https://github.com/openssl/openssl
$ git clone -b ja4_fingerprint https://git.hanada.info/hanada/ngx_ssl_fingerprint_module

# Patch

$ patch -p1 -d openssl < ngx_ssl_fingerprint_module/patches/openssl.openssl-3.5.5+.patch
$ patch -p1 < ngx_ssl_fingerprint_module/patches/nginx-1.29.3+.patch

# Build

$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=./openssl --with-openssl-opt="no-apps no-legacy no-idea no-mdc2 no-rc5 no-zlib no-ssl3 no-tests no-ssl3-method enable-rfc3779 enable-cms no-capieng no-rdrand" --with-stream_ssl_module --add-module=./ngx_ssl_fingerprint_module --with-debug --with-stream --with-http_v2_module --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
$ make -j

# Test

$ objs/nginx -p . -c ./ngx_ssl_fingerprint_module/nginx.conf
$ curl -k https://127.0.0.1:4433
$ openssl s_client -connect localhost:4443

# Fuzzing

$ git clone https://github.com/tlsfuzzer/tlsfuzzer
$ cd tlsfuzzer
$ python3 -m venv venv
$ venv/bin/pip install --pre tlslite-ng
$ PYTHONPATH=. venv/bin/python scripts/test-client-hello-max-size.py

```
