# nginx-ssl-fingerprint

A high performance nginx module for ja4, ja3, and http2 fingerprint.

## Patches
 - [nginx - save ja3/http2 fingerprint](patches)
 - [openssl - save clienthello data](patches)

### Support Matrix

|              | openssl-3.5.4 |
| -------------| ------------- |
| nginx-1.29.3 | ✅            |

## Configuration

### HTTP module variables

| Name              | Default Value | Comments                 |
| ----------------- | ------------- | ------------------------ |
| http_ssl_greased  | 0             | TLS greased flag.        |
| http_ssl_ja3      | NULL          | The ja3 fingerprint.     |
| http_ssl_ja3_hash | NULL          | The ja3 fingerprint hash.|
| http2_fingerprint | NULL          | The http2 fingerprint.   |
| http_ssl_ja4_r    | NULL          | The ja4 raw fingerprint. |
| http_ssl_ja4      | NULL          | The ja4 fingerprint.     |
| http_ssl_ja4_ro   | NULL          | The ja4 original raw fingerprint. |
| http_ssl_ja4_o    | NULL          | The ja4 original fingerprint.     |

#### Example

```nginx
http {
    server {
        listen                 127.0.0.1:4433 ssl http2;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 200 "ja4: $http_ssl_ja4\nja3: $http_ssl_ja3\nh2fp: $http2_fingerprint";
    }
}
```

### Stream module variables

| Name                | Default Value | Comments                 |
| ------------------- | ------------- | ------------------------ |
| stream_ssl_greased  | 0             | TLS greased flag.        |
| stream_ssl_ja3      | NULL          | The ja3 fingerprint.     |
| stream_ssl_ja3_hash | NULL          | The ja3 fingerprint hash.|
| stream_ssl_ja4_r    | NULL          | The ja4 raw fingerprint. |
| stream_ssl_ja4      | NULL          | The ja4 fingerprint.     |
| stream_ssl_ja4_ro   | NULL          | The ja4 original raw fingerprint. |
| stream_ssl_ja4_o    | NULL          | The ja4 original fingerprint.     |

#### Example

```nginx
stream {
    server {
        listen                 127.0.0.1:4443 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 "ja4: $stream_ssl_ja4\nja3: $stream_ssl_ja3\n";
    }
}
```


## Quick Start

```bash

# Clone

$ git clone -b release-1.29.3 --depth=1 https://github.com/nginx/nginx
$ cd nginx
$ git clone -b openssl-3.5.4 --depth=1 https://github.com/openssl/openssl
$ git clone -b ja4_fingerprint https://github.com/hnakamur/nginx-ssl-fingerprint

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.openssl-3.5.4.ja4.patch
$ patch -p1 < nginx-ssl-fingerprint/patches/nginx-1.29.3.ja4.patch

# Build

$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=./openssl --with-openssl-opt="no-apps no-legacy no-idea no-mdc2 no-rc5 no-zlib no-ssl3 no-tests no-ssl3-method enable-rfc3779 enable-cms no-capieng no-rdrand" --add-module=./nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-http_v2_module --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
$ make -j

# Test

$ objs/nginx -p . -c ./nginx-ssl-fingerprint/nginx.conf
$ curl -k https://127.0.0.1:4433
$ openssl s_client -connect localhost:4443

# Fuzzing

$ git clone https://github.com/tlsfuzzer/tlsfuzzer
$ cd tlsfuzzer
$ python3 -m venv venv
$ venv/bin/pip install --pre tlslite-ng
$ PYTHONPATH=. venv/bin/python scripts/test-client-hello-max-size.py

```
