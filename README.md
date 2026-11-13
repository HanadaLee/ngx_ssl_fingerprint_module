# ngx_ssl_fingerprint_module

Exposes JA3 and JA4 TLS client fingerprints as nginx variables for HTTP and Stream, including HTTP/3 connections.

## Table of Contents

- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
  - [ssl_fingerprint](#ssl_fingerprint)
- [Embedded Variables](#embedded-variables)
- [Tests](#tests)
- [Author and license](#author-and-license)

## Synopsis

```nginx
events {}

http {
    ssl_fingerprint on;

    log_format fingerprint '$remote_addr $ssl_fingerprint_ja3_hash $ssl_fingerprint_ja4';
    access_log logs/fingerprint.log fingerprint;

    server {
        listen 443 ssl;
        server_name example.com;

        ssl_certificate server.crt;
        ssl_certificate_key server.key;

        location / {
            return 200 "$ssl_fingerprint_ja4\n";
        }
    }
}

stream {
    ssl_fingerprint on;

    server {
        listen 8443 ssl;

        ssl_certificate server.crt;
        ssl_certificate_key server.key;

        return "$ssl_fingerprint_ja4\n";
    }
}
```

## Installation

Requires nginx with SSL support and the bundled [core patch](patches/nginx-1.29.3+.patch). No OpenSSL patch is required.

Apply the patch before compiling nginx:

```sh
patch -d /path/to/nginx -p1 < /path/to/ngx_ssl_fingerprint_module/patches/nginx-1.29.3+.patch
```

Run from the nginx source directory:

```sh
./configure \
    --with-http_ssl_module \
    --with-stream \
    --with-stream_ssl_module \
    --add-module=/path/to/ngx_ssl_fingerprint_module
make
```

Omit the Stream options for an HTTP-only build. HTTP/2 and HTTP/3 require their corresponding nginx modules.

Dynamic modules and a dynamic Stream subsystem are not supported.

## Directives

### ssl_fingerprint

| Syntax: | **ssl_fingerprint** `on` \| `off`; |
| :--- | :--- |
| Default: | `ssl_fingerprint off;` |
| Context: | `http`, `stream` |

Enables or disables TLS ClientHello fingerprint collection. HTTP and Stream share this setting.

## Embedded Variables

The variables are available in HTTP and Stream. They describe the first ClientHello of the TLS connection and remain the same for requests that reuse that connection. Values are empty when collection is disabled or no ClientHello has been captured, including plain HTTP and TCP connections.

### $ssl_greased

`1` if the ClientHello cipher suite list contains a GREASE value, or `0` otherwise.

### $ssl_fingerprint_ja3

JA3 fingerprint string.

### $ssl_fingerprint_ja3_hash

MD5 hash of the JA3 fingerprint, in lowercase hexadecimal.

### $ssl_fingerprint_ja4

JA4 fingerprint with hashed cipher and extension components.

### $ssl_fingerprint_ja4_r

Raw JA4 fingerprint with sorted cipher and extension lists. The extension list excludes SNI and ALPN.

### $ssl_fingerprint_ja4_o

JA4 fingerprint with hashed components derived from the original cipher and extension order.

### $ssl_fingerprint_ja4_ro

Raw JA4 fingerprint preserving the original cipher and extension order. The extension list includes SNI and ALPN when present.

GREASE values are excluded from the JA3 and JA4 fingerprints.

## Tests

Run the parser tests with a C compiler, OpenSSL development libraries, and Python 3:

```sh
bash util/run-unit-tests.sh
```

The integration tests use nginx-tests and a binary built with this module:

```sh
TEST_NGINX_BINARY=/path/to/nginx \
PERL5LIB=/path/to/nginx-tests/lib \
prove -v t/*.t
```

The integration suite requires Perl, IO::Socket::SSL, and the OpenSSL command-line tool. HTTP/3 tests additionally require CryptX. Lua callback tests require `ngx_http_lua_module` and its Lua libraries.

## Author and license

Copyright (C) 2020-2024 Phus Lu

Copyright (C) Hanada

Licensed under the [BSD 2-Clause License](LICENSE).
