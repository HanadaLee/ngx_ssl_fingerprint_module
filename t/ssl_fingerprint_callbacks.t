#!/usr/bin/perl

use warnings;
use strict;
use Test::More;
use IO::Socket::SSL;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx qw/:DEFAULT http_content/;

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite lua socket_ssl/)
    ->has_daemon('openssl');

my $lua_path = $ENV{TEST_FINGERPRINT_LUA_PATH} || ';;';
$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    lua_package_path "$lua_path";
    ssl_fingerprint on;
    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_client_hello_by_lua_block {
        local hello = require "ngx.ssl.clienthello"
        if hello.get_client_hello_server_name() == "reject.test" then
            ngx.log(ngx.NOTICE, "fingerprint test: rejecting ClientHello")
            return ngx.exit(ngx.ERROR)
        end
        ngx.sleep(0.001)
        ngx.log(ngx.NOTICE, "fingerprint test: ClientHello callback resumed")
    }
    server {
        listen 127.0.0.1:8443 ssl;
        server_name localhost reject.test;
        return 200 "default|\$ssl_fingerprint_ja4|\$ssl_fingerprint_ja3";
    }
    server {
        listen 127.0.0.1:8443 ssl;
        server_name selected.test;
        ssl_client_hello_by_lua_block {
            ngx.sleep(0.001)
            ngx.log(ngx.NOTICE, "fingerprint test: selected TLS server")
        }
        return 200 "selected|\$ssl_fingerprint_ja4|\$ssl_fingerprint_ja3";
    }
}
EOF

$t->write_file('openssl.conf', "[req]\ndistinguished_name=dn\n[dn]\n");
my $d = $t->testdir();
system("openssl req -x509 -newkey rsa:2048 -nodes -config $d/openssl.conf "
    . "-subj /CN=localhost/ -keyout $d/localhost.key "
    . "-out $d/localhost.crt >>$d/openssl.out 2>&1") == 0
    or die "certificate generation failed";
$t->run()->plan(8);

my $response = http_content(http_get('/', SSL => 1,
    SSL_hostname => 'localhost', SSL_version => 'TLSv1_2'));
like($response, qr/^default\|t12d/, 'TLS 1.2 and asynchronous Lua callback');
$response = http_content(http(
    "GET / HTTP/1.0\r\nHost: selected.test\r\n\r\n", SSL => 1,
    SSL_hostname => 'selected.test', SSL_version => 'TLSv1_3'));
like($response, qr/^selected\|t13d/, 'SNI server selected with Lua and fingerprint');
like($response, qr/\|771,/, 'TLS 1.3 JA3 retains legacy version');
like($t->read_file('error.log'), qr/fingerprint test: selected TLS server/,
    'SNI selects the server-specific callback before the HTTP request');

for (1..3) {
    my $s = IO::Socket::SSL->new(PeerAddr => '127.0.0.1',
        PeerPort => port(8443), SSL_verify_mode => 0,
        SSL_hostname => 'reject.test', Timeout => 3);
    ok(!$s, "Lua rejection is not bypassed by capture $_");
    close $s if $s;
}
like($t->read_file('error.log'),
    qr/fingerprint test: ClientHello callback resumed/,
    'Lua ClientHello retry completed');
