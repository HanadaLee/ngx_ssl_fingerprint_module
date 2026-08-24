#!/usr/bin/perl

# Tests for SSL fingerprint collection disabled by default.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_ssl stream stream_ssl stream_return socket_ssl
		ngx_ssl_fingerprint_module/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        return 200 "$ssl_greased|$ssl_fingerprint_ja3|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4_r|$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_ro|$ssl_fingerprint_ja4_o";
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen  127.0.0.1:8444 ssl;
        return  "$ssl_greased|$ssl_fingerprint_ja3|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4_r|$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_ro|$ssl_fingerprint_ja4_o";
    }
}

EOF

$t->write_file('openssl.conf', <<'EOF');
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate: $!\n";

$t->run()->plan(2);

###############################################################################

is(http_content(http_get('/', SSL => 1, SSL_hostname => 'localhost')),
	'||||||', 'HTTP fingerprints are disabled by default');
is(stream(
	PeerAddr => '127.0.0.1:' . port(8444),
	SSL => 1,
	SSL_hostname => 'localhost'
)->read(), '||||||', 'stream fingerprints are disabled by default');

###############################################################################
