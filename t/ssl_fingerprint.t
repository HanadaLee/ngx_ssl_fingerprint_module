#!/usr/bin/perl

# Tests for HTTP and stream SSL fingerprints.

###############################################################################

use warnings;
use strict;

use Digest::MD5 qw/ md5_hex /;
use Digest::SHA qw/ sha256_hex /;
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

    ssl_fingerprint on;

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        return 200 "$ssl_greased|$ssl_fingerprint_ja3|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4_r|$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_ro|$ssl_fingerprint_ja4_o;$ssl_greased|$ssl_fingerprint_ja3|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4_r|$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_ro|$ssl_fingerprint_ja4_o";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        return 200 "$ssl_greased|$ssl_fingerprint_ja3|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4_r|$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_ro|$ssl_fingerprint_ja4_o";
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    ssl_fingerprint on;

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen  127.0.0.1:8444 ssl;
        return  "$ssl_greased|$ssl_fingerprint_ja3|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4_r|$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_ro|$ssl_fingerprint_ja4_o";
    }

    server {
        listen  127.0.0.1:8081;
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

$t->run()->plan(27);

###############################################################################

my $response = http_get('/', SSL => 1, SSL_hostname => 'localhost');
like($response, qr/^HTTP\/1\.1 200 /, 'HTTP TLS request succeeds');

my ($http, $http_again) = split /;/, http_content($response), 2;
my @http = fingerprints($http);

is(scalar @http, 7, 'HTTP exposes all fingerprint variables');
like($http[0], qr/^[01]$/, 'HTTP greased flag');
like($http[1], qr/^\d+,[\d-]*,[\d-]*,[\d-]*,[\d-]*$/,
	'HTTP JA3 raw format');
like($http[2], qr/^[0-9a-f]{32}$/, 'HTTP JA3 hash format');
is($http[2], md5_hex($http[1]), 'HTTP JA3 hash matches raw value');
like($http[3], ja4_raw_re(), 'HTTP JA4 raw format');
like($http[4], ja4_re(), 'HTTP JA4 format');
is($http[4], ja4($http[3]), 'HTTP JA4 hashes its raw components');
like($http[5], ja4_raw_re(), 'HTTP original JA4 raw format');
like($http[6], ja4_re(), 'HTTP original JA4 format');
is($http[6], ja4($http[5]), 'HTTP original JA4 hashes raw components');
is(substr($http[3], 0, 10), substr($http[5], 0, 10),
	'HTTP JA4 variants retain the same prefix');
is($http_again, $http, 'HTTP repeated variable reads are stable');

my $stream = stream(
	PeerAddr => '127.0.0.1:' . port(8444),
	SSL => 1,
	SSL_hostname => 'localhost'
)->read();
my @stream = fingerprints($stream);

is(scalar @stream, 7, 'stream exposes all fingerprint variables');
like($stream[0], qr/^[01]$/, 'stream greased flag');
like($stream[1], qr/^\d+,[\d-]*,[\d-]*,[\d-]*,[\d-]*$/,
	'stream JA3 raw format');
is($stream[2], md5_hex($stream[1]), 'stream JA3 hash matches raw value');
like($stream[3], ja4_raw_re(), 'stream JA4 raw format');
like($stream[4], ja4_re(), 'stream JA4 format');
is($stream[4], ja4($stream[3]), 'stream JA4 hashes its raw components');
like($stream[5], ja4_raw_re(), 'stream original JA4 raw format');
like($stream[6], ja4_re(), 'stream original JA4 format');
is($stream[6], ja4($stream[5]),
	'stream original JA4 hashes raw components');
is(substr($stream[3], 0, 10), substr($stream[5], 0, 10),
	'stream JA4 variants retain the same prefix');

is(http_content(http_get('/')), '||||||',
	'HTTP variables are empty without TLS');
is(stream('127.0.0.1:' . port(8081))->read(), '||||||',
	'stream variables are empty without TLS');

###############################################################################

sub fingerprints {
	return split /\|/, shift, -1;
}


sub ja4_raw_re {
	return qr/^[tq]\d{2}[di]\d{4}[0-9a-z]{2}_[0-9a-f]{4}(?:,[0-9a-f]{4})*_[0-9a-f]{4}(?:,[0-9a-f]{4})*(?:_[0-9a-f]{4}(?:,[0-9a-f]{4})*)?$/;
}


sub ja4_re {
	return qr/^[tq]\d{2}[di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/;
}


sub ja4 {
	my ($a, $b, $c) = split /_/, shift, 3;

	return join('_', $a, substr(sha256_hex($b), 0, 12),
		length($c) ? substr(sha256_hex($c), 0, 12) : '000000000000');
}

###############################################################################
