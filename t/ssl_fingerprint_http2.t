#!/usr/bin/perl

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

my $t = Test::Nginx->new()->has(qw/http http_ssl http_v2 rewrite socket_ssl/)
    ->has_daemon('openssl');
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    http2 on;
    ssl_fingerprint on;
    server {
        listen 127.0.0.1:8443 ssl;
        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
        return 200 "$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_r|$ssl_fingerprint_ja3";
    }
}
EOF

$t->write_file('openssl.conf', "[req]\ndistinguished_name=dn\n[dn]\n");
my $d = $t->testdir();
system("openssl req -x509 -newkey rsa:2048 -nodes -config $d/openssl.conf "
    . "-subj /CN=localhost/ -keyout $d/localhost.key "
    . "-out $d/localhost.crt >>$d/openssl.out 2>&1") == 0
    or die "certificate generation failed";
$t->run()->plan(11);

my $s = Test::Nginx::HTTP2->new(port(8443), SSL => 1, alpn => 'h2');
my $first = get();
like($first, qr/^t1[23][di]\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}\|/,
    'TLS fingerprint is available over HTTP/2');
for (1..10) {
    is(get(), $first, "TLS fingerprint retained across HTTP/2 stream $_");
}

sub get {
    my $sid = $s->new_stream();
    my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
    return join '', map { $_->{data} }
        grep { $_->{type} eq 'DATA' && $_->{sid} == $sid } @$frames;
}
