#!/usr/bin/perl

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;

my $t = Test::Nginx->new()->has(qw/http http_v3 rewrite cryptx/)
    ->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    ssl_fingerprint on;
    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name localhost;
        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
        location /hash {
            return 200 "$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_o|$ssl_fingerprint_ja3_hash";
        }
        location /all {
            return 200 "$ssl_fingerprint_ja4|$ssl_fingerprint_ja4_o|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4_r|$ssl_fingerprint_ja4_ro|$ssl_fingerprint_ja3";
        }
    }
}
EOF

$t->write_file('openssl.conf', "[req]\ndistinguished_name=dn\n[dn]\n");
my $d = $t->testdir();
system("openssl req -x509 -newkey rsa:2048 -nodes -config $d/openssl.conf "
    . "-subj /CN=localhost/ -keyout $d/localhost.key "
    . "-out $d/localhost.crt >>$d/openssl.out 2>&1") == 0
    or die "certificate generation failed";
$t->run()->plan(25);

my $s = Test::Nginx::HTTP3->new(8980);
my $first = get('/hash');
like($first, qr/^q13d\d{4}h3_[0-9a-f]{12}_[0-9a-f]{12}\|/,
    'QUIC fingerprint captured through message callback');
my $all = get('/all');
is(join('|', (split /\|/, $all)[0..2]), $first,
    'cached hashes survive the first stream closing');
my @values = split /\|/, $all;
like($values[3], qr/^q13d/, 'raw fingerprint uses QUIC transport');
like($values[4], qr/^q13d/, 'original raw fingerprint uses QUIC transport');
like($values[5], qr/^771,/, 'JA3 keeps the ClientHello legacy version');
for (1..20) {
    is(get('/all'), $all, "fingerprints survive stream turnover $_");
}

sub get {
    my ($path) = @_;
    my $sid = $s->new_stream({ path => $path });
    my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
    return join '', map { $_->{data} }
        grep { $_->{type} eq 'DATA' && $_->{sid} == $sid } @$frames;
}
