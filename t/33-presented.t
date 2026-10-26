#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use IO::Socket::INET;
use POSIX ();
use lib 't/lib';

use SICK::Device;
use SICK::OpenSSL;
use SICK::Target;
use Path::Tiny qw( path );
use Test::SICK::PKI qw( new_ca new_cert );

# The default presented_cert: openssl s_client against host:port. Everything
# here stays on 127.0.0.1 - an openssl s_server and two tiny servers of our
# own on ports the system picks.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();
plan skip_all => 'cannot listen on 127.0.0.1'
  unless IO::Socket::INET->new( LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1 );

{
  package SICK::Target::Probe;
  our @ISA = ('SICK::Target');
  sub deploy { 1 }

  package SICK::Target::Impatient;
  our @ISA = ('SICK::Target::Probe');
  sub connect_timeout { 2 }
}

my $tmp   = tempdir( CLEANUP => 1 );
my $root  = new_ca( dir => $tmp, name => 'root',  cn => 'Presented Root' );
my $inter = new_ca( dir => $tmp, name => 'inter', cn => 'Presented Intermediate', issuer => $root );
my $leaf  = new_cert( dir => $tmp, name => 'leaf', ca => $inter, cn => 'device.example.internal',
  san => 'DNS:device.example.internal,IP:127.0.0.1' );

my @children;
END {
  local $?;    # the exit code of the test, not of the servers
  if (@children) { kill 'TERM', @children; waitpid $_, 0 for @children }
}

sub free_port {
  my $socket = IO::Socket::INET->new( LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1 ) or die 'listen: '.$!;
  my $port = $socket->sockport;
  close $socket;
  return $port;
}

sub answers {
  my ( $port ) = @_;
  for ( 1 .. 100 ) {
    my $socket = IO::Socket::INET->new( PeerAddr => '127.0.0.1', PeerPort => $port, Timeout => 1 );
    if ($socket) { close $socket; return 1 }
    select undef, undef, undef, 0.1;
  }
  return 0;
}

# a listener of our own; the child runs $serve for every connection
sub tcp_server {
  my ( $serve ) = @_;
  my $listener = IO::Socket::INET->new( LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 5, ReuseAddr => 1 )
    or die 'listen: '.$!;
  my $pid = fork;
  die 'fork: '.$! unless defined $pid;
  unless ($pid) {
    while ( my $client = $listener->accept ) { $serve->($client) }
    POSIX::_exit(0);
  }
  push @children, $pid;
  my $port = $listener->sockport;
  close $listener;
  return $port;
}

sub target {
  my ( %arg ) = @_;
  my $class = delete $arg{class} || 'SICK::Target::Probe';
  my $device = SICK::Device->new(
    name         => 'device',
    type         => 'probe',
    names        => [ 'device.example.internal', '127.0.0.1' ],
    lifetime     => 86400,
    renew_before => 3600,
    key          => 'rsa2048',
    %arg,
  );
  return $class->new( device => $device );
}

# an openssl s_server with the test certificate and its intermediate
my $tls_port = free_port();
{
  my @command = (
    SICK::OpenSSL::bin(), 's_server', '-accept', '127.0.0.1:'.$tls_port,
    '-cert', $leaf->{cert}, '-key', $leaf->{key}, '-cert_chain', $inter->{cert}, '-www'
  );
  my $pid = fork;
  die 'fork: '.$! unless defined $pid;
  unless ($pid) {
    open STDIN,  '<', '/dev/null';
    open STDOUT, '>', $tmp.'/s_server.log';
    open STDERR, '>&', \*STDOUT;
    { no warnings 'exec'; exec { $command[0] } @command }
    POSIX::_exit(127);
  }
  push @children, $pid;
}
my $tls_up = answers($tls_port);

subtest 'a TLS server presents its certificate' => sub {
  plan skip_all => 'openssl s_server did not come up: '.( -e $tmp.'/s_server.log' ? path($tmp.'/s_server.log')->slurp_raw : q{} )
    unless $tls_up;

  my $bundle = target( host => '127.0.0.1', port => $tls_port )->presented_cert;
  isa_ok $bundle, 'SICK::Bundle';
  is $bundle->cert, $leaf->{cert_pem}, 'the certificate of the server';
  is $bundle->fingerprint_sha256, SICK::Bundle->new( cert => $leaf->{cert_pem} )->fingerprint_sha256, '... by fingerprint';
  is $bundle->key, undef, 'no key, of course';
  is $bundle->chain, $inter->{pem}, 'what the server sends along is the chain';
  ok $bundle->is_issued_by( $root->{pem} ), '... so the certificate verifies against the root';
  is_deeply $bundle->names, [ '127.0.0.1', 'device.example.internal' ], 'names';
};

subtest 'nobody listens: unreachable' => sub {
  my $port = free_port();
  my $ok = eval { target( host => '127.0.0.1', port => $port )->presented_cert; 1 };
  ok !$ok, 'dies';
  like $@, qr/^unreachable: 127\.0\.0\.1:$port: \S/, 'unreachable: <host>:<port>: <reason>';
  like $@, qr/^unreachable: 127\.0\.0\.1:$port: Connection refused/, '... with the reason of the system';
  unlike $@, qr/\n.*\n/s, '... on one line';
};

subtest 'a server that does not speak TLS: no certificate' => sub {
  my $port = tcp_server( sub {
      my ( $client ) = @_;
      print {$client} "220 this is not TLS\r\n";
      close $client;
  } );
  my $target = target( host => '127.0.0.1', port => $port );
  my @result = eval { $target->presented_cert };
  is $@, q{}, 'does not die: the device was reached';
  is_deeply \@result, [undef], 'undef, one value also in list context';
};

subtest 'a server that never answers: unreachable after the time limit' => sub {
  my $port = tcp_server( sub { my ( $client ) = @_; sleep 30; close $client } );
  my $start = time;
  my $ok = eval { target( class => 'SICK::Target::Impatient', host => '127.0.0.1', port => $port )->presented_cert; 1 };
  ok !$ok, 'dies';
  like $@, qr/^unreachable: 127\.0\.0\.1:$port did not answer within 2s/, '... as unreachable, with the limit';
  cmp_ok time - $start, '<', 15, '... and without waiting longer';
};

subtest 'what s_client is asked' => sub {
  my $log     = $tmp.'/s_client-args.log';
  my $wrapper = $tmp.'/openssl-recorder';
  path($wrapper)->spew_raw(<<"WRAPPER");
#!$^X
open my \$log, '>>', '$log' or die \$!;
print {\$log} join( ' ', \@ARGV ), "\\n";
close \$log;
print STDERR \$ENV{SICK_TEST_STDERR} if defined \$ENV{SICK_TEST_STDERR};
exit 1;
WRAPPER
  chmod 0755, $wrapper or die 'chmod: '.$!;
  local $ENV{SICK_OPENSSL} = $wrapper;

  my $asked = sub {
    my ( %arg ) = @_;
    unlink $log;
    eval { target(%arg)->presented_cert };
    return path($log)->slurp_raw;
  };

  is $asked->( host => '192.0.2.5' ),
    "s_client -connect 192.0.2.5:443 -showcerts -servername device.example.internal\n",
    'an address as host: port 443, the first host name as server name';
  is $asked->( host => 'box.example.internal', port => 8443 ),
    "s_client -connect box.example.internal:8443 -showcerts -servername box.example.internal\n",
    'a host name as host is the server name';
  is $asked->(),
    "s_client -connect device.example.internal:443 -showcerts -servername device.example.internal\n",
    'no host: the first name of the device';
  is $asked->( host => '2001:db8::5', names => ['192.0.2.5'] ),
    "s_client -connect [2001:db8::5]:443 -showcerts\n",
    'an IPv6 host goes in brackets; without any host name there is no server name';

  # reasons, the way different versions of openssl print them
  my %reason = (
    'Name or service not known' =>
      "40E7:error:10080002:BIO routines:BIO_lookup_ex:system lib:../crypto/bio/bio_addr.c:738:Name or service not known\nconnect:errno=0\n",
    'Connection refused' =>
      "140:error:0200206F:system library:connect:Connection refused:../crypto/bio/b_sock2.c:110:\nconnect:errno=111\n",
    'No route to host' =>
      "4037:error:80000071:system library:BIO_connect:No route to host:../crypto/bio/bio_sock2.c:183:calling connect()\n4037:error:10000067:BIO routines:BIO_connect:connect error:../crypto/bio/bio_sock2.c:185:\nconnect:errno=113\n",
    'connect:errno=110' => "connect:errno=110\n",
    'no connection'     => q{}
  );
  for my $reason ( sort keys %reason ) {
    local $ENV{SICK_TEST_STDERR} = $reason{$reason};
    my $ok = eval { target( host => 'box.example.internal' )->presented_cert; 1 };
    ok !$ok, 'dies';
    is $@ =~ s/ at \S+ line \d+\.\n\z//r, 'unreachable: box.example.internal:443: '.$reason, '... with the reason "'.$reason.'"';
  }
};

subtest 'openssl is missing: that is not "unreachable"' => sub {
  local $ENV{SICK_OPENSSL} = $tmp.'/no-such-openssl';
  my $ok = eval { target( host => '127.0.0.1', port => $tls_port )->presented_cert; 1 };
  ok !$ok, 'dies';
  like $@, qr/^cannot run '\Q$tmp\E\/no-such-openssl': \S/, '... naming the missing program';
  unlike $@, qr/unreachable/, '... and not blaming the device';
};

done_testing;
