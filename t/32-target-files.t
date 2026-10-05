#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use IO::Socket::INET;
use lib 't/lib';

use SICK::Bundle;
use SICK::Decision;
use SICK::Device;
use SICK::Issuer::SelfSigned;
use SICK::OpenSSL;
use SICK::Target;
use SICK::Target::Files;
use Test::SICK::PKI qw( new_ca new_cert slurp spew );

# SICK::Target::Files with certificates of SICK::Issuer::SelfSigned: files
# on disk, their modes, the reload command.

plan skip_all => 'openssl is not installed' unless SICK::OpenSSL::available();

my $tmp    = tempdir( CLEANUP => 1 );
my $issuer = SICK::Issuer::SelfSigned->new( dir => $tmp.'/ca' );
my %spec   = ( names => [ 'web.example.internal', '192.0.2.7' ], lifetime => 90 * 86400, key => 'ec256' );
my $bundle = $issuer->issue( {%spec} );
my $count  = 0;

sub mode_of { sprintf '%04o', ( stat $_[0] )[2] & 07777 }

sub files_in {
  my ( $dir ) = @_;
  opendir my $dh, $dir or die 'cannot read '.$dir.': '.$!;
  return [ sort grep { !/\A\.\.?\z/ } readdir $dh ];
}

# a files device with a fresh directory, and its target
sub target {
  my ( %options ) = @_;
  my $host = delete $options{host};
  my $port = delete $options{port};
  my $log  = delete $options{log};
  $options{dir} = $tmp.'/target'.++$count unless exists $options{dir};
  delete $options{dir} unless defined $options{dir};
  my $device = SICK::Device->new(
    name         => 'web',
    type         => 'files',
    host         => $host,
    port         => $port,
    names        => $spec{names},
    lifetime     => $spec{lifetime},
    renew_before => 30 * 86400,
    key          => $spec{key},
    options      => \%options,
  );
  return SICK::Target::Files->new( device => $device, log => $log );
}

subtest 'the class' => sub {
  is( SICK::Target->class_for('files'), 'SICK::Target::Files', 'type files' );
  isa_ok target(), 'SICK::Target';
};

subtest 'validate' => sub {
  my $good = target( reload => 'true', mode_key => '0640' );
  is $good->validate, $good, 'dir, reload and mode_key are the options';
  ok target( reload => [ 'systemctl', 'reload', 'nginx' ] )->validate, 'reload may be a list';

  my %bad = (
    'no dir'                 => [ { dir => undef }, qr/^devices\.web: missing 'dir'/ ],
    'an empty dir'           => [ { dir => q{} }, qr/^devices\.web: missing 'dir'/ ],
    'an unknown option'      => [ { colour => 'blue' }, qr/^devices\.web: unknown key 'colour' for type 'files'/ ],
    'a mode that is no mode' => [ { mode_key => 'rw-------' }, qr/^devices\.web\.mode_key: invalid file mode 'rw-------'/ ],
    'a mode out of range'    => [ { mode_key => '0888' }, qr/^devices\.web\.mode_key: invalid file mode '0888'/ ],
    'reload as a mapping'    => [ { reload => { run => 'x' } }, qr/^devices\.web\.reload: must be a command or a non-empty list/ ],
    'reload as an empty list' => [ { reload => [] }, qr/^devices\.web\.reload: must be a command or a non-empty list/ ],
    'dir as a list'          => [ { dir => ['/a'] }, qr/^devices\.web\.dir: must be a directory path/ ]
  );
  for my $case ( sort keys %bad ) {
    my ( $options, $message ) = @{ $bad{$case} };
    my $ok = eval { target(%$options)->validate; 1 };
    ok !$ok, 'dies for '.$case;
    like $@, $message, '... with its place in the device list';
  }

  my $ok = eval { target( dir => undef )->deploy($bundle); 1 };
  ok !$ok, 'deploy validates as well';
  like $@, qr/^devices\.web: missing 'dir'/, '... with the same message';
};

subtest 'deploy writes the four files' => sub {
  my $target = target();
  my $dir    = $target->dir;
  ok !-e $dir, 'the directory does not exist yet';

  is $target->deploy($bundle), undef, 'deploy returns nothing';
  is_deeply files_in($dir), [qw( cert.pem chain.pem fullchain.pem key.pem )], 'exactly the four files, no temporary ones left';
  is slurp( $dir.'/cert.pem' ),      $bundle->cert,      'cert.pem';
  is slurp( $dir.'/fullchain.pem' ), $bundle->fullchain, 'fullchain.pem';
  is slurp( $dir.'/key.pem' ),       $bundle->key,       'key.pem';
  is slurp( $dir.'/chain.pem' ),     q{},                'chain.pem is empty without a chain';

  is mode_of( $dir.'/key.pem' ), '0600', 'key.pem has mode 0600';
  is mode_of( $dir.'/'.$_ ), '0644', $_.' has mode 0644' for qw( cert.pem chain.pem fullchain.pem );

  my $read_back = SICK::Bundle->from_files( cert => $dir.'/cert.pem', key => $dir.'/key.pem' );
  is $read_back->fingerprint_sha256, $bundle->fingerprint_sha256, 'what is on disk is the certificate';
};

subtest 'modes do not depend on the umask' => sub {
  my $old    = umask 0;
  my $open   = target();
  my $custom = target( mode_key => '0640' );
  $open->deploy($bundle);
  $custom->deploy($bundle);
  umask 0077;
  my $closed = target();
  $closed->deploy($bundle);
  umask $old;

  is mode_of( $open->dir.'/key.pem' ),    '0600', 'key.pem is 0600 with umask 0';
  is mode_of( $custom->dir.'/key.pem' ),  '0640', 'mode_key sets another mode';
  is mode_of( $closed->dir.'/cert.pem' ), '0644', 'cert.pem is 0644 with umask 077';
};

subtest 'a chain' => sub {
  my $root  = new_ca( dir => $tmp, name => 'root' );
  my $inter = new_ca( dir => $tmp, name => 'inter', issuer => $root );
  my $leaf  = new_cert( dir => $tmp, name => 'leaf', ca => $inter, cn => 'web.example.internal', san => 'DNS:web.example.internal' );
  my $chained = SICK::Bundle->new( cert => $leaf->{cert_pem}, chain => $inter->{pem}, key => $leaf->{key_pem} );

  my $target = target();
  $target->deploy($chained);
  is slurp( $target->dir.'/chain.pem' ), $inter->{pem}, 'chain.pem';
  is slurp( $target->dir.'/fullchain.pem' ), $leaf->{cert_pem}.$inter->{pem}, 'fullchain.pem is certificate plus chain';

  my $presented = $target->presented_cert;
  is $presented->chain, $inter->{pem}, 'presented_cert reads the chain back';
  ok $presented->is_issued_by( $root->{pem} ), '... so it verifies against the root';

  $target->deploy($bundle);
  is slurp( $target->dir.'/chain.pem' ), q{}, 'a later certificate without a chain empties chain.pem';
  is $target->presented_cert->chain, undef, '... and presented_cert has none';
};

subtest 'deploy replaces files, it does not rewrite them' => sub {
  my $target = target();
  my $dir    = $target->dir;
  $target->deploy($bundle);
  my %inode = map { $_ => ( stat $dir.'/'.$_ )[1] } qw( cert.pem key.pem );

  open my $reader, '<', $dir.'/cert.pem' or die $!;
  my $second = $issuer->issue( {%spec} );
  $target->deploy($second);

  is slurp( $dir.'/cert.pem' ), $second->cert, 'the new certificate is in place';
  is slurp( $dir.'/key.pem' ),  $second->key,  'the new key is in place';
  isnt( ( stat $dir.'/'.$_ )[1], $inode{$_}, $_.' is a new file (written aside, then renamed)' ) for qw( cert.pem key.pem );
  is do { local $/; <$reader> }, $bundle->cert, 'someone who had the old file open still reads all of the old one';
  is_deeply files_in($dir), [qw( cert.pem chain.pem fullchain.pem key.pem )], 'no temporary files left';
};

subtest 'a bundle without a key' => sub {
  my $target = target();
  my $dir    = $target->dir;
  $target->deploy($bundle);
  my $no_key = SICK::Bundle->new( cert => $issuer->issue( {%spec} )->cert );
  $target->deploy($no_key);
  is slurp( $dir.'/cert.pem' ), $no_key->cert, 'the certificate is replaced';
  is slurp( $dir.'/key.pem' ),  $bundle->key,  'the key that was there stays';

  my $fresh = target();
  $fresh->deploy($no_key);
  is_deeply files_in( $fresh->dir ), [qw( cert.pem chain.pem fullchain.pem )], 'no key.pem is made up';
};

subtest 'reload runs after the files are written' => sub {
  my $seen   = $tmp.'/seen-by-reload.pem';
  my $target = target();
  my $dir    = $target->dir;
  my $copy   = 'open my $in, q{<}, shift or exit 5; open my $out, q{>}, shift or exit 6; print {$out} <$in>';

  $target = target( dir => $dir, reload => [ $^X, '-e', $copy, $dir.'/fullchain.pem', $seen ] );
  $target->deploy($bundle);
  is slurp($seen), $bundle->fullchain, 'a reload given as a list saw the new files';

  unlink $seen;
  my $argument = q{it's "one" $argument; with * and spaces};
  my $echo = target( reload => [ $^X, '-e', 'open my $out, q{>}, shift; print {$out} shift', $seen, $argument ] );
  $echo->deploy($bundle);
  is slurp($seen), $argument, 'the elements of a list reach the program untouched by any shell';

  unlink $seen;
  my $shell = target();
  $shell = target( dir => $shell->dir, reload => 'cat "'.$shell->dir.'/cert.pem" > "'.$seen.'" && true' );
  $shell->deploy($bundle);
  is slurp($seen), $bundle->cert, 'a reload given as one string is a shell command';

  my $none = target( reload => q{} );
  ok eval { $none->deploy($bundle); 1 }, 'an empty reload is no reload';
};

subtest 'a failing reload fails the deployment' => sub {
  my $target = target( reload => [ $^X, '-e', 'print STDERR qq{service is down\n}; exit 3' ] );
  my $ok = eval { $target->deploy($bundle); 1 };
  ok !$ok, 'deploy dies';
  like $@, qr/^reload failed \(exit 3\): service is down/, '... with the exit code and the message of the command';
  is slurp( $target->dir.'/cert.pem' ), $bundle->cert, 'the files are in place all the same';

  $target = target( reload => 'exit 4' );
  $ok = eval { $target->deploy($bundle); 1 };
  ok !$ok, 'a failing shell command';
  like $@, qr/^reload failed \(exit 4\)/, '... reports its exit code';

  $target = target( reload => [ $tmp.'/no-such-program' ] );
  $ok = eval { $target->deploy($bundle); 1 };
  ok !$ok, 'a reload program that does not exist';
  like $@, qr/^cannot run '\Q$tmp\E\/no-such-program': \S/, '... is named';
};

subtest 'a directory that cannot be written' => sub {
  plan skip_all => 'root writes everywhere' unless $>;
  my $target = target();
  my $dir    = $target->dir;
  $target->deploy($bundle);
  chmod 0555, $dir or die 'chmod: '.$!;

  my $second = $issuer->issue( {%spec} );
  my $ok = eval { $target->deploy($second); 1 };
  my $error = $@;
  chmod 0755, $dir;

  ok !$ok, 'deploy dies';
  like $error, qr/^cannot write '\Q$dir\E\/key\.pem': \S/, '... with the file and the reason';
  unlike $error, qr/PRIVATE KEY/, '... and without the key';
  is slurp( $dir.'/cert.pem' ), $bundle->cert, 'the old certificate is untouched';
  is slurp( $dir.'/key.pem' ),  $bundle->key,  '... and so is the old key';
  is_deeply files_in($dir), [qw( cert.pem chain.pem fullchain.pem key.pem )], 'no temporary files left';
};

subtest 'presented_cert without a host is cert.pem' => sub {
  my $target = target();
  is $target->presented_cert, undef, 'nothing while there is no cert.pem';
  is_deeply [ $target->presented_cert ], [undef], '... one undef in list context, safe as a hash value';

  $target->deploy($bundle);
  my $presented = $target->presented_cert;
  isa_ok $presented, 'SICK::Bundle';
  is $presented->fingerprint_sha256, $bundle->fingerprint_sha256, 'after deploy it is the deployed certificate';
  is $presented->key, undef, '... without the key';

  spew( $target->dir.'/cert.pem', "not a certificate\n" );
  is $target->presented_cert, undef, 'a cert.pem without a certificate is no certificate';

SKIP: {
    skip 'root reads every file', 2 unless $>;
    $target->deploy($bundle);
    chmod 0000, $target->dir.'/cert.pem' or die 'chmod: '.$!;
    my $ok = eval { $target->presented_cert; 1 };
    ok !$ok, 'a cert.pem that cannot be read dies';
    like $@, qr/^unreachable: cannot read certificate file '\Q${\ $target->dir}\E\/cert\.pem': \S/, '... as unreachable';
    chmod 0644, $target->dir.'/cert.pem';
  }
};

subtest 'how long the new certificate may take to show' => sub {
  is target()->verify_timeout, 0, 'without a host there is nothing to wait for: the file is there or it is not';
  is target( host => '127.0.0.1' )->verify_timeout, 30, 'with a host the service gets the time every device gets';
};

subtest 'presented_cert with a host asks the host' => sub {
  my $listener = IO::Socket::INET->new( LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1 )
    or plan skip_all => 'cannot listen on 127.0.0.1: '.$!;
  my $port = $listener->sockport;
  close $listener;

  my $target = target( host => '127.0.0.1', port => $port );
  $target->deploy($bundle);
  my $ok = eval { $target->presented_cert; 1 };
  ok !$ok, 'cert.pem is there, but nobody listens on the port: dies';
  like $@, qr/^unreachable: 127\.0\.0\.1:$port: /, '... as unreachable, without looking at cert.pem';
};

subtest 'log' => sub {
  my @lines;
  my $target = target( log => sub { push @lines, @_ }, reload => [ $^X, '-e', '1' ] );
  $target->deploy($bundle);
  is scalar @lines, 2, 'two messages';
  like $lines[0], qr/^wrote cert\.pem, fullchain\.pem, chain\.pem, key\.pem to \Q${\ $target->dir}\E$/, 'what was written where';
  like $lines[1], qr/^running reload: /, 'that reload runs';
  unlike join( "\n", @lines ), qr/PRIVATE KEY/, 'no key material in the log';
};

subtest 'issue, deploy, decide' => sub {
  my $target = target();
  my %common = ( root_pem => $issuer->root_pem, now => time );

  my $before = SICK::Decision::evaluate( device => $target->device, presented => $target->presented_cert, %common );
  is_deeply [ @$before{qw( renew reason )} ], [ 1, 'missing' ], 'before: missing';

  $target->deploy( $issuer->issue( $target->device->spec ) );
  my $after = SICK::Decision::evaluate( device => $target->device, presented => $target->presented_cert, %common );
  is_deeply [ @$after{qw( renew reason )} ], [ 0, 'ok' ], 'after: ok';

  my $elsewhere = SICK::Issuer::SelfSigned->new( dir => $tmp.'/another-ca' );
  $target->deploy( $elsewhere->issue( $target->device->spec ) );
  my $foreign = SICK::Decision::evaluate( device => $target->device, presented => $target->presented_cert, %common );
  is_deeply [ @$foreign{qw( renew reason )} ], [ 1, 'foreign-ca' ], 'a certificate of another CA: foreign-ca';
};

done_testing;
