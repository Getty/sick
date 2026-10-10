#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use IO::Socket::INET;
use POSIX ();
use lib 't/lib';

use SICK::Bundle;
use SICK::Decision;
use SICK::Device;
use SICK::Issuer::SelfSigned;
use SICK::OpenSSL;
use SICK::Target;
use SICK::Target::Files;
use Path::Tiny ();
use Test::SICK::PKI qw( new_ca new_cert slurp spew );

# SICK::Target::Files with certificates of SICK::Issuer::SelfSigned: files
# on disk, their modes, the generations they are published as, the reload
# command and the rollback when it fails.

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

# the generation directories below dir/.sick, and where current and
# previous point
sub generations { return [] unless -d $_[0].'/.sick'; [ grep { !/\A\./ && -d $_[0].'/.sick/'.$_ && !-l $_[0].'/.sick/'.$_ } @{ files_in( $_[0].'/.sick' ) } ] }
sub current_of  { readlink $_[0].'/.sick/current' }
sub previous_of { readlink $_[0].'/.sick/previous' }

my @FOUR = qw( cert.pem chain.pem fullchain.pem key.pem );

# a reload command that counts its runs in $count and fails (exit 3, with a
# message) while the file $fail exists; with $once it removes $fail as it
# fails, so only the first run fails
sub counting_reload {
  my ( $count, $fail, $once ) = @_;
  my $code = 'open my $c, q{>>}, $ARGV[0] or exit 9; print {$c} qq{run\n}; close $c;'
    .' if ( -e $ARGV[1] ) { unlink $ARGV[1] if $ARGV[2]; print STDERR qq{service is down\n}; exit 3 } exit 0';
  return [ $^X, '-e', $code, $count, $fail, $once ? 1 : 0 ];
}
sub runs_in { -e $_[0] ? scalar( () = slurp( $_[0] ) =~ /^run$/mg ) : 0 }

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

subtest 'deploy publishes one generation' => sub {
  my $target = target();
  my $dir    = $target->dir;
  ok !-e $dir, 'the directory does not exist yet';

  is $target->deploy($bundle), undef, 'deploy returns nothing';
  is_deeply files_in($dir), [ '.sick', @FOUR ], 'the four names and .sick, no temporary files left';
  for my $name (@FOUR) {
    ok -l $dir.'/'.$name, $name.' is a symbolic link';
    is readlink( $dir.'/'.$name ), '.sick/current/'.$name, '... relative, to .sick/current/'.$name;
  }

  my $generation = current_of($dir);
  like $generation, qr/\A[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{8}\z/, '.sick/current names a generation: UTC time to the microsecond and short fingerprint';
  is substr( $generation, -8 ), substr( $bundle->fingerprint_sha256, 0, 8 ), '... the fingerprint of the certificate';
  is_deeply generations($dir), [$generation], 'one generation';
  is_deeply files_in( $dir.'/.sick/'.$generation ), [@FOUR], '... with the four files in it';
  is previous_of($dir), undef, 'no previous generation after the first deploy';

  is slurp( $dir.'/cert.pem' ),      $bundle->cert,      'cert.pem';
  is slurp( $dir.'/fullchain.pem' ), $bundle->fullchain, 'fullchain.pem';
  is slurp( $dir.'/key.pem' ),       $bundle->key,       'key.pem';
  is slurp( $dir.'/chain.pem' ),     q{},                'chain.pem is empty without a chain';

  is mode_of( $dir.'/key.pem' ), '0600', 'key.pem has mode 0600 (the file the link points to)';
  is mode_of( $dir.'/'.$_ ), '0644', $_.' has mode 0644' for qw( cert.pem chain.pem fullchain.pem );
  is mode_of( $dir.'/.sick' ), '0755', '.sick has mode 0755';
  is mode_of( $dir.'/.sick/'.$generation ), '0755', 'the generation directory has mode 0755';

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
  is_deeply files_in($dir), [ '.sick', @FOUR ], 'no temporary files left';
  is_deeply [ sort @{ generations($dir) } ], [ sort grep { defined } current_of($dir), previous_of($dir) ],
    '... and no generation but current and previous';
};

subtest 'a bundle without a key' => sub {
  my $target = target();
  my $dir    = $target->dir;
  $target->deploy($bundle);
  my $no_key = SICK::Bundle->new( cert => $issuer->issue( {%spec} )->cert );
  $target->deploy($no_key);
  is slurp( $dir.'/cert.pem' ), $no_key->cert, 'the certificate is replaced';
  is slurp( $dir.'/key.pem' ),  $bundle->key,  'the key that was there stays';
  ok -e $dir.'/.sick/'.current_of($dir).'/key.pem', '... carried over into the new generation';
  is mode_of( $dir.'/key.pem' ), '0600', '... with its mode';

  my $fresh = target();
  $fresh->deploy($no_key);
  is_deeply files_in( $fresh->dir ), [qw( .sick cert.pem chain.pem fullchain.pem )], 'no key.pem is made up';
  ok !-e $fresh->dir.'/.sick/'.current_of( $fresh->dir ).'/key.pem', '... not in the generation either';
  $fresh->deploy($bundle);
  is readlink( $fresh->dir.'/key.pem' ), '.sick/current/key.pem', 'a later bundle with a key gets its link';
  is slurp( $fresh->dir.'/key.pem' ), $bundle->key, '... to its key';
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

subtest 'a failing reload on the first deploy: nothing to go back to' => sub {
  my $target = target( reload => [ $^X, '-e', 'print STDERR qq{service is down\n}; exit 3' ] );
  my $ok = eval { $target->deploy($bundle); 1 };
  ok !$ok, 'deploy dies';
  like $@, qr/^reload failed \(exit 3\): service is down; there is no previous certificate to restore, the new one stays in place/,
    '... with the exit code, the message of the command and that nothing was restored';
  is slurp( $target->dir.'/cert.pem' ), $bundle->cert, 'the files are in place all the same';
  is scalar @{ generations( $target->dir ) }, 1, '... as the one generation';

  $target = target( reload => 'exit 4' );
  $ok = eval { $target->deploy($bundle); 1 };
  ok !$ok, 'a failing shell command';
  like $@, qr/^reload failed \(exit 4\); there is no previous certificate/, '... reports its exit code';

  $target = target( reload => [ $tmp.'/no-such-program' ] );
  $ok = eval { $target->deploy($bundle); 1 };
  ok !$ok, 'a reload program that does not exist';
  like $@, qr/^cannot run '\Q$tmp\E\/no-such-program': \S.*; there is no previous certificate/, '... is named';
};

subtest 'a failing reload goes back to the previous generation' => sub {
  my $runs   = $tmp.'/reload-count-'.++$count;
  my $fail   = $tmp.'/reload-fail-'.$count;
  my @lines;
  my $target = target( reload => counting_reload( $runs, $fail, 1 ), log => sub { push @lines, @_ } );
  my $dir    = $target->dir;

  $target->deploy($bundle);
  my $old = current_of($dir);
  is runs_in($runs), 1, 'the first deploy ran the reload once';

  my $second = $issuer->issue( {%spec} );
  spew( $fail, q{} );
  @lines = ();
  my $ok = eval { $target->deploy($second); 1 };
  my $error = $@;
  ok !$ok, 'deploy dies when the reload fails';
  like $error, qr/^reload failed \(exit 3\): service is down; restored the previous certificate \(generation \Q$old\E\) and ran the reload again/,
    '... saying that the reload failed and the previous certificate is back';
  is runs_in($runs), 3, 'the reload ran twice: for the new certificate, then for the old one';
  is current_of($dir), $old, '.sick/current points to the old generation again';
  is_deeply generations($dir), [$old], 'the new generation is gone';
  is slurp( $dir.'/cert.pem' ), $bundle->cert, 'cert.pem is the old certificate';
  is slurp( $dir.'/key.pem' ),  $bundle->key,  '... key.pem the old key';
  is $target->presented_cert->fingerprint_sha256, $bundle->fingerprint_sha256, 'presented_cert sees the old one';
  like join( "\n", @lines ), qr/^reload failed, going back to generation \Q$old\E$/m, 'the switch back is logged';
  unlike join( "\n", @lines ).$error, qr/PRIVATE KEY/, 'no key material in log or message';

  # a third deploy that fails keeps the second as previous of the first
  $target->deploy($second);
  my $new = current_of($dir);
  is previous_of($dir), $old, 'after a good deploy the old generation is the previous one';
  spew( $fail, q{} );
  ok !eval { $target->deploy( $issuer->issue( {%spec} ) ); 1 }, 'another failing reload';
  is current_of($dir), $new, '... goes back to the generation before it';
  is previous_of($dir), $old, '... and previous is what it was';
  is_deeply [ sort @{ generations($dir) } ], [ sort $old, $new ], '... the two generations stay';

  # a reload that fails for the old certificate as well
  spew( $fail, q{} );
  my $always = target( dir => $dir, reload => counting_reload( $runs, $fail, 0 ) );
  my $before = runs_in($runs);
  $ok = eval { $always->deploy( $issuer->issue( {%spec} ) ); 1 };
  $error = $@;
  unlink $fail;
  ok !$ok, 'a reload that fails both times';
  like $error, qr/^reload failed \(exit 3\): service is down; restored the previous certificate \(generation \Q$new\E\), but the reload after that failed as well: reload failed \(exit 3\): service is down/,
    '... reports the second failure too';
  is runs_in($runs) - $before, 2, '... and ran twice';
  is current_of($dir), $new, '... the old generation is current all the same';
};

subtest 'a directory that cannot be written' => sub {
  plan skip_all => 'root writes everywhere' unless $>;
  my $target = target();
  my $dir    = $target->dir;
  $target->deploy($bundle);
  my $old = current_of($dir);
  chmod 0555, $dir.'/.sick' or die 'chmod: '.$!;

  my $second = $issuer->issue( {%spec} );
  my $ok = eval { $target->deploy($second); 1 };
  my $error = $@;
  chmod 0755, $dir.'/.sick';

  ok !$ok, 'deploy dies';
  like $error, qr/^cannot create directory '\Q$dir\E\/\.sick\/[^']+': \S/, '... with the directory and the reason';
  unlike $error, qr/PRIVATE KEY/, '... and without the key';
  is slurp( $dir.'/cert.pem' ), $bundle->cert, 'the old certificate is untouched';
  is slurp( $dir.'/key.pem' ),  $bundle->key,  '... and so is the old key';
  is current_of($dir), $old, '... and current';
  is_deeply files_in($dir), [ '.sick', @FOUR ], 'no temporary files left';
  is_deeply files_in( $dir.'/.sick' ), [ sort 'current', $old ], '... in .sick either';

  my $locked = target();
  Path::Tiny::path( $locked->dir )->mkdir;
  chmod 0555, $locked->dir or die 'chmod: '.$!;
  $ok = eval { $locked->deploy($bundle); 1 };
  $error = $@;
  chmod 0755, $locked->dir;
  ok !$ok, 'a directory without .sick that cannot be written';
  like $error, qr/^cannot create directory '\Q${\ $locked->dir}\E\/\.sick': \S/, '... names .sick';
};

subtest 'plain files of an earlier SICK become the previous generation' => sub {
  my $target = target();
  my $dir    = $target->dir;
  Path::Tiny::path($dir)->mkdir;
  spew( $dir.'/cert.pem',      $bundle->cert );
  spew( $dir.'/chain.pem',     q{} );
  spew( $dir.'/fullchain.pem', $bundle->fullchain );
  spew( $dir.'/key.pem',       $bundle->key );
  chmod 0600, $dir.'/key.pem';
  chmod 0644, map { $dir.'/'.$_ } qw( cert.pem chain.pem fullchain.pem );

  my @lines;
  my $runs  = $tmp.'/reload-count-'.++$count;
  my $fail  = $tmp.'/reload-fail-'.$count;
  $target = target( dir => $dir, log => sub { push @lines, @_ }, reload => counting_reload( $runs, $fail, 1 ) );
  my $second = $issuer->issue( {%spec} );
  $target->deploy($second);

  is readlink( $dir.'/'.$_ ), '.sick/current/'.$_, $_.' is now a link' for @FOUR;
  is slurp( $dir.'/cert.pem' ), $second->cert, 'to the new certificate';
  is slurp( $dir.'/key.pem' ),  $second->key,  '... and its key';
  my $migrated = previous_of($dir);
  like $migrated, qr/\A[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{8}\z/, 'the plain files are the previous generation';
  is slurp( $dir.'/.sick/'.$migrated.'/key.pem' ), $bundle->key, '... with the old key';
  is mode_of( $dir.'/.sick/'.$migrated.'/key.pem' ), '0600', '... in its mode';
  like $lines[0], qr/^moved cert\.pem, chain\.pem, fullchain\.pem, key\.pem of an earlier SICK into generation \Q$migrated\E, \Q$dir\E now links to \.sick\/current$/,
    'the move is logged';

  # the same with a reload that fails: back to the plain files' content
  my $again = target();
  my $odir  = $again->dir;
  Path::Tiny::path($odir)->mkdir;
  spew( $odir.'/'.$_, slurp( $dir.'/.sick/'.$migrated.'/'.$_ ) ) for @FOUR;
  chmod 0600, $odir.'/key.pem';
  $again = target( dir => $odir, reload => counting_reload( $runs, $fail, 1 ) );
  spew( $fail, q{} );
  ok !eval { $again->deploy($second); 1 }, 'a failing reload right after the move';
  like $@, qr/; restored the previous certificate \(generation /, '... restores';
  is slurp( $odir.'/cert.pem' ), $bundle->cert, '... the certificate of the plain files';
  is slurp( $odir.'/key.pem' ),  $bundle->key,  '... and their key';
};

subtest 'at most two generations remain' => sub {
  my $target = target();
  my $dir    = $target->dir;
  my @seen;
  for ( 1 .. 4 ) {
    $target->deploy($bundle);    # the same certificate, within the same second
    push @seen, current_of($dir);
  }
  is scalar( keys %{ { map { $_ => 1 } @seen } } ), 4, 'every deploy is a generation of its own, also with the same certificate';
  is_deeply [ sort @{ generations($dir) } ], [ sort @seen[ 2, 3 ] ], 'the last two remain';
  is current_of($dir),  $seen[3], 'current is the last';
  is previous_of($dir), $seen[2], 'previous the one before';
};

subtest 'a reader never sees a key that is not its certificate' => sub {
  my @bundles = map { $issuer->issue( {%spec} ) } 1 .. 3;
  my %key_of  = map { $_->cert => $_->key } @bundles;
  my $target  = target();
  my $dir     = $target->dir;
  $target->deploy( $bundles[0] );

  my $report = $tmp.'/reader-'.++$count;
  my $stop   = $report.'.stop';
  my $pid    = fork;
  die 'fork: '.$! unless defined $pid;
  unless ($pid) {
    # the reader: resolve the generation once (through cert.pem), read
    # certificate and key from it, and compare
    my ( $reads, $mixed, $gone ) = ( 0, 0, 0 );
    until ( -e $stop ) {
      my $from = eval { Path::Tiny::path( $dir.'/cert.pem' )->realpath->parent->stringify };
      my ( $cert, $key );
      if ( defined $from && open( my $c, '<', $from.'/cert.pem' ) && open( my $k, '<', $from.'/key.pem' ) ) {
        local $/;
        ( $cert, $key ) = ( scalar <$c>, scalar <$k> );
      }
      unless ( defined $key ) { $gone++; next }    # a generation removed while being read
      $reads++;
      $mixed++ unless exists $key_of{$cert} && $key_of{$cert} eq $key;
    }
    open my $out, '>', $report or POSIX::_exit(1);
    print {$out} join( q{ }, $reads, $mixed, $gone );
    close $out;
    POSIX::_exit(0);
  }

  $target->deploy( $bundles[ $_ % 3 ] ) for 1 .. 30;
  spew( $stop, q{} );
  waitpid $pid, 0;
  my ( $reads, $mixed, $gone ) = split / /, slurp($report);
  cmp_ok $reads, '>', 30, 'the reader read while 30 deploys happened ('.$reads.' times)';
  is $mixed, 0, 'never a key beside a certificate it does not belong to';
  note $gone.' reads found their generation removed and tried again';
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
  like $lines[0], qr/^wrote cert\.pem, fullchain\.pem, chain\.pem, key\.pem to \Q${\ $target->dir}\E as generation [0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{8}$/, 'what was written where';
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
