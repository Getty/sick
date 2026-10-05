#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Path qw( make_path );
use File::Temp qw( tempdir );

use SICK::Device;
use SICK::Target;

# SICK::Target: from the type of a device to a class, and what the base
# class gives every target. The plugin modules are written here, into a
# temporary directory that is put into @INC.

my $tmp = tempdir( CLEANUP => 1 );
make_path( $tmp.'/SICK/Target/CiscoSB' );

my %module = (
  'CiscoSB.pm' => <<'PERL',
package SICK::Target::CiscoSB;
use strict;
use warnings;
use parent 'SICK::Target';
sub required_options { qw( credentials ) }
sub optional_options { qw( slot ) }
sub deploy { 'deployed by CiscoSB' }
1;
PERL
  'CiscoSB/Session.pm' => <<'PERL',
package SICK::Target::CiscoSB::Session;
use strict;
use warnings;
sub deploy { 'not a target at all' }
1;
PERL
  'NoDeploy.pm' => <<'PERL',
package SICK::Target::NoDeploy;
use strict;
use warnings;
use parent 'SICK::Target';
1;
PERL
  'NotATarget.pm' => <<'PERL',
package SICK::Target::NotATarget;
use strict;
use warnings;
sub new    { bless {}, shift }
sub deploy { 1 }
1;
PERL
  'Broken.pm' => <<'PERL',
package SICK::Target::Broken;
use strict;
use warnings;
this is not perl (
1;
PERL
);
for my $name ( keys %module ) {
  open my $fh, '>', $tmp.'/SICK/Target/'.$name or die 'cannot write '.$name.': '.$!;
  print {$fh} $module{$name};
  close $fh or die $!;
}
unshift @INC, $tmp;

sub device {
  my ( %arg ) = @_;
  return SICK::Device->new(
    name         => 'box',
    type         => 'cisco-sb',
    names        => [ 'box.example.internal', '192.0.2.5' ],
    lifetime     => 86400,
    renew_before => 3600,
    key          => 'rsa2048',
    %arg,
  );
}

subtest 'a type finds its class' => sub {
  ok !$INC{'SICK/Target/CiscoSB.pm'}, 'the plugin is not loaded yet';
  is( SICK::Target->class_for('cisco-sb'), 'SICK::Target::CiscoSB', 'cisco-sb finds SICK::Target::CiscoSB' );
  ok $INC{'SICK/Target/CiscoSB.pm'}, '... and loads it';
  is( SICK::Target->class_for($_), 'SICK::Target::CiscoSB', 'so does '.$_ )
    for 'CiscoSB', 'ciscosb', 'cisco_sb', 'Cisco-SB', 'CISCO SB';
  ok( SICK::Target::CiscoSB->isa('SICK::Target'), 'the class is a SICK::Target' );

  # Only letters and digits of a type count, and the type is only ever
  # compared with the names of modules that exist: it is never part of a path.
  is( SICK::Target->class_for('../Cisco/SB'), 'SICK::Target::CiscoSB', 'a type with path characters is just its letters' );

  is( SICK::Target->class_for('files'), 'SICK::Target::Files', 'the built-in files target' );

  {
    package SICK::Target::InMemory;
    our @ISA = ('SICK::Target');
    sub deploy { 1 }
    $INC{'SICK/Target/InMemory.pm'} = __FILE__;
  }
  is( SICK::Target->class_for('in-memory'), 'SICK::Target::InMemory', 'a class that is already loaded needs no file' );
};

subtest 'no class for a type' => sub {
  my $ok = eval { SICK::Target->class_for('juniper-ex'); 1 };
  ok !$ok, 'dies';
  like $@,
    qr/^no target for type 'juniper-ex'; install a SICK-Target-\* distribution that provides it/,
    '... and says what to install';

  for my $type ( 'cisco-sb-session', 'ciscosb/session', 'cisco', '---', '../Target', 'Target' ) {
    $ok = eval { SICK::Target->class_for($type); 1 };
    ok !$ok, 'no target for "'.$type.'"';
    like $@, qr/^no target for type '\Q$type\E'/, '... with the type as written';
  }

  for my $type ( undef, q{} ) {
    $ok = eval { SICK::Target->class_for($type); 1 };
    ok !$ok, 'dies without a type';
    like $@, qr/^class_for needs a device type/, '... saying so';
  }
};

subtest 'classes that are no targets are rejected' => sub {
  my $ok = eval { SICK::Target->class_for('no-deploy'); 1 };
  ok !$ok, 'a class without deploy is rejected';
  like $@, qr/^SICK::Target::NoDeploy \(type 'no-deploy'\) does not implement deploy/, '... by name';

  $ok = eval { SICK::Target->class_for('not-a-target'); 1 };
  ok !$ok, 'a class that is no SICK::Target is rejected';
  like $@, qr/^SICK::Target::NotATarget \(type 'not-a-target'\) is not a SICK::Target/, '... by name';

  $ok = eval { SICK::Target->class_for('broken'); 1 };
  ok !$ok, 'a module that does not compile is rejected';
  like $@, qr/^cannot load SICK::Target::Broken for type 'broken': \S/, '... with the reason';
};

subtest 'new, device, option and log' => sub {
  my @lines;
  my $device = device( options => { credentials => '/etc/sick/box.cred', slot => '2' } );
  my $target = SICK::Target::CiscoSB->new( device => $device, log => sub { push @lines, @_ } );
  isa_ok $target, 'SICK::Target::CiscoSB';
  is $target->device, $device, 'device';
  is $target->option('slot'), '2',   'option';
  is $target->option('nope'), undef, 'an option that is not set';
  is $target->deploy, 'deployed by CiscoSB', 'deploy is the one of the subclass';

  $target->log('first');
  $target->log('second');
  is_deeply \@lines, [ 'first', 'second' ], 'log hands every message to the callback';

  my $quiet = SICK::Target::CiscoSB->new( device => $device );
  is $quiet->log('nobody listens'), undef, 'log without a callback is silent';

  my $ok = eval { SICK::Target::CiscoSB->new; 1 };
  ok !$ok, 'new dies without a device';
  like $@, qr/^SICK::Target::CiscoSB->new needs a device/, '... saying so';
  $ok = eval { SICK::Target::CiscoSB->new( device => $device, log => 'print' ); 1 };
  ok !$ok, 'new dies when log is no code reference';
};

subtest 'defaults of the base class' => sub {
  my $target = SICK::Target::CiscoSB->new( device => device( options => { credentials => 'x' } ) );
  is $target->csr( { names => ['box.example.internal'], lifetime => 60 } ), undef, 'csr is undef: the key is made by SICK';
  is_deeply [ $target->csr( {} ) ], [undef], '... one undef in list context, safe as a hash value';
  is $target->connect_timeout, 10, 'the time limit for the device is 10 seconds';
  is $target->verify_timeout,  30, 'a device gets 30 seconds to present a new certificate';

  is_deeply [ $target->endpoint ], [ 'box.example.internal', 443 ], 'endpoint without host: the first name, port 443';
  my $with_host = SICK::Target::CiscoSB->new( device => device( host => '192.0.2.5', port => 8443 ) );
  is_deeply [ $with_host->endpoint ], [ '192.0.2.5', 8443 ], 'endpoint with host and port';

  my $base = SICK::Target->new( device => device() );
  my $ok = eval { $base->deploy; 1 };
  ok !$ok, 'deploy of the base class dies';
  like $@, qr/^SICK::Target does not implement deploy/, '... saying so';
};

subtest 'validate' => sub {
  my $good = SICK::Target::CiscoSB->new( device => device( options => { credentials => '/etc/sick/box.cred', slot => '1' } ) );
  is $good->validate, $good, 'valid options: validate returns the target';

  my $ok = eval { SICK::Target::CiscoSB->new( device => device( options => { slot => '1' } ) )->validate; 1 };
  ok !$ok, 'a missing required option dies';
  like $@, qr/^devices\.box: missing 'credentials'/, '... with its place in the device list';

  $ok = eval { SICK::Target::CiscoSB->new( device => device( options => { credentials => q{} } ) )->validate; 1 };
  ok !$ok, 'an empty required option is a missing one';
  like $@, qr/^devices\.box: missing 'credentials'/, '... with the same message';

  $ok = eval { SICK::Target::CiscoSB->new( device => device( options => { credentials => 'x', colour => 'blue' } ) )->validate; 1 };
  ok !$ok, 'an unknown option dies';
  like $@, qr/^devices\.box: unknown key 'colour' for type 'cisco-sb'/, '... with its place and the type';

  $ok = eval {
    SICK::Target::CiscoSB->new( device => device( options => { credentials => 'x', zebra => 1, colour => 2 } ) )->validate;
    1;
  };
  like $@, qr/^devices\.box: unknown keys 'colour', 'zebra' for type 'cisco-sb'/, 'several unknown options, sorted';
};

done_testing;
