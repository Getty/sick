#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );

use SICK::Config;

# SICK::Config: the device list. No openssl, no network.

my $tmp     = tempdir( CLEANUP => 1 );
my $example = 't/fixtures/sick.example.yml';

sub write_file {
  my ( $name, $content ) = @_;
  my $path = $tmp.'/'.$name;
  open my $fh, '>', $path or die 'cannot write '.$path.': '.$!;
  print {$fh} $content;
  close $fh or die 'cannot write '.$path.': '.$!;
  return $path;
}

# load a list that has to fail and return the message
sub error_of {
  my ( $yaml ) = @_;
  my $ok = eval { SICK::Config->load_string( $yaml, 'list.yml' ); 1 };
  return $ok ? undef : $@;
}

my $minimal = <<'YAML';
devices:
  web:
    type: files
    names: [web.example.internal]
YAML

subtest 'the example of the design document loads' => sub {
  my $config = SICK::Config->load($example);
  isa_ok $config, 'SICK::Config';
  is $config->path, $example, 'path';

  is_deeply $config->ca,
    {
      url           => 'https://ca.example.internal:9000',
      root          => '/etc/sick/root_ca.crt',
      provisioner   => 'sick',
      password_file => '/etc/sick/provisioner.pw'
    },
    'ca as written';
  is_deeply $config->defaults, { lifetime => 397 * 86400, renew_before => 30 * 86400, key => 'rsa2048' },
    'defaults with durations in seconds';

  my @devices = $config->devices;
  is_deeply [ map { $_->name } @devices ], [qw( switch router grafana )], 'devices in the order of the file';
  isa_ok $_, 'SICK::Device' for @devices;

  my $switch = $config->device('switch');
  is $switch, $devices[0], 'device by name is the same object';
  is $switch->name, 'switch',      'name';
  is $switch->type, 'cisco-sb',    'type';
  is $switch->host, '192.0.2.199', 'host';
  is $switch->port, 443,           'port defaults to 443';
  is_deeply $switch->names, [ 'switch.example.internal', 'switch.hq.example.org', '192.0.2.199' ],
    'names: lower case, order of the list';
  is $switch->lifetime,     397 * 86400, 'lifetime from the defaults, in seconds';
  is $switch->renew_before, 30 * 86400,  'renew_before from the defaults, in seconds';
  is $switch->key,          'rsa2048',   'key from the defaults';
  is_deeply $switch->options, { credentials => '/etc/sick/switch.cred' }, 'type-specific keys are the options';
  is $switch->path, 'devices.switch', 'path for messages';
  is_deeply $switch->spec,
    { names => [ 'switch.example.internal', 'switch.hq.example.org', '192.0.2.199' ], lifetime => 397 * 86400, key => 'rsa2048' },
    'spec for an issuer';

  my $router = $config->device('router');
  is $router->host, undef, 'no host when the entry has none';
  is_deeply $router->options,
    {
      hook      => 'routeros',
      env       => { ROUTER_OS_HOST => 'router.example.internal', ROUTER_OS_USERNAME => 'sick' },
      env_files => { ROUTER_OS_PASSWORD => '/etc/sick/router.pw' }
    },
    'nested options survive';

  is_deeply $config->device('grafana')->options, { dir => '/srv/certs/grafana', reload => 'docker restart grafana' },
    'options of the files device';

  is $config->device('nobody'), undef, 'an unknown device is undef';
  is $config->device(undef),    undef, '... and so is no name';
  is_deeply [ $config->device('nobody') ], [undef], '... one undef in list context';
};

subtest 'defaults and what devices override' => sub {
  my $config = SICK::Config->load_string( <<'YAML', 'list.yml' );
defaults:
  lifetime: 90d
  key: ec256
devices:
  plain:
    type: files
    names: [plain.example.internal]
  special:
    type: files
    host: Special.Example.Internal
    port: 8443
    names: [special.example.internal]
    lifetime: 12h
    renew_before: 45m
    key: rsa4096
    mode_key: 0640
YAML
  is_deeply $config->defaults, { lifetime => 90 * 86400, renew_before => 30 * 86400, key => 'ec256' },
    'given defaults on top of the built-in ones';
  is_deeply $config->ca, {}, 'no ca section is an empty one';

  my $plain = $config->device('plain');
  is $plain->lifetime,     90 * 86400, 'lifetime from defaults';
  is $plain->renew_before, 30 * 86400, 'renew_before built in';
  is $plain->key,          'ec256',    'key from defaults';

  my $special = $config->device('special');
  is $special->lifetime,     12 * 3600,                  'device overrides lifetime';
  is $special->renew_before, 45 * 60,                    'device overrides renew_before';
  is $special->key,          'rsa4096',                  'device overrides key';
  is $special->host,         'special.example.internal', 'host is lower case';
  is $special->port,         8443,                       'port';
  is_deeply $special->options, { mode_key => '0640' }, 'scalars stay text: 0640 keeps its zero';

  my $built_in = SICK::Config->load_string( $minimal, 'list.yml' );
  is_deeply $built_in->defaults, { lifetime => 397 * 86400, renew_before => 30 * 86400, key => 'rsa2048' },
    'built-in defaults without a defaults section';
};

subtest 'names' => sub {
  my $config = SICK::Config->load_string( <<'YAML', 'list.yml' );
devices:
  mixed:
    type: files
    names: [Zeta.Example.Internal, 2001:DB8:0:0:0:0:0:1, alpha.example.internal, ZETA.example.internal, '*.wild.example.internal']
YAML
  is_deeply $config->device('mixed')->names,
    [ 'zeta.example.internal', '2001:db8::1', 'alpha.example.internal', '*.wild.example.internal' ],
    'lower case, IPv6 in short form, duplicates dropped, order kept';
};

subtest 'a device without type or names is an error with its place' => sub {
  like error_of("devices:\n  ant:\n    names: [ant.example.internal]\n"),
    qr/^list\.yml: devices\.ant: missing 'type'/, 'missing type';
  like error_of("devices:\n  ant:\n    type:\n    names: [ant.example.internal]\n"),
    qr/^list\.yml: devices\.ant: missing 'type'/, 'empty type';
  like error_of("devices:\n  ant:\n    type: files\n"),
    qr/^list\.yml: devices\.ant: missing 'names'/, 'missing names';
  like error_of("devices:\n  ant:\n    type: files\n    names: []\n"),
    qr/^list\.yml: devices\.ant: missing 'names'/, 'empty names';
  like error_of("devices:\n  ant:\n    type: files\n    names:\n"),
    qr/^list\.yml: devices\.ant: missing 'names'/, 'names without a value';
  like error_of("devices:\n  ant:\n    type: files\n    names: ant.example.internal\n"),
    qr/^list\.yml: devices\.ant\.names: must be a list/, 'names that are no list';
  like error_of("devices:\n  ant: files\n"),
    qr/^list\.yml: devices\.ant: must be a mapping/, 'a device that is no mapping';

  my $path = write_file( 'broken.yml', "devices:\n  ant:\n    names: [ant.example.internal]\n" );
  my $ok = eval { SICK::Config->load($path); 1 };
  ok !$ok, 'load dies as well';
  like $@, qr/^\Q$path\E: devices\.ant: missing 'type'/, '... and names the file';
};

subtest 'unknown keys are errors' => sub {
  like error_of( "colour: blue\n".$minimal ), qr/^list\.yml: unknown key 'colour'/, 'at the top level';
  like error_of( "ca:\n  url: https://ca.example.internal\n  colour: blue\n".$minimal ),
    qr/^list\.yml: ca: unknown key 'colour'/, 'in ca';
  like error_of( "defaults:\n  colour: blue\n".$minimal ),
    qr/^list\.yml: defaults: unknown key 'colour'/, 'in defaults';
  like error_of( "defaults:\n  port: 8443\n".$minimal ),
    qr/^list\.yml: defaults: unknown key 'port'/, 'a device key is not a default';
  like error_of( "zebra: 1\ncolour: blue\n".$minimal ),
    qr/^list\.yml: unknown keys 'colour', 'zebra'/, 'several at once, sorted';

  my $config = SICK::Config->load_string( "ca:\n  type: selfsigned\n  dir: /var/lib/sick/ca\n  step: /opt/step\n".$minimal, 'list.yml' );
  is_deeply $config->ca, { type => 'selfsigned', dir => '/var/lib/sick/ca', step => '/opt/step' },
    'type, dir and step are known in ca';
};

subtest 'invalid values' => sub {
  my $device = "devices:\n  ant:\n    type: files\n    names: [ant.example.internal]\n";

  like error_of( $device."    lifetime: soon\n" ),
    qr/^list\.yml: devices\.ant\.lifetime: invalid duration 'soon'/, 'device lifetime';
  like error_of( $device."    renew_before: 1w\n" ),
    qr/^list\.yml: devices\.ant\.renew_before: invalid duration '1w'/, 'device renew_before';
  like error_of( "defaults:\n  lifetime: forever\n".$device ),
    qr/^list\.yml: defaults\.lifetime: invalid duration 'forever'/, 'default lifetime';
  like error_of( $device."    key: rsa1024\n" ),
    qr/^list\.yml: devices\.ant\.key: invalid key type 'rsa1024'/, 'device key';
  like error_of( "defaults:\n  key: dsa\n".$device ),
    qr/^list\.yml: defaults\.key: invalid key type 'dsa'/, 'default key';
  like error_of( $device."    lifetime: 0\n" ),
    qr/^list\.yml: devices\.ant\.lifetime: must be longer than zero/, 'lifetime of zero';
  like error_of( $device."    lifetime: 10d\n    renew_before: 10d\n" ),
    qr/^list\.yml: devices\.ant: 'renew_before' must be shorter than 'lifetime'/, 'renew_before not below lifetime';
  like error_of( $device."    port: 70000\n" ), qr/^list\.yml: devices\.ant\.port: invalid port '70000'/, 'port out of range';
  like error_of( $device."    port: https\n" ), qr/^list\.yml: devices\.ant\.port: invalid port 'https'/, 'port that is no number';
  like error_of( $device."    host: 'two words'\n" ), qr/^list\.yml: devices\.ant\.host: invalid host 'two words'/, 'host';
  like error_of("devices:\n  ant:\n    type: ../evil\n    names: [ant.example.internal]\n"),
    qr/^list\.yml: devices\.ant\.type: invalid type/, 'type with a path in it';

  for my $bad ( 'two words', 'a,b', 'semi;colon', 'slash/name', '-lead.example', '999.1.1.1', 'new\nline' ) {
    like error_of("devices:\n  ant:\n    type: files\n    names: [ok.example.internal, \"$bad\"]\n"),
      qr/^list\.yml: devices\.ant\.names: invalid name '/, 'name '.$bad;
  }

  like error_of("ca:\n  url: [a, b]\n".$minimal), qr/^list\.yml: ca\.url: must be a plain value/, 'a list as ca value';
  like error_of("ca: nope\n".$minimal),           qr/^list\.yml: ca: must be a mapping/,          'ca that is no mapping';
  like error_of("devices: nope\n"),               qr/^list\.yml: devices: must be a mapping/,     'devices that is no mapping';
};

subtest 'files that are no device list' => sub {
  like error_of("- a\n- b\n"), qr/^list\.yml: must be a mapping with the keys ca, defaults, devices/, 'a list';
  like error_of(q{}), qr/^list\.yml: must contain exactly one YAML document/, 'an empty file';
  like error_of("--- {}\n--- {}\n"), qr/^list\.yml: must contain exactly one YAML document/, 'two documents';
  like error_of("devices: [unclosed\n"), qr/^list\.yml: invalid YAML: \S/, 'broken YAML';
  unlike error_of("devices: [unclosed\n"), qr/YAML\/PP/, '... without the innards of the parser';
  like error_of("devices:\n  ant:\n    type: files\n    names: [a.example]\n  ant:\n    type: files\n    names: [b.example]\n"),
    qr/^list\.yml: invalid YAML: .*[Dd]uplicate/, 'the same device twice';

  my $config = SICK::Config->load_string( "devices:\n", 'list.yml' );
  is scalar( () = $config->devices ), 0, 'an empty devices section is no device';

  my $missing = $tmp.'/no-such-list.yml';
  my $ok = eval { SICK::Config->load($missing); 1 };
  ok !$ok, 'a missing file dies';
  like $@, qr/^cannot read config file '\Q$missing\E': \S/, '... with path and reason';

  $ok = eval { SICK::Config->load($tmp); 1 };
  ok !$ok, 'a directory dies';
  like $@, qr/^cannot read config file '\Q$tmp\E': Is a directory/, '... saying so';
};

subtest 'read_secret' => sub {
  my $marker = 'placeholder-'.$$.'-not-a-real-secret';

  is( SICK::Config->read_secret( write_file( 'one.pw', $marker."\n" ) ), $marker, 'first line without its line end' );
  is( SICK::Config->read_secret( write_file( 'bare.pw', $marker ) ), $marker, 'no line end at all' );
  is( SICK::Config->read_secret( write_file( 'crlf.pw', $marker."\r\n" ) ), $marker, 'CRLF line end' );
  is( SICK::Config->read_secret( write_file( 'two.pw', "user\n".$marker."\n" ) ), 'user', 'only the first line' );
  is( SICK::Config->read_secret( write_file( 'space.pw', ' '.$marker." \n" ) ), ' '.$marker.' ', 'spaces belong to the secret' );
  is( SICK::Config->read_secret( write_file( 'empty.pw', q{} ) ), q{}, 'an empty file is an empty secret' );

  my $config = SICK::Config->load_string( $minimal, 'list.yml' );
  is $config->read_secret( $tmp.'/one.pw' ), $marker, 'works on an object';

  my $missing = $tmp.'/missing.pw';
  my $ok = eval { SICK::Config->read_secret($missing); 1 };
  ok !$ok, 'a missing file dies';
  like $@, qr/^cannot read secret file '\Q$missing\E': \S/, '... with path and reason';
  unlike $@, qr/\n.*\n/s, '... on one line, no stack trace';

  $ok = eval { SICK::Config->read_secret($tmp); 1 };
  ok !$ok, 'a directory dies';
  like $@, qr/^cannot read secret file '\Q$tmp\E': Is a directory/, '... saying so';

SKIP: {
    skip 'root reads every file', 3 unless $>;
    my $locked = write_file( 'locked.pw', $marker."\n" );
    chmod 0000, $locked or die 'chmod: '.$!;
    $ok = eval { SICK::Config->read_secret($locked); 1 };
    ok !$ok, 'an unreadable file dies';
    like $@, qr/^cannot read secret file '\Q$locked\E': \S/, '... with path and reason';
    unlike $@, qr/\Q$marker\E/, '... and without its content';
    chmod 0600, $locked;
  }
};

done_testing;
