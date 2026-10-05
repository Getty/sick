#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use SICK::Duration;

# SICK::Duration::parse turns the durations of the device list into seconds.

subtest 'every unit' => sub {
  is SICK::Duration::parse('30d'), 30 * 86400, 'days';
  is SICK::Duration::parse('12h'), 12 * 3600,  'hours';
  is SICK::Duration::parse('45m'), 45 * 60,    'minutes';
  is SICK::Duration::parse('90s'), 90,         'seconds';
  is SICK::Duration::parse('3600'), 3600, 'a bare number is seconds';
  is SICK::Duration::parse('397d'), 34300800, 'the default lifetime of the spec';
  is SICK::Duration::parse('0'), 0, 'zero is a duration';
};

subtest 'invalid input dies with the input in the message' => sub {
  for my $bad ( '', ' ', '30 d', '30x', 'd', '-5d', '1.5h', '1d12h', '30D', '0x10', "30d\n", ' 30d' ) {
    my $ok = eval { SICK::Duration::parse($bad); 1 };
    my $shown = $bad;
    $shown =~ s/\n/\\n/g;
    ok !$ok, 'dies for "'.$shown.'"';
    like $@, qr/^invalid duration '\Q$bad\E'/, '... and names the input';
  }

  my $ok = eval { SICK::Duration::parse(undef); 1 };
  ok !$ok, 'dies for undef';
  like $@, qr/^invalid duration ''/, '... as an empty input';

  $ok = eval { SICK::Duration::parse( [] ); 1 };
  ok !$ok, 'dies for a reference';
  like $@, qr/^invalid duration /, '... with the same message';
};

done_testing;
