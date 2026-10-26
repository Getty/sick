#!/usr/bin/env perl
# k8s/test carries copies of two files of docker/, because a kustomization
# reads nothing above its own directory. They must not drift apart.
use strict;
use warnings;
use Path::Tiny qw( path );
use Test::More;

for my $pair (
  [ 'docker/init-ca.sh',        'k8s/test/init-ca.sh' ],
  [ 'docker/trust-httpd.conf',  'k8s/test/trust-httpd.conf' ],
) {
  my ( $original, $copy ) = @$pair;
SKIP: {
    skip "$original is not in this tree", 1 unless -f $original && -f $copy;
    is path($copy)->slurp_raw, path($original)->slurp_raw, "$copy is $original";
  }
}

done_testing;
