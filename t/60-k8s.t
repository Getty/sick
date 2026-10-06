#!/usr/bin/env perl
# k8s/test carries copies of two files of docker/, because a kustomization
# reads nothing above its own directory. They must not drift apart.
use strict;
use warnings;
use Test::More;

sub slurp {
  my ($file) = @_;
  open my $fh, '<:raw', $file or die "$file: $!";
  local $/;
  return scalar <$fh>;
}

for my $pair (
  [ 'docker/init-ca.sh',        'k8s/test/init-ca.sh' ],
  [ 'docker/trust-httpd.conf',  'k8s/test/trust-httpd.conf' ],
) {
  my ( $original, $copy ) = @$pair;
SKIP: {
    skip "$original is not in this tree", 1 unless -f $original && -f $copy;
    is slurp($copy), slurp($original), "$copy is $original";
  }
}

done_testing;
