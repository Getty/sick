#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

for (qw(
  SICK
  SICK::Bundle
  SICK::CLI
  SICK::Command
  SICK::Config
  SICK::Decision
  SICK::Device
  SICK::Duration
  SICK::Issuer
  SICK::Issuer::SelfSigned
  SICK::Issuer::StepCA
  SICK::Names
  SICK::OpenSSL
  SICK::Runner
  SICK::Target
  SICK::Target::Acmesh
  SICK::Target::Files
  SICK::Temp
  SICK::Trust
)) {
  use_ok($_);
}

is( SICK->VERSION, SICK::Config->VERSION, 'every module carries the version of the distribution' );

done_testing;
