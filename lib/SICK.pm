package SICK;
# ABSTRACT: Ship internal certificates and keys to devices that cannot fetch them themselves

use strict;
use warnings;

our $VERSION = '0.001';

=head1 SYNOPSIS

A device list is the whole configuration:

    ca:
      url: https://ca.example.internal:9000
      root: /etc/sick/root_ca.crt
      provisioner: sick
      password_file: /etc/sick/provisioner.pw
    defaults:
      lifetime: 397d
      renew_before: 30d
      key: rsa2048
    devices:
      switch:
        type: cisco-sb                  # SICK::Target::CiscoSB, its own distribution
        host: 192.0.2.199
        names: [switch.example.internal, 192.0.2.199]
        credentials: /etc/sick/switch.cred
      grafana:
        type: files                     # built in
        names: [grafana.example.internal]
        dir: /srv/certs/grafana
        reload: "docker restart grafana"

The parts, used by hand:

    use SICK::Config;
    use SICK::Decision;
    use SICK::Issuer::StepCA;
    use SICK::Target;

    my $config = SICK::Config->load('/etc/sick/sick.yml');
    my $issuer = SICK::Issuer::StepCA->new( %{ $config->ca } );

    for my $device ( $config->devices ) {
      my $target = SICK::Target->class_for( $device->type )->new( device => $device );
      $target->validate;

      my $decision = SICK::Decision::evaluate(
        device    => $device,
        presented => $target->presented_cert,
        root_pem  => $issuer->root_pem,
      );
      next unless $decision->{renew};

      $target->deploy( $issuer->issue( $device->spec ) );
    }

=head1 DESCRIPTION

SICK - I<Ship Internal Certificates & Keys> - brings certificates of an
internal certificate authority to devices that cannot take care of that
themselves, and keeps them current: switches, routers, management
controllers, appliances, and services that simply read a file.

Such devices cannot use a public CA. Their names are internal or they are
reached by address, they cannot answer an ACME challenge, and nothing on
them renews a certificate every ninety days. What they can do is accept a
certificate somebody hands them. SICK is that somebody.

It deliberately does very little itself:

=over 4

=item *

The CA is L<step-ca|https://smallstep.com/docs/step-ca/>. SICK asks it for
certificates through the C<step> command line (L<SICK::Issuer::StepCA>).

=item *

X.509 is the business of the C<openssl> command line (L<SICK::OpenSSL>).
Nothing is parsed in Perl.

=item *

What SICK adds is the device list (L<SICK::Config>), the decision whether a
device needs a new certificate (L<SICK::Decision>), and the connections to
the devices (L<SICK::Target>).

=back

For every device the same four steps apply. B<Check>: which certificate does
the device present - none, one of another CA, one with other names, one
about to expire? B<Issue>: if so, get a new one. B<Deploy>: the target of
the device type installs it. B<Check again>: the device has to present the
new certificate now. A run changes nothing when everything is current, so it
can be repeated as often as a timer likes.

The core distribution depends on core Perl and L<YAML::PP>, nothing else.
The programs it calls - C<openssl>, C<step> - are prerequisites of a run,
not of the installation; when one is missing, the error says which. A device
type that needs more than that (SSH, an HTTP client) is a distribution of
its own, C<SICK-Target-*>, and is found by the C<type> in the device list.

Secrets are never in the device list, only the paths of the files that hold
them, and they do not show up in messages.

=head1 MODULES

=over 4

=item L<SICK::Config>, L<SICK::Device>

The device list and one entry of it.

=item L<SICK::Decision>

Renew or not: C<ok>, C<missing>, C<foreign-ca>, C<names>, C<expiring>.

=item L<SICK::Issuer>, L<SICK::Issuer::StepCA>, L<SICK::Issuer::SelfSigned>

Where certificates come from: a step-ca, or a throwaway CA for tests.

=item L<SICK::Target>, L<SICK::Target::Files>

Where certificates go: the base class and plugin loader, and the built-in
target that writes PEM files and runs a reload command.

=item L<SICK::Bundle>

Certificate, chain and key, and what C<openssl> says about the certificate.

=item L<SICK::OpenSSL>, L<SICK::Command>, L<SICK::Temp>, L<SICK::Names>, L<SICK::Duration>

The plumbing: external programs without a shell, private temporary
directories, one spelling for names, durations in seconds.

=back

=seealso

=over 4

=item * L<step-ca|https://smallstep.com/docs/step-ca/> and the L<step CLI|https://smallstep.com/docs/step-cli/> - the CA and its client

=item * L<OpenSSL|https://www.openssl.org/> - everything X.509

=item * L<YAML::PP> - reads the device list

=back

=cut

1;
