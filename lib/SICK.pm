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
      intermediates: /etc/sick/intermediate_ca.crt
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
      pve1:
        type: proxmox-ve                # SICK::Target::ProxmoxVE (and proxmox-bs,
                                        # SICK::Target::ProxmoxBS), their own distribution
        host: pve1.example.internal
        names: [pve1.example.internal]
        node: pve1
        token_id: sick@pve!sick
        token_file: /etc/sick/pve1.token
      grafana:
        type: files                     # built in
        names: [grafana.example.internal]
        dir: /srv/certs/grafana
        reload: "docker restart grafana"
      router:
        type: acmesh                    # built in: a deploy hook of acme.sh
        hook: routeros
        names: [router.example.internal]
        env: { ROUTER_OS_HOST: router.example.internal, ROUTER_OS_USERNAME: sick }

On the command line (L<sick>):

    sick check                   # what does every device present?
    sick run                     # renew what is due
    sick inventory               # what was issued, deployed and last seen
    sick trust /srv/www/trust    # root certificate and instructions for clients

From Perl:

    use SICK::Config;
    use SICK::Issuer;
    use SICK::Runner;

    my $config = SICK::Config->load('/etc/sick/sick.yml');
    my $runner = SICK::Runner->new(
      config => $config,
      issuer => SICK::Issuer->from_ca( %{ $config->ca } ),
    );

    for my $result ( $runner->run ) {
      print "$result->{device}: $result->{action}\n";
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

Where L<acme.sh|https://github.com/acmesh-official/acme.sh> already has a
deploy hook for a device, SICK uses that hook (L<SICK::Target::Acmesh>).

=item *

What SICK adds is the device list (L<SICK::Config>), the decision whether a
device needs a new certificate (L<SICK::Decision>), the connections to the
devices (L<SICK::Target>) and the run that ties them together
(L<SICK::Runner>).

=back

For every device the same four steps apply. B<Check>: which certificate does
the device present - none, one of another CA, one with other names, one
about to expire? B<Issue>: if so, get a new one. B<Deploy>: the target of
the device type installs it. B<Check again>: the device has to present the
new certificate now. A run changes nothing when everything is current, so it
can be repeated as often as a timer likes. SICK is no daemon: renewal is
C<sick run> in a timer or a cron job.

A certificate of an internal CA only helps on machines that trust that CA.
C<sick trust> writes the root certificate in the forms clients want and a
page that explains the installation per platform (L<SICK::Trust>) - and the
intermediate certificate with it, which a client needs for every device
that presents its certificate alone.

The F<docker/> directory of the repository puts the three together with
Docker Compose: a step-ca that sets itself up on first start, SICK on a
schedule, and a small web server for the page of C<sick trust>.

Besides core Perl, the core distribution depends on L<Moo>,
L<namespace::autoclean> and L<Type::Tiny> for its classes, L<Path::Tiny> for
files and L<YAML::PP> for the device list.
The programs it calls - C<openssl>, C<step>, C<acme.sh> - are prerequisites
of a run, not of the installation; when one is missing, the error says
which. A device
type that needs more than that (SSH, an HTTP client) is a distribution of
its own, C<SICK-Target-*>, and is found by the C<type> in the device list.

Secrets are never in the device list, only the paths of the files that hold
them, and they do not show up in messages.

=head1 MODULES

=over 4

=item L<sick>, L<SICK::CLI>

The command line: C<check>, C<run>, C<inventory>, C<trust>.

=item L<SICK::Runner>

Check, issue, deploy, check again - for every device, one not stopping the
others.

=item L<SICK::State>

What a run remembers: one record per device - last look, last issue, last
deployment, failures and back-off, never a key - and the lock that keeps
two runs apart.

=item L<SICK::Report>

C<check> and C<inventory> for machines: JSON, and the text format of
Prometheus.

=item L<SICK::Config>, L<SICK::Device>

The device list and one entry of it.

=item L<SICK::Decision>

Renew or not: C<ok>, C<missing>, C<foreign-ca>, C<names>, C<expiring>.

=item L<SICK::Issuer>, L<SICK::Issuer::StepCA>, L<SICK::Issuer::SelfSigned>

Where certificates come from: a step-ca, or a throwaway CA for tests.

=item L<SICK::Target>, L<SICK::Target::Files>, L<SICK::Target::Acmesh>

Where certificates go: the base class and plugin loader, and the two
built-in targets - one writes PEM files and runs a reload command, the
other hands the certificate to a deploy hook of acme.sh.

=item L<SICK::Trust>

The root certificate as PEM, DER and Apple configuration profile, and a page
with instructions for every platform.

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

=item * L<acme.sh|https://github.com/acmesh-official/acme.sh> - its deploy hooks, through L<SICK::Target::Acmesh>

=item * L<Moo> - the classes

=item * L<YAML::PP> - reads the device list

=back

=cut

1;
