package SICK::Issuer::StepCA;
# ABSTRACT: Have certificates issued by a step-ca through the step command line

use strict;
use warnings;
use parent 'SICK::Issuer';
use Carp qw( croak );
use SICK::Bundle;
use SICK::Command;
use SICK::Temp;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Issuer::StepCA;

    my $issuer = SICK::Issuer::StepCA->new(
      url           => 'https://ca.example.internal:9000',
      root          => '/etc/sick/root_ca.crt',
      provisioner   => 'sick',
      password_file => '/etc/sick/provisioner.pw',
    );

    my $bundle = $issuer->issue( {
      names    => [ 'switch.example.internal', '192.0.2.199' ],
      lifetime => 397 * 86400,
      key      => 'rsa2048',
    } );

In the device list:

    ca:
      url: https://ca.example.internal:9000
      root: /etc/sick/root_ca.crt
      provisioner: sick
      password_file: /etc/sick/provisioner.pw

=head1 DESCRIPTION

Certificates for devices that cannot answer an ACME challenge come from a
JWK provisioner of L<step-ca|https://smallstep.com/docs/step-ca/>: whoever
holds the password of the provisioner may have certificates issued for any
name the CA allows. SICK holds that password - as a file it never reads -
and calls the C<step> program, which does the talking.

C<step> is a prerequisite of a run, not of the installation. It is started
without a shell. The password is handed over as the path of its file and
never appears on a command line, in the environment or in a message.

The provisioner has to allow the lifetimes that are asked for; step-ca
grants 24 hours unless its C<maxTLSCertDuration> claim is raised.

=cut

sub attributes          { qw( url root provisioner password_file step ) }
sub required_attributes { qw( url root provisioner password_file ) }

sub url           { $_[0]->{url} }
sub root          { $_[0]->{root} }
sub provisioner   { $_[0]->{provisioner} }
sub password_file { $_[0]->{password_file} }
sub step          { defined $_[0]->{step} && length $_[0]->{step} ? $_[0]->{step} : 'step' }

=attr url

Required. The URL of the step-ca, C<https://ca.example.internal:9000>.

=attr root

Required. Path of the root certificate of the CA. C<step> uses it to verify
the CA, L</root_pem> returns its content.

=attr provisioner

Required. Name of the JWK provisioner.

=attr password_file

Required. Path of the file with the password of the provisioner.

=attr step

The C<step> program. Defaults to C<step> from the C<PATH>.

=cut

sub issue {
  my ( $self, $spec ) = @_;
  $spec = $self->check_spec($spec);
  $self->_check_files;

  my $tmp    = SICK::Temp->dir;
  my $cert   = $tmp->file('cert.pem');
  my $key    = $tmp->file('key.pem');
  my $params = $self->key_params( $spec->{key} );

  $self->_step(
    'ca', 'certificate',
    $self->_common_args($spec),
    ( map { ( '--san', $_ ) } @{ $spec->{names} } ),
    $params->{type} eq 'rsa'
    ? ( '--kty', 'RSA', '--size', $params->{bits} )
    : ( '--kty', 'EC', '--curve', $params->{curve} ),
    $spec->{names}[0], $cert, $key,
  );

  my $bundle = SICK::Bundle->from_files( cert => $cert, key => $key );
  croak 'step wrote an encrypted private key; SICK needs it unencrypted'
    if $bundle->key =~ /ENCRYPTED/;
  return $bundle;
}

=method issue

    my $bundle = $issuer->issue($spec);

Runs

    step ca certificate --ca-url <url> --root <root> --provisioner <provisioner>
      --provisioner-password-file <password_file> --not-after <lifetime>s
      --san <name> ... --kty RSA --size <bits> | --kty EC --curve P-256
      <first name> <cert file> <key file>

and returns the result as a L<SICK::Bundle> with the key; what C<step>
writes after the certificate itself (the intermediate) is the chain.

Certificate and key are written into a private temporary directory
(L<SICK::Temp>, files not readable for anybody else) that is gone when
C<issue> returns or dies.

Croaks with C<< step failed (exit <N>): <stderr> >> when C<step> does not
succeed - the CA refusing the lifetime or the password included, in the
words of C<step> -, with C<< cannot run 'step': <reason> >> when it is not
installed, and with C<< cannot read secret file '<path>': <reason> >> when
the password file is missing or unreadable.

=cut

sub sign {
  my ( $self, $csr_pem, $spec ) = @_;
  $spec = $self->check_spec($spec);

  my $wanted = join ', ', sort @{ $spec->{names} };
  my $asked  = join ', ', @{ $self->csr_names($csr_pem) };
  croak 'the certificate request is for ['.$asked.'], not for ['.$wanted
    .']; step-ca takes the names from the request'
    unless $asked eq $wanted;
  $self->_check_files;

  my $tmp  = SICK::Temp->dir;
  my $csr  = $tmp->write( 'request.csr', $csr_pem );
  my $cert = $tmp->file('cert.pem');

  $self->_step( 'ca', 'sign', $self->_common_args($spec), $csr, $cert );

  return SICK::Bundle->from_files( cert => $cert );
}

=method sign

    my $bundle = $issuer->sign( $csr_pem, $spec );

Runs

    step ca sign --ca-url <url> --root <root> --provisioner <provisioner>
      --provisioner-password-file <password_file> --not-after <lifetime>s
      <csr file> <cert file>

and returns a L<SICK::Bundle> without a key.

C<step ca sign> has no C<--san>: the CA signs the names the request asks
for. C<sign> therefore reads them first (L<SICK::Issuer/csr_names>) and
croaks, before anything is sent to the CA, unless they are exactly the names
of the spec. A device whose request cannot carry all its names cannot be
served this way.

Fails like L</issue>.

=cut

sub root_pem {
  my ( $self ) = @_;
  my $root = eval { SICK::Bundle->from_files( cert => $self->root ) };
  return $root->fullchain if $root;
  my $error = $@;
  $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  $error =~ s/\Acannot read certificate file/cannot read CA root/;
  $error =~ s/\Acert is not a PEM certificate/CA root '${\ $self->root}' is not a PEM certificate/;
  croak $error;
}

=method root_pem

The content of the L</root> file: the PEM certificates in it. Croaks with
C<< cannot read CA root '<path>': <reason> >> when it cannot be read.

=cut

#### internals

sub _common_args {
  my ( $self, $spec ) = @_;
  return (
    '--ca-url',                    $self->url,
    '--root',                      $self->root,
    '--provisioner',               $self->provisioner,
    '--provisioner-password-file', $self->password_file,
    '--not-after',                 $spec->{lifetime}.'s'
  );
}

# Fail early and in our own words when a file step needs is not there. The
# password file is opened to see that it can be read; nothing is read.
sub _check_files {
  my ( $self ) = @_;
  $self->root_pem;
  my $path = $self->password_file;
  open my $fh, '<', $path
    or croak 'cannot read secret file \''.$path.'\': '.$!;
  croak 'cannot read secret file \''.$path.'\': Is a directory' if -d $fh;
  close $fh;
  return;
}

sub _step {
  my ( $self, @args ) = @_;
  my ( $out, $err, $exit ) = SICK::Command::run( [ $self->step, @args ], umask => 077 );
  return $out unless $exit;
  $err =~ s/\A\s+//;
  $err =~ s/\s+\z//;
  croak 'step failed (exit '.$exit.'): '.$err;
}

1;
