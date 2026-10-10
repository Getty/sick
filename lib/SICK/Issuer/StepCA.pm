package SICK::Issuer::StepCA;
# ABSTRACT: Have certificates issued by a step-ca through the step command line

use Moo;
extends 'SICK::Issuer';
use Carp qw( croak );
use Path::Tiny ();
use SICK::Bundle;
use SICK::Command;
use SICK::Temp;
use Types::Standard qw( Str );
use namespace::autoclean;

our $VERSION = '0.001';

=head1 SYNOPSIS

    use SICK::Issuer::StepCA;

    my $issuer = SICK::Issuer::StepCA->new(
      url           => 'https://ca.example.internal:9000',
      root          => '/etc/sick/root_ca.crt',
      intermediates => '/etc/sick/intermediate_ca.crt',
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
      intermediates: /etc/sick/intermediate_ca.crt
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
grants 24 hours unless its C<maxTLSCertDuration> claim is raised
(C<step ca provisioner update sick --x509-max-dur 19800h>).

A step-ca never signs with its root: every certificate comes from its
intermediate, and what C<step> writes is the certificate followed by that
intermediate. A device that stores one certificate per slot presents the
certificate alone, and nothing leads from there to the root. Name the
intermediate certificate of the CA as L</intermediates> - step-ca keeps it
in F<certs/intermediate_ca.crt>, next to F<certs/root_ca.crt> - and SICK
recognizes such a certificate as its own.

The command lines are verified against C<step> 0.30.2 and a step-ca 0.30.2.

=cut

sub attributes          { qw( url root intermediates provisioner password_file step ) }
sub required_attributes { qw( url root provisioner password_file ) }

has url           => ( is => 'ro', isa => Str, required => 1 );
has root          => ( is => 'ro', isa => Str, required => 1 );
has intermediates => ( is => 'ro', isa => Str );
has provisioner   => ( is => 'ro', isa => Str, required => 1 );
has password_file => ( is => 'ro', isa => Str, required => 1 );
has step          => ( is => 'ro', isa => Str, default => 'step' );

=attr url

Required. The URL of the step-ca, C<https://ca.example.internal:9000>.

=attr root

Required. Path of the root certificate of the CA. C<step> uses it to verify
the CA, L</root_pem> returns its content. The file holds this one
certificate and nothing else: C<step> refuses a file with more than one PEM
block.

=attr intermediates

Optional. Path of a file with the intermediate certificate of the CA, or
several of them. C<step> does not get to see it; it is what
L</intermediates_pem> returns. Set it whenever a device presents its
certificate without the chain: SICK then knows that certificate as its own,
and C<sick trust> hands the intermediate to the clients as well
(L<SICK::Trust>).

=attr provisioner

Required. Name of the JWK provisioner.

=attr password_file

Required. Path of the file with the password of the provisioner.

=attr step

The C<step> program. Defaults to C<step> from the C<PATH>, also when it is
given empty.

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
writes after the certificate itself (the intermediate) is the chain. The
key comes unencrypted, RSA keys as PKCS#1 (C<BEGIN RSA PRIVATE KEY>), EC
keys as SEC 1 (C<BEGIN EC PRIVATE KEY>). step-ca starts the validity one
minute in the past; the certificate ends C<lifetime> from now.

C<--not-after> takes a point in time or a duration in the units of Go,
hours at most - C<397d> is refused -, which is why the lifetime is handed
over in seconds.

Certificate and key are written into a private temporary directory
(L<SICK::Temp>, files not readable for anybody else) that is gone when
C<issue> returns or dies.

Croaks with C<< step failed (exit <N>): <what step said> >> when C<step>
does not succeed - the CA refusing the lifetime
(C<requested duration of ... is more than the authorized maximum certificate
duration of ...>) or a wrong password (C<failed to decrypt JWE: invalid
password>) included, in the words of C<step>. Its progress lines, its
colours and its hint at C<STEPDEBUG> are left out. Croaks with
C<< cannot run 'step': <reason> >> when it is not installed, and with
C<< cannot read secret file '<path>': <reason> >> when the password file is
missing or unreadable.

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
  my $root = $self->_certificates( $self->root, 'CA root' );
  croak 'CA root \''.$self->root.'\' holds more than one certificate; step needs the root alone'
    .' - name the intermediate certificate as ca.intermediates'
    if defined $root->chain;
  return $root->cert;
}

=method root_pem

The certificate in the L</root> file as PEM. Croaks with
C<< cannot read CA root '<path>': <reason> >> when it cannot be read, and
when the file holds more than one certificate: C<step> would refuse it
(C<contains more than one PEM encoded block>), and the intermediate has a
place of its own.

=cut

sub intermediates_pem {
  my ( $self ) = @_;
  my $path = $self->intermediates;
  return undef unless defined $path && length $path;
  return $self->_certificates( $path, 'CA intermediates' )->fullchain;
}

=method intermediates_pem

The certificates in the L</intermediates> file as PEM, C<undef> when none
is configured. Croaks with
C<< cannot read CA intermediates '<path>': <reason> >> when the file
cannot be read.

=cut

#### internals

# The certificates of a file of the ca section, as a bundle; errors in the
# words of the device list.
sub _certificates {
  my ( $self, $path, $what ) = @_;
  my $bundle = eval { SICK::Bundle->from_files( cert => $path ) };
  return $bundle if $bundle;
  my $error = $@;
  $error =~ s/ at \S+ line [0-9]+\.?\s*\z//;
  $error =~ s/\Acannot read certificate file/cannot read $what/;
  $error =~ s/\Acert is not a PEM certificate/$what '$path' is not a PEM certificate/;
  croak $error;
}

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
  my $file = Path::Tiny::path($path);
  croak 'cannot read secret file \''.$path.'\': Is a directory' if $file->is_dir;
  my $fh = eval { $file->openr_raw };
  croak 'cannot read secret file \''.$path.'\': '.( ref $@ ? $@->{err} : 'unknown error' )
    unless $fh;
  close $fh;
  return;
}

sub _step {
  my ( $self, @args ) = @_;
  my ( $out, $err, $exit ) = SICK::Command::run( [ $self->step, @args ], umask => 077 );
  return $out unless $exit;
  croak 'step failed (exit '.$exit.'): '.$self->_said($err);
}

# What step has to say, out of what it prints. On standard error it reports
# its progress ("<check mark> Provisioner: sick (JWK) [kid: ...]") in
# colour, terminal or not, and ends a failure with a hint for its developers.
sub _said {
  my ( $self, $err ) = @_;
  $err = q{} unless defined $err;
  $err =~ s/\e\[[0-9;?]*[ -\/]*[@-~]//g;
  my @lines = grep { /\S/ && !/\A\s*\xe2\x9c\x94/ && !/\ARe-run with STEPDEBUG=1/ } split /\r?\n/, $err;
  s/\A\s+//, s/\s+\z// for @lines;
  return @lines ? join( "\n", @lines ) : 'it did not say why';
}

1;
