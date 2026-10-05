requires 'perl', '5.020';

requires 'Carp';
requires 'Digest::SHA';
requires 'Errno';
requires 'Fcntl';
requires 'File::Path';
requires 'File::Temp';
requires 'Getopt::Long', '2.39';
requires 'IO::Handle';
requires 'IO::Select';
requires 'MIME::Base64';
requires 'POSIX';
requires 'Socket';
requires 'Time::HiRes';
requires 'Time::Local';
requires 'YAML::PP', '0.027';

on test => sub {
  requires 'Digest::SHA';
  requires 'File::Path';
  requires 'File::Temp';
  requires 'IO::Socket::INET';
  requires 'JSON::PP';
  requires 'MIME::Base64';
  requires 'Test::More', '0.96';
};
