requires 'perl', '5.020';

requires 'Carp';
requires 'Errno';
requires 'Fcntl';
requires 'File::Path';
requires 'File::Temp';
requires 'IO::Handle';
requires 'IO::Select';
requires 'POSIX';
requires 'Socket';
requires 'Time::HiRes';
requires 'Time::Local';
requires 'YAML::PP', '0.027';

on test => sub {
  requires 'File::Temp';
  requires 'IO::Socket::INET';
  requires 'JSON::PP';
  requires 'Test::More', '0.96';
};
