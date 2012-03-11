use warnings;
use strict;

our $VERSION = '0.10';
our %IRSSI = (
	authors => 'mauke',
	name => 'splitmsg',
);

use bytes ();

Irssi::settings_add_int $IRSSI{name}, 'splitmsg_msgmax', 400;
my $msgmax = Irssi::settings_get_int 'splitmsg_msgmax';

Irssi::signal_add 'setup changed' => sub {
	$msgmax = Irssi::settings_get_int 'splitmsg_msgmax';
};

Irssi::signal_add_first 'server sendmsg' => sub {
	my ($server, $target, $msg, $flag) = @_;
	my $fixed = length ":$server->{nick}!$server->{userhost} PRIVMSG $target :\015\012";
	$fixed >= $msgmax and return;
	$fixed + length($msg) <= $msgmax and return;

	my $px = 0;

	my $lim = $msgmax - $fixed;
	my $min = int($lim / 2);
	my $uni = $msg;
	utf8::decode $uni;

	unless ($px) {
		my $bl = 0;
		while ($uni =~ /\G(\X+?)(?!\S)/cg) {
			$bl += bytes::length $1;
			next if $bl < $min;
			last if $bl > $lim;
			$px = $bl;
		}
	}
	unless ($px) {
		pos($uni) = 0;
		my $bl = 0;
		while ($uni =~ /\G(\X)/cg) {
			$bl += bytes::length $1;
			next if $bl < $min;
			last if $bl > $lim;
			$px = $bl;
		}
	}
	unless ($px) {
		pos($uni) = 0;
		my $bl = 0;
		while ($uni =~ /\G(.)/cg) {
			$bl += bytes::length $1;
			next if $bl < $min;
			last if $bl > $lim;
			$px = $bl;
		}
	}
	unless ($px) {
		$px = $lim; # I don't think we should ever get here
	}

	my $fst = substr $msg, 0, $px, '';
	Irssi::signal_continue $server, $target, $fst, $flag;
	Irssi::signal_emit 'server sendmsg' => $server, $target, $msg, $flag;
};
