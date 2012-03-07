use warnings;
use strict;

use again 'Data::Munge' => qw(list2re);

use Irssi ();

our $VERSION = '0.02';

our %IRSSI = (
	authors => 'mauke',
	name => 'cap_all',
);

sub esc {
	my $s = join '', @_;
	$s =~ s/%/%%/g;
	$s
}

Irssi::signal_register {
	'message join-extended' => [qw(iobject string string string string string)],
	'message account' => [qw(iobject string string string)],
};

our %pending;

my %cap_handlers = (
	LS => sub {
		my ($server, $args) = @_;
		$args = " $args ";
		my $caps = '';
		for my $want (qw(multi-prefix extended-join account-notify)) {
			$caps .= " $want" if $args =~ / [=~]?$want /;
		}

		if ($caps) {
			$caps =~ s/^ //;
			$server->send_raw_now("CAP REQ :$caps");
		} else {
			$server->send_raw_now('CAP END');
		}
	},
	LIST => sub {
		my ($server, $args) = @_;
		$server->print('', esc("active CAPs: $args"));
	},
	ACK => sub {
		my ($server, $args) = @_;
		$server->print('', esc("enabled CAPs: $args"));
		$server->send_raw_now('CAP END');
	},
	NAK => sub {
		my ($server, $args) = @_;
		$server->print('', esc("couldn't enable CAPs: $args"));
		$server->send_raw_now('CAP END');
	},
);
my $cap_re = list2re keys %cap_handlers;

Irssi::signal_add 'event cap' => sub {
	my ($server, $data, $nick, $address) = @_;
	$server->{connected} and return;

	my $tag = $server->{tag};

	my ($cmd, $cont, $single_arg, $multi_arg) = $data =~ /^\S+ ($cap_re) (\* )?(?:([^:\s]\S*) *|:(.*))$/ or do {
		# I have no idea what you just said
		$server->print('', esc("couldn't parse CAP: $data"), MSGLEVEL_CLIENTERROR);
		delete $pending{$tag};
		$server->send_raw_now('CAP END');
		return;
	};

	my $args = defined $single_arg ? $single_arg : $multi_arg;
	$args =~ s/\s+\z//;

	if ($cont) {
		$pending{$tag}{$cmd} .= "$args ";
		return;
	}

	if (defined(my $cont = $pending{$tag}{$cmd})) {
		$args = $cont . $args;
		delete $pending{$tag}{$cmd};
		delete $pending{$tag} unless %{$pending{$tag}};
	}

	$cap_handlers{$cmd}($server, $args);
};

Irssi::signal_add_first 'event join' => sub {
	my ($server, $data, $nick, $address) = @_;
	my ($channel, $account, $realname) = $data =~ /^(\S+) (\S+) ([^:\s]\S*|:.*)/ or return;
	$realname =~ s/^://;

	Irssi::signal_emit 'message join-extended', $server, $channel, $nick, $address, $account, $realname;
	Irssi::signal_continue $server, $channel, $nick, $address;
};

Irssi::signal_add_first 'server connected' => sub {
	my ($server) = @_;
	$server->send_raw_now('CAP LS');
};

Irssi::signal_add 'event account' => sub {
	my ($server, $data, $nick, $address) = @_;
	$data =~ s/^:// or $data =~ s/ .*//;
	Irssi::signal_emit 'message account', $server, $data, $nick, $address;
};
