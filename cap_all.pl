use warnings;
use strict;

use Data::Munge qw(list2re);
use File::Open qw(fopen_nothrow fsysopen_nothrow);
use Errno ();
use End;
use MIME::Base64 qw(encode_base64 decode_base64);
use Time::HiRes qw(time);

use Irssi ();
{ package Irssi::Nick; }

our $VERSION = '0.04';

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

our %pending_cap;
our %pending_auth;

our %sasl_auth_method = (
	PLAIN => sub {
		my ($v, $data) = @_;
		"$v->{user}\0$v->{user}\0$v->{password}"
	},
);

our %sasl_auth;

my $sasl_file = Irssi::get_irssi_dir . '/sasl.auth';

sub sasl_load {
	my $fh = fopen_nothrow $sasl_file or do {
		Irssi::print esc "$sasl_file: $!" unless $!{ENOENT};
		return;
	};

	my %proto;

	while (my $line = readline $fh) {
		chomp $line;
		my ($network, $user, $password, $method) = split /\t/, $line;
		unless ($sasl_auth_method{$method}) {
			Irssi::print esc "$sasl_file: $.: unknown method [$method]";
			next;
		}
		$proto{$network} = {
			user => $user,
			password => $password,
			method => $method,
		};
	}

	%sasl_auth = %proto;
}

sub sasl_save {
	my $temp = "$sasl_file.$$.tmp";

	my $fh = fsysopen_nothrow $temp, 'w', {
		creat => 0600,
		excl => 1,
	} or do {
		Irssi::print esc "$temp: $!";
		return;
	};
	my $sentinel = end { unlink $temp if $temp; };

	for my $network (sort keys %sasl_auth) {
		my $v = $sasl_auth{$network};
		print $fh "$network\t$v->{user}\t$v->{password}\t$v->{method}\n" or do {
			Irssi::print esc "$temp: $!";
			return;
		};
	}

	$fh->flush && $fh->sync or do {
		Irssi::print esc "$temp: $!";
		return;
	};

	close $fh;
	rename $temp, $sasl_file or do {
		Irssi::print esc "$temp -> $sasl_file: $!";
		return;
	};
	$temp = undef;
}

my %cap_handlers = (
	LS => sub {
		my ($server, $args) = @_;
		$args = " $args ";
		my $caps = '';
		for my $want (qw(multi-prefix extended-join account-notify)) {
			$caps .= " $want" if $args =~ / [=~]?$want /;
		}
		if ($args =~ / [=~]?sasl / && $sasl_auth{$server->{chatnet}}) {
			$caps .= " sasl";
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
		if (" $args " =~ / sasl / && (my $v = $sasl_auth{$server->{chatnet}})) {
			my $tag = $server->{tag};
			my $pauth = $pending_auth{$tag} ||= {};
			$pauth->{buffer} = '';
			if ($sasl_auth_method{$v->{method}}) {
				$server->send_raw_now("AUTHENTICATE $v->{method}");
				$pauth->{timestamp} = time;
				$pending_auth{$server->{tag}}{watchdog} =
					Irssi::timeout_add_once 4000, \&watchdog_timer, $server->{tag};
				return;
			}
			delete $pending_auth{$server->{tag}}{buffer};
			$server->print('', esc("unknown method: [$v->{method}]"));
		}
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
		delete $pending_cap{$tag};
		$server->send_raw_now('CAP END');
		return;
	};

	my $args = defined $single_arg ? $single_arg : $multi_arg;
	$args =~ s/\s+\z//;

	if ($cont) {
		$pending_cap{$tag}{$cmd} .= "$args ";
		return;
	}

	if (defined(my $cont = $pending_cap{$tag}{$cmd})) {
		$args = $cont . $args;
		delete $pending_cap{$tag}{$cmd};
		delete $pending_cap{$tag} unless %{$pending_cap{$tag}};
	}

	$cap_handlers{$cmd}($server, $args);
};

Irssi::signal_add 'event authenticate' => sub {
	my ($server, $data, $nick, $address) = @_;
	my $v = $sasl_auth{$server->{chatnet}} or return;
	my $tag = $server->{tag};
	my $pauth = $pending_auth{$tag} or return;
	defined $pauth->{buffer} or return;

	$data = '' if $data eq '+';

	$pauth->{buffer} .= $data;
	$pauth->{timestamp} = time;
	return if length($data) >= 400;

	my $buf = decode_base64 delete $pauth->{buffer};

	my $out = $sasl_auth_method{$v->{method}}($v, $buf);
	$out = encode_base64($out, '');

	while (length($out) >= 400) {
		$server->send_raw_now("AUTHENTICATE " . substr $out, 0, 400, '');
		$pauth->{timestamp} = time;
	}
	$server->send_raw_now("AUTHENTICATE " . ($out eq '' ? '+' : $out));
	$pauth->{timestamp} = time;
};

sub watchdog_timer {
	my ($tag) = @_;
	my $pauth = $pending_auth{$tag} or return;
	delete $pauth->{watchdog};
	my $server = Irssi::server_find_tag $tag or return;
	my $now = time;
	my $diff = 4000 - int(1000 * ($now - $pauth->{timestamp}));
	if ($diff >= 10) {
		$pauth->{watchdog} =
			Irssi::timeout_add_once $diff, \&watchdog_timer, $tag;
		return;
	}
	$server->print('', esc("SASL authentication timed out"));
	$server->send_raw_now("CAP END");
}

sub sasl_end {
	my ($server, $data, $nick, $address) = @_;

	$data =~ s/^\S+ :?//;
	$server->print('', esc($data));
	$server->send_raw_now("CAP END");

	my $pauth = $pending_auth{$server->{tag}} or return;
	if (my $t = delete $pauth->{watchdog}) {
		Irssi::timeout_remove $t;
	}
}

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

for my $event (qw(903 904 905 906 907)) {
	Irssi::signal_add "event $event" => \&sasl_end;
}

Irssi::signal_add 'setup saved' => \&sasl_save;
Irssi::signal_add 'setup reread' => \&sasl_load;
sasl_load;
