use warnings;
use strict;

use Irssi ();

use Dir::Self;
use lib __DIR__ . '/lib';

our $VERSION = '0.051';

our %IRSSI = (
	name => 'whyban',
	authors => 'mauke',
);

use IrssiX::Util qw(esc puts);
use POSIX qw(strftime);

Irssi::Irc::Server::redirect_register
	'mode q',
	0,
	0,
	{
		'event 728' => 1,
	},
	{
		'event 729' => 1,
		'event 403' => 1,
		'event 442' => 1,
		'event 479' => 1,
	},
	{}
;

my $masks_reply_event = "redir $IRSSI{name} masks reply";
my $masks_reply_end   = "redir $IRSSI{name} masks end";
#Irssi::signal_register { $masks_reply_end => [] };
my $whois_reply_event = "redir $IRSSI{name} whois reply";
my $whois_auth_event  = "redir $IRSSI{name} whois auth";
my $whois_reply_end   = "redir $IRSSI{name} whois end";
#Irssi::signal_register { $whois_reply_end => [] };
my $mode_reply_event  = "redir $IRSSI{name} mode reply";
my $mode_reply_end    = "redir $IRSSI{name} mode end";

our @Q_mode;
our @Q_mode_b;
our @Q_mode_q;
our @Q_whois;

sub finalize {
	my ($ctx) = @_;
	if (!$ctx->{matches}) {
		$ctx->{print}("${\esc $ctx->{nick}} %9${\esc $ctx->{channel}}%9: no matches");
	}
}

sub check_channel {
	my ($ctx) = @_;
	my $channel = $ctx->{channel};
	my $server = Irssi::server_find_tag $ctx->{server};
	push @Q_mode, $ctx;
	$server->redirect_event(
		"mode channel",
		1,
		$channel,
		0,
		$mode_reply_end,
		{
			'event 324' => $mode_reply_event,
			'' => 'event empty',
			'event 403' => $mode_reply_end,
			'event 442' => $mode_reply_end,
			'event 479' => $mode_reply_end,
		}
	);
	$server->send_raw("MODE $channel");
}

Irssi::signal_add $mode_reply_end => sub {
	my $ctx = shift @Q_mode or return;
	finalize $ctx;
};

Irssi::signal_add $mode_reply_event => sub {
	my ($server, $args, $sender_nick, $sender_address) = @_;
	my $ctx = shift @Q_mode or return;

	my ($channame, $modes, $rest) = $args =~ /^[^ ]+ ([^ ]+) ([^ ]+)(.*)\z/
		or return puts "$IRSSI{name}: ?mode($args)";
	my @args = split ' ', $rest;
	$modes =~ s/^\+//;

	my $prefix = "${\esc $ctx->{nick}} %9${\esc $channame}%9:";
	if ($modes =~ /i/) {
		$ctx->{print}("$prefix +i");
		$ctx->{matches}++;
	}
	if ($modes =~ /k/) {
		$ctx->{print}("$prefix +k ?");
		$ctx->{matches}++;
	}
	if ($modes =~ /r/ && !$ctx->{account}) {
		$ctx->{print}("$prefix +r");
		$ctx->{matches}++;
	}
	finalize $ctx;
};

sub check_masks {
	my ($mode, $ctx) = @_;
	my $server = Irssi::server_find_tag $ctx->{server};

	my $q = $mode eq 'q' ? \@Q_mode_q : \@Q_mode_b;
	push @$q, $ctx;
	my %ev_reply = $mode eq 'q' ? (
		'event 728' => "$masks_reply_event q",
	) : (
		'event 367' => "$masks_reply_event b",
	);
	my %ev_end = $mode eq 'q' ? (
		'event 729' => "$masks_reply_end q",
	) : (
		'event 368' => "$masks_reply_end b",
	);
	my $ev_end = "$masks_reply_end $mode";
	$server->redirect_event(
		"mode $mode",
		1,
		"$ctx->{channel} +$mode",
		0,
		"$masks_reply_end $mode",
		{
			%ev_reply,
			'' => 'event empty',
			%ev_end,
		}
	);
	$server->send_raw("MODE $ctx->{channel} $mode");
}

Irssi::signal_add "$masks_reply_end q" => sub {
	my $ctx = shift @Q_mode_q or return;
	check_masks 'b', $ctx;
};

Irssi::signal_add "$masks_reply_end b" => sub {
	my $ctx = shift @Q_mode_b or return;
	check_channel $ctx;
};

my @times = (
	[secs => 1],
	[mins => 60],
	[hours => 60],
	[days => 24],
	[years => 365],
);

for my $proto (['q', \@Q_mode_q], ['b', \@Q_mode_b]) {
	my ($mode, $queue) = @$proto;

	Irssi::signal_add "$masks_reply_event $mode" => sub {
		my ($server, $args, $sender_nick, $sender_address) = @_;
		my $ctx = $queue->[0] or return;
		$args =~ s/^[^ ]+ // or return;

		my ($channame, $mask, $setter, $timestamp) = $args =~ /^([^ ]+) (?:q )?([^ ]+) ([^ ]+) ([^ ]+)\z/
			or return puts "$IRSSI{name}: ?mode_$mode($args)";

		if ($mask =~ /^\$(~?)([arx])(?::(.*))?\z/) {
			my ($invert, $type, $param) = ($1, $2, $3);
			defined $param or $param = '*';
			my $re = do {
				my $x = $param;
				$x =~ s{(\W)}{
					$1 eq '*' ? '.*' :
					$1 eq '?' ? '.' :
					'\\' . $1
				}eg;
				qr/^$x\z/i
			};

			my $matched;

			if ($type eq 'a') {
				$matched = defined $ctx->{account} && $ctx->{account} =~ /$re/;
			} elsif ($type eq 'r') {
				$matched = defined $ctx->{realname} && $ctx->{realname} =~ /$re/;
			} elsif ($type eq 'x') {
				$matched = defined $ctx->{realname} && "$ctx->{nick}!$ctx->{user}\@$ctx->{host}#$ctx->{realname}" =~ /$re/;
			}

			$matched = !$matched if $invert;

			$matched or return;
		} else {
			(my $emask = $mask) =~ s/\$#.*//s;
			$server->mask_match($emask, $ctx->{nick}, $ctx->{user}, $ctx->{host}) or return;
		}

		my $delta = time - $timestamp;
		my $unit = 'secs';

		for my $tm (@times) {
			$delta < $tm->[1] and last;
			$delta = int $delta / $tm->[1];
			$unit = $tm->[0];
		}
		
		$ctx->{print}("${\esc $ctx->{nick}} %9${\esc $channame}%9: +${\esc $mode} %c${\esc $mask}%n [by %9${\esc $setter}%9 ${\esc $delta} ${\esc $unit} ago (${\esc strftime '%Y-%m-%d', localtime $timestamp})]");
		$ctx->{matches}++;
	};
}

Irssi::signal_add $whois_reply_end => sub {
	my $ctx = shift @Q_whois or return;
	grep !defined $ctx->{$_}, qw(nick user host) and do {
		$ctx->{print}("couldn't get user/host for ${\esc $ctx->{nick}}");
		return;
	};
	my $server = Irssi::server_find_tag $ctx->{server};
	my $modes = $server->isupport('CHANMODES');
	my $mode = $modes =~ /^[^,q]*q/ ? 'q' : 'b';
	check_masks $mode, $ctx;
};

Irssi::signal_add $whois_auth_event => sub {
	my ($server, $args, $sender_nick, $sender_address) = @_;
	my $ref = $Q_whois[0] or return;
	$args =~ s/^[^ ]+ // or return;
	my ($nickname, $account) = $args =~ /^([^ ]+) ([^ ]+)/ 
		or return puts "$IRSSI{name}: ?whois_($args)";

	$ref->{account} = $account;
};

Irssi::signal_add $whois_reply_event => sub {
	my ($server, $args, $sender_nick, $sender_address) = @_;
	my $ref = $Q_whois[0] or return;
	$args =~ s/^[^ ]+ // or return;
	my ($nickname, $username, $host, $realname) = $args =~ /^([^ ]+) ([^ ]+) ([^ ]+) \* :(.*)/ 
		or return puts "$IRSSI{name}: ?whois($args)";

	$ref->{nick} = $nickname;
	$ref->{user} = $username;
	$ref->{host} = $host;
	$ref->{realname} = $realname;
};

sub check_modes_for {
	my ($server, $nick, $chan, $print) = @_;

	push @Q_whois, {
		nick => $nick,
		channel => $chan,
		server => $server->{tag},
		print => $print,
	};
	$server->redirect_event(
		'whois',
		1,
		$nick,
		0,
		$whois_reply_end,
		{
			'event 311' => $whois_reply_event,
			'event 330' => $whois_auth_event,
			'' => 'event empty',
			'event 318' => $whois_reply_end,
		}
	);
	$server->send_raw("WHOIS :$nick");
}

sub whyban {
	my ($data, $server, $witem) = @_;
	my @args = split ' ', $data;
	if (@args < 1 || @args > 2) {
		puts "Usage: why NICK [CHANNEL]";
		return;
	}
	my ($nickname, $channame) = @args;
	if (!$channame) {
		$channame = $witem && $witem->{type} eq 'CHANNEL' && $witem->{name} or do {
			puts "No channel specified";
			return;
		};
	}

	my $print = $witem ? sub { $witem->print($_[0], Irssi::MSGLEVEL_CRAP) } : sub { $server->print('', $_[0], Irssi::MSGLEVEL_CRAP) };
	check_modes_for $server, $nickname, $channame, $print;
}

Irssi::command_bind 'why' => \&whyban;
