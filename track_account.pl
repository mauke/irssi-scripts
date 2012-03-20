use warnings;
use strict;

use Irssi ();

use Dir::Self;
use lib __DIR__ . "/lib";

use again 'IrssiX::Util' => qw(esc case_fold_for require_script);

our $VERSION = '0.05';

our %IRSSI = (
	authors => 'mauke',
	name => 'track_account',
);

require_script 'cap_all';

our %accounts;
our %nicks_by_account;

sub _remove_by {
	my ($f, $list, $x) = @_;
	my $fx = $f->($x);
	@$list = grep $f->($_) ne $fx, @$list;
}

sub _add_by {
	my ($f, $list, $x) = @_;
	_remove_by $f, $list, $x;
	push @{$_[1]}, $x;
}

sub set_nick_account {
	my ($server, $nick, $account) = @_;
	my $tag = $server->{tag};
	my $cfold = case_fold_for $server;
	my $fnick = $cfold->($nick);
	my $e = $accounts{$tag}{$fnick};
	my $prev_acc = $e && $e->{account};
	return $fnick if ($prev_acc || '') eq ($account || '');
	if ($prev_acc) {
		_remove_by $cfold, $nicks_by_account{$tag}{$cfold->($prev_acc)}, $nick;
	}
	if ($account) {
		$accounts{$tag}{$fnick}{account} = $account;
		_add_by $cfold, $nicks_by_account{$tag}{$cfold->($account)}, $nick;
	} else {
		delete $accounts{$tag}{$fnick}{account};
	}
	$fnick
}

sub xaccount {
	my ($x) = @_;
	$x && $x eq '*' ? 0 : $x
}

sub purge_nick {
	my ($server, $nick) = @_;
	my $fnick = set_nick_account $server, $nick, undef;
	delete $accounts{$server->{tag}}{$fnick};
}

Irssi::signal_add 'server connected' => sub {
	my ($server) = @_;
	my $tag = $server->{tag};
	$accounts{$tag} = {};
	$nicks_by_account{$tag} = {};
};

Irssi::signal_add 'server disconnected' => sub {
	my ($server) = @_;
	my $tag = $server->{tag};
	delete $accounts{$tag};
	delete $nicks_by_account{$tag};
};

for my $sig_nick ('message nick', 'message own_nick') {
	Irssi::signal_add $sig_nick => sub {
		my ($server, $newnick, $oldnick, $address) = @_;
		my $tag = $server->{tag};
		my $cfold = case_fold_for $server;
		my $tree = $accounts{$tag};
		my $foldnick = $cfold->($oldnick);
		my ($oacc, $oreal) = @{$tree->{$foldnick}}{qw(account realname)};
		purge_nick $server, $oldnick;
		my $fnewnick = set_nick_account $server, $newnick, $oacc;
		if (defined $oreal) {
			$tree->{$fnewnick}{realname} = $oreal;
		}
	};
}

Irssi::signal_add_last 'message quit' => sub {
	my ($server, $nick, $address, $reason) = @_;
	purge_nick $server, $nick;
};

Irssi::signal_add 'message account' => sub {
	my ($server, $account, $nick, $address) = @_;
	set_nick_account $server, $nick, xaccount $account;
};

Irssi::signal_add 'message join-extended' => sub {
	my ($server, $channel, $nick, $address, $account, $realname) = @_;
	my $fnick = set_nick_account $server, $nick, xaccount $account;
	$accounts{$server->{tag}}{$fnick}{realname} = $realname;
};

Irssi::signal_add_first 'message part' => sub {
	my ($server, $channel, $nick, $address, $reason) = @_;
	my $tag = $server->{tag};
	my $cfold = case_fold_for $server;
	my $tree = $accounts{$tag};
	my $fnick = $cfold->($nick);
	my $fchannel = $cfold->($channel);

	my @onicks;
	@onicks = map $_->{nick}, $server->channel_find($channel)->nicks if $fnick eq $cfold->($server->{nick});

	Irssi::signal_continue @_;

	my $forget_in_channel = sub {
		my ($fnick) = @_;
		$tree->{$fnick} or return;
		my @existings = $server->nicks_get_same($nick);
		while (my ($chan, undef) = splice @existings, 0, 2) {
			if ($cfold->($chan->{name}) ne $fchannel) {
				return;
			}
		}
		purge_nick $server, $fnick;
	};

	$forget_in_channel->($fnick);
	for my $onick (@onicks) {
		$forget_in_channel->($cfold->($onick));
	}
};

Irssi::signal_add "redir $IRSSI{name} whospcrpl" => sub {
	my ($server, $data, $snick, $address) = @_;
	my $tag = $server->{tag};
	my ($nick, $account, $realname) = $data =~ /^\S+ (\S+) (\S+) ([^:]\S*|:.*)$/ or return;
	$realname =~ s/^://;
	my $fnick = set_nick_account $server, $nick, xaccount $account;
	$accounts{$tag}{$fnick}{realname} = $realname;
};

Irssi::signal_add 'channel joined' => sub {
	my ($channel) = @_;
	my $server = $channel->{server};
	defined $server->isupport('WHOX') or return;
	my $cname = $channel->{name};
	$server->redirect_event(
		'who', 1, $cname, -1,
		'event empty',
		{
			'event 354' => "redir $IRSSI{name} whospcrpl",
			'' => 'event empty',
		}
	);
	$server->send_raw("WHO $cname %nar");
};

sub metadata_for {
	my ($server, $nick, $field) = @_;
	my $cfold = case_fold_for $server;
	my $p = \%accounts;
	for my $k ($server->{tag}, $cfold->($nick), $field) {
		defined($p = $p->{$k}) or return;
	}
	$p
}

sub realname_for { metadata_for @_[0, 1], 'realname' }
sub account_for  { metadata_for @_[0, 1], 'account' }
sub nicks_for {
	my ($server, $account) = @_;
	@{$nicks_by_account{$server->{tag}}{case_fold_for($server)->($account)} || []}
}
