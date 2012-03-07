use warnings;
use strict;

use Irssi ();

use Dir::Self;
use lib __DIR__ . '/lib';

use again 'IrssiX::Util' => qw(case_fold_for timer_add_once esc later puts);
use again 'IrssiX::ADNS';
use again 'Time::HiRes' => qw(time);
use again 'Errno';
use again 'JSON'; BEGIN { JSON->VERSION(2) }
use again 'File::Open' => qw(fopen_nothrow fsysopen);
use again 'IO::Handle' => [];
use again 'Text::LevenshteinXS' => [];
use again 'Data::Munge' => qw(list2re); BEGIN { Data::Munge->VERSION('0.04') }

our $VERSION = '0.022';

our %IRSSI = (
	authors => 'mauke',
	name => 'vision',
);

our $ADNS = IrssiX::ADNS->new;

#== local/sync ==
# nickspam
#   if length($msg) >= N and count_nicks($msg) >= M: complain

# re
#   $msg matches fixed regex

# strbl
#   $msg contains any of set of fixed strings (case insensitive)

# nick, ident, host, gecos
#   $nick/$ident/$host/$realname equals fixed string (case insensitive)

# nuhg
#   "$nick!$user\@$host!$realname" matches fixed regex

#== tracking/sync ==
# floodqueue
#   N matching(type,target,host) events in M seconds

# splitflood
#   if N copies of the same message arrive in a channel in M seconds: blacklist that message for 10 minutes and complain
#   if a blacklisted message arrives in a channel: complain
#   NB. separate blacklist per rule

# advsplitflood
#   remove leading/trailing digits, then goto splitflood

# levenflood
#   take last max(6 .. 12) messages to channel where length >= 30
#   remove those where length != length($msg)
#   remove those where dist_levenshtein($msg) > 4
#   if 5 or more are left: complain

#== async ==
# dnsbl
#   resolve host
#   resolve/check against dnsbl

our %sliding_history;
our $sliding_history_gc_tag;
our $sliding_history_max_age = 0;

sub sliding_history_purge {
	my ($now) = @_;

	my $next_expiry;

	for my $channels (values %sliding_history) {
		for my $chan (keys %$channels) {
			my $queue = $channels->{$chan};
			while (@$queue && $queue->[0]{timestamp} + $sliding_history_max_age < $now) {
				shift @$queue;
			}
			if (@$queue) {
				my $ts = $queue->[0]{timestamp} + $sliding_history_max_age;
				$next_expiry = $ts if !defined($next_expiry) || $ts < $next_expiry;
			} else {
				delete $channels->{$chan};
			}
		}
	}

	$next_expiry
}

sub sliding_history_gc {
	$sliding_history_gc_tag = undef;

	my $now = time;

	my $next = sliding_history_purge $now;
	defined $next or return;

	$sliding_history_gc_tag = timer_add_once 1000 * ($next - $now), \&sliding_history_gc;
}

sub add_to_history {
	my ($event, $server, $channel, $sender, $data) = @_;
	$sliding_history_max_age or return;

	my $cfold = case_fold_for $server;

	my $queue = $sliding_history{$server->{tag}}{$cfold->($channel)} ||= [];
	my $now = time;

	push @$queue, {
		type => $event,
		timestamp => $now,
		sender => $sender,
		data => $data,
	};

	unless ($sliding_history_gc_tag) {
		$sliding_history_gc_tag = timer_add_once 1000 * $sliding_history_max_age, \&sliding_history_gc;
	}
}

our %leven_history;

sub add_to_leven_history {
	my ($event, $server, $channel, $sender, $data) = @_;
	my $cfold = case_fold_for $server;

	my $queue = $leven_history{$server->{tag}}{$cfold->($channel)}{$event} ||= [];
	push @$queue, {
		sender => $sender,
		data => $data,
	};
	shift @$queue while @$queue > 12;
}

our %temp_blacklist;
our $temp_blacklist_gc_tag;

sub temp_blacklist_purge {
	my ($now) = @_;

	my $next_expiry;

	for my $blacklist (values %temp_blacklist) {
		for my $msg (keys %$blacklist) {
			my $expires = $blacklist->{$msg};
			if ($expires < $now) {
				delete $blacklist->{$msg};
			} elsif (!defined($next_expiry) || $expires < $next_expiry) {
				$next_expiry = $expires;
			}
		}
	}

	$next_expiry
}

sub temp_blacklist_gc {
	$temp_blacklist_gc_tag = undef;

	my $now = time;
	my $next = temp_blacklist_purge $now;
	defined $next or return;

	$temp_blacklist_gc_tag = timer_add_once 1000 * ($next - $now), \&temp_blacklist_gc;
}

sub add_to_temp_blacklist {
	my ($id, $msg, $expires) = @_;
	$temp_blacklist{$id}{$msg} = $expires;

	unless ($temp_blacklist_gc_tag) {
		$temp_blacklist_gc_tag = timer_add_once 1000 * ($expires - time), \&temp_blacklist_gc;
	}
}

# rule:
#   - id
#   - match function (type)
#   - severity
#   - description (format template)
#   - event types to match
#   - fixed arguments

our %reporting_on;
our %rules;
our %rules_by_event;

our $DIR = "${\Irssi::get_irssi_dir}/$IRSSI{name}.d";

unless (mkdir $DIR) {
	$!{EEXIST} or die "$DIR: $!";
}

sub slurp { local $/; readline $_[0] }

sub read_json_from_default {
	my ($file, $def) = @_;
	$file = "$DIR/$file";
	my $fh = fopen_nothrow $file, 'rb';
	if (!$fh) {
		$!{ENOENT} or die "$file: $!";
		return $def;
	}
	decode_json slurp $fh
}

sub write_json_to {
	my ($file, $data) = @_;
	$file = "$DIR/$file";
	my $json = JSON->new->canonical->ascii->indent->space_after->encode($data);

	my $proxy = "$file.$$";
	my $fh = fsysopen $proxy, 'w', {
		creat => 0644,
		excl => 1,
	};
	binmode $fh;
	$fh->autoflush(1);
	print $fh $json or die "$proxy: $!";
	eval {$fh->sync} || $@ or die "$proxy: $!";
	close $fh or die "$proxy: $!";
	rename $proxy, $file or die "$proxy -> $file: $!";
}

our @global_blacklist;
our $global_blacklist_re = list2re @global_blacklist;

our %exempt_accounts;
our %privileged_accounts;

sub reread_config {
	my $repmap = read_json_from_default 'reportmap.json', {};
	my $raw = read_json_from_default 'rules.json', [];
	my $ea = read_json_from_default 'exempt.json', {};
	my $gb = read_json_from_default 'global_blacklist.json', [];
	my $pa = read_json_from_default 'accounts.json', {};

	my %fea;
	for my $net (keys %$ea) {
		my $tree = $fea{$net} ||= {};
		my $srv = Irssi::server_find_chatnet($net);
		my $cfold = $srv ? case_fold_for $srv : sub { lc $_[0] };
		for my $acc (@{$ea->{$net}}) {
			$tree->{$cfold->($acc)} = 1;
		}
	}

	my $max_age = 0;
	my (%rs, %rsbe);
	for my $proto (@$raw) {
		my $type = $proto->{type};
		if ($type eq 'floodqueue' || $type eq 'splitflood') {
			$max_age = $proto->{window} if $proto->{window} > $max_age;
		}
		for my $k (grep /(?<![^\-])re\z/, keys %$proto) {
			$proto->{$k} = qr/$proto->{$k}/;
		}
		my $id = $proto->{id};
		$rs{$id} = $proto;
		$rsbe{$_}{$id} = undef for @{$proto->{events}};
	}

	%privileged_accounts = %$pa;
	%reporting_on = %$repmap;
	$global_blacklist_re = list2re @global_blacklist = map lc, @$gb;
	%exempt_accounts = %fea;
	%rules = %rs;
	%rules_by_event = map +($_ => [keys %{$rsbe{$_}}]), keys %rsbe;
	$sliding_history_max_age = $max_age;
}

sub prune_re {
	my ($href) = @_;
	my ($pre, $post) = split /,/, qr/,/;
	my %r;
	for my $k (keys %$href) {
		my $v = $href->{$k};
		if (ref($v) eq 'Regexp') {
			$v = "$v";
			my $t = $v;
			$v = $t if $t =~ s/^\Q$pre// && $t =~ s/\Q$post\E\z//;
		}
		$r{$k} = $v;
	}
	%r
}

sub rewrite_rules {
	my $rules_data = [map +{prune_re($rules{$_}), id => $_}, keys %rules];
	write_json_to 'rules.json', $rules_data;
}

sub rewrite_exempts {
	write_json_to 'exempt.json', { map +($_ => [sort keys %{$exempt_accounts{$_}}]), keys %exempt_accounts };
}

sub rewrite_blacklist {
	write_json_to 'global_blacklist.json', \@global_blacklist;
}

sub rewrite_config {
	rewrite_rules;
	rewrite_exempts;
	rewrite_blacklist;
}

our %severity_map = (
	debug => 0,
	info => 1,
	low => 2,
	medium => 3,
	high => 4,
);

our %last_report;

sub report_match {
	my ($server, $rule, $sender, $channel, $bonus) = @_;
	my $out = $reporting_on{$server->{chatnet}} or return;

	if ($channel) {
		my $now = time;
		my $cfold = case_fold_for $server;
		my $fchannel = $cfold->($channel);
		my $e = $last_report{$server->{tag}}{$fchannel} ||= {};
		if (
			$e->{severity} &&
			$severity_map{$e->{severity}} >= $severity_map{$rule->{severity}} &&
			$e->{timestamp} > $now - 45
		) {
			return;
		}
		$e->{severity} = $rule->{severity};
		$e->{timestamp} = $now;
	}

	$bonus ||= {};
	my $format = $rule->{format} || 'triggered rule $id';
	$format =~ s{\$(\$|\w+|\{\w+\})}{
		my $t = $1;
		s/^\{//, s/\}\z// for $t;
		$t eq '$' ? '$' :
		$t eq 'id' ? $rule->{id} :
		$t eq 'host' ? $sender->[2] :
		defined $bonus->{$t} ? $bonus->{$t} :
		''
	}eg;

	my $msg = "[$rule->{severity}] " . ($channel ? "[\cB$channel\cB] " : "") . "\cB$sender->[0]\cB - $format";

	if (my $chan = $server->channel_find($out)) {
		$chan->command("say $msg");
	} else {
		$server->print('', esc("$out ?? $msg"), Irssi::MSGLEVEL_CLIENTERROR); 
	}
}

sub generic_handler {
	my ($event, $server, $data, $nick, $address, $target) = @_;
	defined $address or return;
	$reporting_on{$server->{chatnet}} or return;

	my ($user, $host) = split /\@/, $address, 2;
	my $sender = [$nick, $user, $host];
	my $tag = $server->{tag};
	my $cfold = case_fold_for $server;
	my $fchannel;
	if ($target) {
		$server->ischannel($target) or return;
		$fchannel = $cfold->($target)
	}

	my $now = time;
	my $levencheck;
	my @matched_rules;

	my $account = eval { Irssi::Script::track_account::account_for($server, $nick) };
	unless ($account && $exempt_accounts{$server->{chatnet}}{$cfold->($account)}) {
		my @ids = @{$rules_by_event{$event} || []};

		for my $rule (@rules{@ids}) {
			my $matched;
			my $type = $rule->{type};

			if ($type eq 'msg-re') {
				if ($data =~ /$rule->{re}/) {
					$matched = 1;
				}
			} elsif ($type eq 'strbl') {
				if (lc($data) =~ /$global_blacklist_re/) {
					$matched = 1;
				}
			} elsif ($type eq 'nick') {
				if ($cfold->($nick) eq $cfold->($rule->{str})) {
					$matched = 1;
				}
			} elsif ($type eq 'user') {
				if (lc($user) eq lc($rule->{str})) {
					$matched = 1;
				}
			} elsif ($type eq 'host') {
				if (lc($host) eq lc($rule->{str})) {
					$matched = 1;
				}
			} elsif ($type eq 'realname') {
				my $realname = eval { Irssi::Script::track_account::realname_for($server, $nick) };
				defined $realname or next;
				if (lc($realname) eq lc($rule->{str})) {
					$matched = 1;
				}
			} elsif ($type eq 'sender') {
				my $realname = eval { Irssi::Script::track_account::realname_for($server, $nick) };
				defined $realname or next;
				if ("$nick!$user\@$host#$realname" =~ /$rule->{re}/) {
					$matched = 1;
				}
			} elsif ($type eq 'nickspam') {
				$fchannel or next;
				my $minlen = $rule->{minlen};
				my $nickcount = $rule->{nickcount};
				length $data >= $minlen or next;
				my $chan = $server->channel_find($target) or next;
				my $t = $cfold->($data);
				my %uniq;
				@uniq{grep !/[^a-zA-Z0-9\[\\\]\^_{|}~]/ && $chan->nick_find($_), $t =~ /[^\s,]+/g} = ();
				if (keys %uniq >= $nickcount) {
					$matched = 1;
				}
			} elsif ($type eq 'dnsbl') {
				my $on_addr = sub {
					my ($addr) = @_;
					my $qh = join('.', reverse split /\./, $addr) . '.' . $rule->{host};
					$ADNS->resolve(
						$qh,
						sub {},
						sub {
							my ($r) = @_;
							my $txt = $rule->{response}{$r} or return;
							report_match $server, $rule, $sender, $target, {result => $txt};
						},
					);
				};
				if ($host =~ m{^gateway/.*/ip\.([0-9]+(?:\.[0-9]+){3})\z}) {
					$on_addr->($1);
					next;
				}
				$ADNS->resolve(
					$host,
					sub {},
					$on_addr,
				);
			} elsif ($type eq 'levenflood') {
				$fchannel or next;
				$levencheck = 1;

				my $queue = $leven_history{$tag}{$fchannel}{$event};
				my $matches = 0;
				for my $msg (@$queue) {
					my $d = Text::LevenshteinXS::distance $data, $msg->{data};
					next if $d > 4;
					$matches++;
					if ($matches >= 5) {
						$matched = 1;
						last;
					}
				}
			} elsif ($type eq 'floodqueue') {
				$fchannel or next;

				my $window = $rule->{window};
				my $cutoff = $now - $window;
				my $threshold = $rule->{threshold};

				my $queue = $sliding_history{$tag}{$fchannel};
				my $matches = 0;
				for my $msg (@$queue) {
					next
						if $msg->{timestamp} < $cutoff
						|| $msg->{type} ne $event
						|| $msg->{sender}[2] ne $host
					;
					$matches++;
					if ($matches >= $threshold) {
						$matched = 1;
						last;
					}
				}
			} elsif ($type eq 'splitflood') {
				$fchannel or next;

				my $normalize = sub {
					my ($str) = @_;
					$str =~ s/^$rule->{'pre-re'}//   if $rule->{'pre-re'};
					$str =~ s/$rule->{'post-re'}\z// if $rule->{'post-re'};
					$str
				};

				my $canon = $normalize->($data);

				my $black = $temp_blacklist{$rule->{id}}{$canon};
				if ($black && $black >= $now) {
					$matched = 1;
					next;
				}

				my $window = $rule->{window};
				my $cutoff = $now - $window;
				my $threshold = $rule->{threshold};
				my $event_re = list2re @{$rule->{events}};

				my $queue = $sliding_history{$tag}{$fchannel};
				my $matches = 0;
				for my $msg (@$queue) {
					next
						if $msg->{timestamp} < $cutoff
						|| $msg->{type} !~ /^$event_re\z/
						|| $normalize->($msg->{data}) ne $canon
					;
					$matches++;
					if ($matches >= $threshold) {
						$matched = 1;
						add_to_temp_blacklist $rule->{id}, $canon, $now + 10 * 60;
						last;
					}
				}
			} else {
				$server->print('', esc("$IRSSI{name}: rule $rule->{id}: unknown type $type"), Irssi::MSGLEVEL_CLIENTERROR);
			}

			if ($matched) {
				push @matched_rules, $rule;
			}
		}
	}

	if (@matched_rules) {
		@matched_rules = sort { $severity_map{$b->{severity}} <=> $severity_map{$a->{severity}} } @matched_rules;
		my $severity = $matched_rules[0]{severity};
		for my $rule (@matched_rules) {
			last if $rule->{severity} ne $severity;
			report_match $server, $rule, $sender, $target;
		}
	}

	if ($fchannel) {
		add_to_history       $event, $server, $fchannel, $sender, $data;
		add_to_leven_history $event, $server, $fchannel, $sender, $data
			if $levencheck && length($data) >= 30;
	}
}

for my $signal ('message public', 'message private') {
	Irssi::signal_add_last $signal => sub {
		Irssi::signal_continue @_;
		my ($server, $msg, $nick, $address, $target) = @_;
		my $cfold = case_fold_for $server;

		my $account = eval { Irssi::Script::track_account::account_for($server, $nick) } or return;
		my $aflags = $privileged_accounts{$server->{chatnet}}{$cfold->($account)} or return;

		my $reply = sub { $server->command("msg $nick @_") };
		if ($target) {
			my $chan = $reporting_on{$server->{chatnet}} or return;
			$cfold->($target) eq $cfold->($chan) or return;
			$msg =~ s/^\Q$server->{nick}\E(?=[[:punct:]\s])//i or return;
			$msg =~ s/^[[:punct:]]+//;
			$reply = sub { $server->command("msg $target @_") };
		}
		$msg =~ s/^\s+//;
		$msg =~ s/^(\S+)\s*// or return;
		my $cmd = $1;

		if ($cmd eq 'mship' || $cmd eq 'channels') {
			$aflags =~ /t/ or return;
			my ($arg) = $msg =~ /^([a-zA-Z0-9\[\\\]\^_{|}~]+)\s*\z/
				or return $reply->("usage: $cmd NICK");
			my @cn = $server->nicks_get_same($arg);
			my @c;
			while (my ($c, $n) = splice @cn, 0, 2) {
				push @c, $c->{name};
			}
			@c = sort @c;
			$reply->("$arg is on: @c");
		} elsif ($cmd eq 'nicks') {
			$aflags =~ /t/ or return;
			my ($arg) = $msg =~ /^([a-zA-Z0-9\[\\\]\^_{|}~]+)\s*\z/
				or return $reply->("usage: $cmd ACCOUNT");
			my @nicks;
			eval { @nicks = Irssi::Script::track_account::nicks_for $server, $arg };
			@nicks = sort @nicks;
			$reply->("$arg is on: @nicks");
		} elsif ($cmd eq 'rehash') {
			$aflags =~ /a/ or return;
			reread_config;
			$reply->("ok");
		} elsif ($cmd eq 'reload') {
			$aflags =~ /a/ or return;
			Irssi::signal_emit 'reload script next', __PACKAGE__;
			$reply->("...");
		} elsif ($cmd eq 'exempt') {
			$aflags =~ /o/ or return;
			my ($arg) = $msg =~ /^([a-zA-Z0-9\[\\\]\^_{|}~]+)\s*\z/
				or return $reply->("usage: $cmd ACCOUNT");
			$exempt_accounts{$server->{chatnet}}{$cfold->($arg)} = 1;
			rewrite_exempts;
			$reply->("$arg exempted");
		} elsif ($cmd eq 'inempt') {
			$aflags =~ /o/ or return;
			my ($arg) = $msg =~ /^([a-zA-Z0-9\[\\\]\^_{|}~]+)\s*\z/
				or return $reply->("usage: $cmd ACCOUNT");
			delete $exempt_accounts{$server->{chatnet}}{$cfold->($arg)};
			rewrite_exempts;
			$reply->("$arg inempted");
		} elsif ($cmd eq 'blacklist') {
			$aflags =~ /o/ or return;
			$msg =~ /\S/
				or return $reply->("usage: $cmd STRING");
			my $str = lc $msg;
			$str =~ /$global_blacklist_re/
				and return $reply->("$msg is already blacklisted");
			push @global_blacklist, $str;
			$global_blacklist_re = list2re @global_blacklist;
			rewrite_blacklist;
			$reply->("$msg blacklisted");
		} elsif (!$target) {
			$reply->("unknown command: $cmd");
		}
	};
}

sub defgenhandler {
	my ($signal, $event, $indices) = @_;
	Irssi::signal_add $signal => sub {
		Irssi::signal_continue @_;
		generic_handler $event, @_[@$indices];
	};
}

defgenhandler 'message public'     => 'public',   [0 .. 4];
defgenhandler 'message part'       => 'part',     [0, 4, 2, 3, 1];
defgenhandler 'message join'       => 'join',     [0, 2, 2, 3, 1];
defgenhandler 'message quit'       => 'quit',     [0, 3, 1, 2];
defgenhandler 'message topic'      => 'topic',    [0, 2, 3, 4, 1];
defgenhandler 'message irc notice' => 'notice',   [0 .. 4];
defgenhandler 'ctcp action'        => 'action',   [0 .. 4];
defgenhandler 'ctcp msg dcc'       => 'cdcc',     [0 .. 4];
defgenhandler 'ctcp msg ping'      => 'cping',    [0 .. 4];
defgenhandler 'ctcp msg version'   => 'cversion', [0 .. 4];

Irssi::signal_add 'event connected' => sub {
	my ($server) = @_;
	my $net = $server->{chatnet};
	my $chan = $reporting_on{$net};
	if ($chan && !$server->channel_find($chan)) {
		$server->command("join $chan");
	}
};

reread_config;
