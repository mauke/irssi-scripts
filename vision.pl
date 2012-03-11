##############################################################################
# config layout:
# ~/
#   .irssi/
#     vision.d/
#       rules.json
#       net.$network/ (where $network = efnet, freenode, ...)
#         report_channel
#         exempt.json
#         blacklist.json
#         accounts.json
#
##############################################################################
# schema:
# * report_channel = channel name
# * exempt.json = [(string) account]
# * accounts.json = map<(string) account, (string) flags>
# * blacklist.json = [string]
# * rules.json = [rule]
#   rule = {
#     id: unique string,
#     type: (string) msg-re | strbl | nick | user | host | realname | sender |
#                    nickspam | dnsbl | levenflood | floodqueue | splitflood,
#     severity: (string) debug | info | low | medium | high,
#     events: [event],
#     format: string,
#     (mention: [(string) account],)?
#     ...: rule_variant<type>
#   }
#   event = (string) join | part | quit | public | action | topic | notice |
#                    cdcc | cping | cversion
#   rule_variant =
#     <msg-re> re: regex string |
#     <strbl> |
#     <nick> str: string |
#     <user> str: string |
#     <host> str: string |
#     <realname> str: string |
#     <sender> re: regex string |
#     <nickspam> minlen: int, nickcount: int |
#     <dnsbl> host: string, response: dnsbl_response |
#     <levenflood> |
#     <floodqueue> window: int, threshold: int |
#     <splitflood> window: int, threshold: int
#                  (, pre-re: regex string)?
#                  (, post-re: regex string)?
#   dnsbl_response: map<(string) ip address, (string) description>
#

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
use again 'Data::Munge' => qw(list2re submatches); BEGIN { Data::Munge->VERSION('0.04') }
use again 'List::Util' => qw(max);

our $VERSION = '0.035';

our %IRSSI = (
	authors => 'mauke',
	name => 'vision',
);

our $ADNS = IrssiX::ADNS->new;

sub realname_for {
	my ($server, $nick) = @_;
	eval { Irssi::Script::track_account::realname_for($server, $nick) }
}

sub account_for {
	my ($server, $nick) = @_;
	eval { Irssi::Script::track_account::account_for($server, $nick) }
}

sub nicks_for {
	my ($server, $account) = @_;
	my @nicks;
	eval { @nicks = Irssi::Script::track_account::nicks_for($server, $account) };
	@nicks
}

sub nick_kinda_for {
	my ($server, $account, $channel) = @_;
	my @nicks = nicks_for $server, $account or return undef;
	$channel or return $nicks[0];
	my $chan = $server->channel_find($channel) or return $nicks[0];
	for my $nick (@nicks) {
		return $nick if $chan->nick_find($nick);
	}
	$nicks[0]
}

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

	$sliding_history_gc_tag = timer_add_once 1000 * max(20, $next - $now), \&sliding_history_gc;
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

sub trim {
	my ($s) = @_;
	s/^\s+//, s/\s+\z// for $s;
	$s
}

sub slurp { local $/; readline $_[0] }

sub read_net_json_from_default {
	my ($net, $file, $def) = @_;
	$file = "$DIR/" . ($net eq '*' ? '' : "net.$net/") . $file;
	my $fh = fopen_nothrow $file, 'rb';
	if (!$fh) {
		$!{ENOENT} or die "$file: $!";
		return $def;
	}
	my $r = decode_json slurp $fh;
	ref($r) eq ref($def) or die "$file: type doesn't match default (${\ref $def})";
	$r
}

sub write_net_json_to {
	my ($net, $file, $data) = @_;
	my $dir = $DIR . ($net eq '*' ? '' : "/net.$net");
	mkdir($dir) || $!{EEXIST} or die "$dir: $!";
	$file = "$dir/$file";
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

our %blacklist;
our %blacklist_re;
our %exempt_accounts;
our %privileged_accounts;
our %channel_properties;

sub reread_net_config {
	my ($net) = @_;
	my $repchan = do {
		my $file = "$DIR/net.$net/report_channel";
		my $fh = fopen_nothrow $file;
		$fh ? trim slurp $fh :
		$!{ENOENT} ? undef :
		die "$file: $!"
	};
	my $ea = read_net_json_from_default $net, 'exempt.json', [];
	my $bl = read_net_json_from_default $net, 'blacklist.json', [];
	my $pa = read_net_json_from_default $net, 'accounts.json', {};
	my $cp = read_net_json_from_default $net, 'channels.json', {};

	my $server = Irssi::server_find_chatnet($net);
	my $cfold = $server ? case_fold_for $server : sub { lc $_[0] };
	my %fea;
	for my $acc (@$ea) {
		$fea{$cfold->($acc)} = 1;
	}
	my %fcp;
	for my $c (keys %$cp) {
		$fcp{$cfold->($c)} = $cp->{$c};
	}

	return {
		reporting_on => $repchan,
		privileged_accounts => $pa,
		blacklist => $bl,
		exempt_accounts => \%fea,
		channel_properties => \%fcp,
	};
}

sub reread_config {
	my $rules_raw = read_net_json_from_default '*', 'rules.json', [];
	my $max_age = 0;
	my (%rs, %rsbe);
	for my $proto (@$rules_raw) {
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

	my (%repmap, %pa, %bl, %bl_re, %ea, %cp);
	for my $server (Irssi::servers) {
		my $net = $server->{chatnet};
		my $conf = reread_net_config $net;
		$repmap{$net} = $conf->{reporting_on};
		$pa{$net} = $conf->{privileged_accounts};
		$bl{$net} = $conf->{blacklist};
		$bl_re{$net} = list2re @{$bl{$net}};
		$ea{$net} = $conf->{exempt_accounts};
		$cp{$net} = $conf->{channel_properties};
	}

	%reporting_on = %repmap;
	%privileged_accounts = %pa;
	%blacklist = %bl;
	%blacklist_re = %bl_re;
	%exempt_accounts = %ea;
	%channel_properties = %cp;

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
	write_net_json_to '*', 'rules.json', $rules_data;
}

sub rewrite_net_exempts {
	my ($net) = @_;
	write_net_json_to $net, 'exempt.json', [sort keys %{$exempt_accounts{$net}}];
}

sub rewrite_net_blacklist {
	my ($net) = @_;
	write_net_json_to $net, 'blacklist.json', \@{$blacklist{$net}};
}

sub rewrite_config {
	rewrite_rules;
	rewrite_net_exempts $_ for keys %exempt_accounts;
	rewrite_net_blacklist $_ for keys %blacklist;
}

our %severity_level = (
	debug => 0,
	info => 1,
	low => 2,
	medium => 3,
	high => 4,
);
our @severities = sort { $severity_level{$a} <=> $severity_level{$b} } keys %severity_level;

sub severity_fancy {
	my ($x) = @_;
	my $c =
		$x eq 'debug'  ? '13' :
		$x eq 'info'   ? '12' :
		$x eq 'low'    ? '09' :
		$x eq 'medium' ? '08' :
		$x eq 'high'   ? '04' :
		''
	;
	"\cC$c\x{25CF}\cC$x"
}

our %last_report;

sub report_match {
	my ($server, $rule, $sender, $channel, $bonus) = @_;
	my $out = $reporting_on{$server->{chatnet}} or return;

	my $fchannel;
	if ($channel) {
		my $now = time;
		my $cfold = case_fold_for $server;
		$fchannel = $cfold->($channel);
		my $e = $last_report{$server->{tag}}{$fchannel} ||= {};
		if (
			$e->{severity} &&
			$severity_level{$e->{severity}} >= $severity_level{$rule->{severity}} &&
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

	my $msg = "${\severity_fancy $rule->{severity}} " . ($channel ? "[\cB$channel\cB] " : "") . "\cB$sender->[0]\cB - $format";

	my $ext = '';
	my @targets;
	{
		my (%mention_accounts, %target_accounts);

		if ($rule->{mention}) {
			@mention_accounts{@{$rule->{mention}}} = ();
		}

		my $rule_severity_level = $severity_level{$rule->{severity}};

		for my $prop (grep $_, $fchannel && $channel_properties{$fchannel}, $channel_properties{'*'}) {
			if (my $mess = $prop->{message}) {
				for my $sev (@severities) {
					next if $severity_level{$sev} > $rule_severity_level;
					@target_accounts{@{$mess->{$sev}}} = ();
				}
			}
			if (my $ment = $prop->{mention}) {
				for my $sev (@severities) {
					next if $severity_level{$sev} > $rule_severity_level;
					@mention_accounts{@{$ment->{$sev}}} = ();
				}
			}
		}

		my @mention = grep $_, map nick_kinda_for($server, $_, $out), sort keys %mention_accounts;
		$ext = ' @ ' . join(', ', @mention) if @mention;

		@targets = grep $_, map nick_kinda_for($server, $_, $fchannel), sort keys %target_accounts;
	}

	if (my $chan = $server->channel_find($out)) {
		$chan->command("say $msg$ext");
	} else {
		$server->print('', esc("$out ?? $msg$ext"), Irssi::MSGLEVEL_CLIENTERROR); 
	}
	$server->command("^msg ${\join ',', @targets} $msg") if @targets;
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

	my $account = account_for($server, $nick) || '';
	unless ($account && $exempt_accounts{$server->{chatnet}}{$cfold->($account)}) {
		if ($event eq 'join') {
			$data = "$nick!$user\@$host?$account#" . (realname_for($server, $nick) || '');
		}

		my @ids = @{$rules_by_event{$event} || []};

		for my $rule (@rules{@ids}) {
			my %bonus;
			my $matched;
			my $type = $rule->{type};

			if ($type eq 'msg-re') {
				if ($data =~ /$rule->{re}/) {
					$matched = 1;
					my $i = 1;
					for my $m (submatches) {
						$bonus{$i++} = $m;
					}
				}
			} elsif ($type eq 'strbl') {
				my $net = $server->{chatnet};
				if ($blacklist_re{$net} && lc($data) =~ /$blacklist_re{$net}/) {
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
				my $realname = realname_for($server, $nick);
				defined $realname or next;
				if (lc($realname) eq lc($rule->{str})) {
					$matched = 1;
				}
			} elsif ($type eq 'sender') {
				my $realname = realname_for($server, $nick);
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
				push @matched_rules, [$rule, \%bonus];
			}
		}
	}

	if (@matched_rules) {
		@matched_rules = sort { $severity_level{$b->[0]{severity}} <=> $severity_level{$a->[0]{severity}} } @matched_rules;
		my $severity = $matched_rules[0][0]{severity};
		for my $pair (@matched_rules) {
			my ($rule, $bonus) = @$pair;
			last if $rule->{severity} ne $severity;
			report_match $server, $rule, $sender, $target, $bonus;
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

		my $net = $server->{chatnet};
		my $account = account_for($server, $nick) or return;
		my $aflags = $privileged_accounts{$net}{$cfold->($account)} or return;

		my $reply = sub { $server->command("msg $nick @_") };
		if ($target) {
			my $chan = $reporting_on{$net} or return;
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
			my @nicks = nicks_for $server, $arg;
			@nicks = sort @nicks;
			$reply->("$arg is on: @nicks");

		} elsif ($cmd eq 'rehash') {
			$aflags =~ /a/ or return;
			eval { reread_config; 1 } or return $reply->("something done fucked up");
			$reply->("ok");

		} elsif ($cmd eq 'reload') {
			$aflags =~ /a/ or return;
			eval { reread_config; 1 } or return $reply->("something done fucked up");
			Irssi::signal_emit 'reload script next', __PACKAGE__;
			$reply->("...");

		} elsif ($cmd eq 'join') {
			$aflags =~ /a/ or return;
			my ($arg) = $msg =~ /^(#\S+)\s*\z/
				or return $reply->("usage: $cmd CHANNEL");
			$server->command("join $arg");
			$reply->("yes");

		} elsif ($cmd eq 'part') {
			$aflags =~ /a/ or return;
			my ($arg) = $msg =~ /^(#\S+)\s*\z/
				or return $reply->("usage: $cmd CHANNEL");
			$server->command("part $arg");
			$reply->("yes");

		} elsif ($cmd eq 'exempt') {
			$aflags =~ /o/ or return;
			my ($arg) = $msg =~ /^([a-zA-Z0-9\[\\\]\^_{|}~]+)\s*\z/
				or return $reply->("usage: $cmd ACCOUNT");
			$exempt_accounts{$net}{$cfold->($arg)} = 1;
			rewrite_net_exempts $net;
			$reply->("$arg exempted");

		} elsif ($cmd eq 'inempt') {
			$aflags =~ /o/ or return;
			my ($arg) = $msg =~ /^([a-zA-Z0-9\[\\\]\^_{|}~]+)\s*\z/
				or return $reply->("usage: $cmd ACCOUNT");
			delete $exempt_accounts{$net}{$cfold->($arg)};
			rewrite_net_exempts $net;
			$reply->("$arg inempted");

		} elsif ($cmd eq 'blacklist') {
			$aflags =~ /o/ or return;
			$msg =~ /\S/
				or return $reply->("usage: $cmd STRING");
			my $str = lc $msg;
			$blacklist_re{$net} && $str =~ /$blacklist_re{$net}/
				and return $reply->("$msg is already blacklisted");
			push @{$blacklist{$net}}, $str;
			$blacklist_re{$net} = list2re @{$blacklist{$net}};
			rewrite_net_blacklist $net;
			$reply->("$msg blacklisted");

		} else {
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

	my $conf = reread_net_config $net;
	$privileged_accounts{$net} = $conf->{privileged_accounts};
	$blacklist{$net} = $conf->{blacklist};
	$blacklist_re{$net} = list2re @{$blacklist{$net}};
	$exempt_accounts{$net} = $conf->{exempt_accounts};
	$channel_properties{$net} = $conf->{channel_properties};
	my $chan = $reporting_on{$net} = $conf->{reporting_on};

	if ($chan && !$server->channel_find($chan)) {
		$server->command("join $chan");
	}
};

Irssi::signal_add 'server disconnected' => sub {
	my ($server) = @_;
	my $net = $server->{chatnet};
	delete $_->{$net} for \(%reporting_on, %privileged_accounts, %blacklist, %blacklist_re, %exempt_accounts, %channel_properties);
};

reread_config;

for my $server (Irssi::servers) {
	my $net = $server->{chatnet};
	my $out = $reporting_on{$server->{chatnet}} or next;
	my $chan = $server->channel_find($out) or next;
	$chan->command("say goliath online.");
}
