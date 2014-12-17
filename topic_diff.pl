use strict;
use warnings;

use Irssi ();

use Algorithm::Diff qw(sdiff);

our $VERSION = '0.02';
our %IRSSI = (
    authors => 'mauke',
    name    => 'topic_diff',
);

sub on_settings_change (&) {
    my ($f) = @_;
    Irssi::signal_add 'setup changed', $f;
    $f->();
}

sub esc {
    my ($x) = @_;
    $x =~ s/%/%%/g;
    $x
}

sub rtrim {
    my ($x) = @_;
    $x =~ s/\s+\z//;
    $x
}

Irssi::settings_add_str $IRSSI{name}, "$IRSSI{name}_chunk_re", '\s+|\w+|[^\s\w]+';

my $_chunk_re;
on_settings_change {
    my $x = Irssi::settings_get_str "$IRSSI{name}_chunk_re";
    $_chunk_re = qr/(?:$x)|./s;
};

sub chunks {
    my ($str) = @_;
    my @r;
    while ($str =~ /$_chunk_re/g) {
        push @r, substr $str, $-[0], $+[0] - $-[0];
    }
    \@r
}

my %format = (
    'u' => ['',   '',   '',   ''  ],
    'c' => ['%y', '%n', '%y', '%n'],
    '+' => ['',   '',   '%g', '%n'],
    '-' => ['%r', '%n', '',   ''  ],
);

Irssi::signal_add 'message topic' => sub {
    my ($server, $channame, $topic_new, $nick, $address) = @_;
    my $channel = $server->channel_find($channame) or return;
    my $topic_old = $channel->{topic};

    $topic_old && $topic_old =~ /\S/ && rtrim($topic_old) ne rtrim($topic_new)
        or return;

    my $diff = sdiff chunks($topic_old), chunks($topic_new);
    
    my $d_old = '';
    my $d_new = '';
    for my $hunk (@$diff) {
        my ($t, $x, $y) = @$hunk;
        my $f = $format{$t};
        $d_old .= $f->[0] . esc($x) . $f->[1];
        $d_new .= $f->[2] . esc($y) . $f->[3];
    }

    Irssi::signal_stop;
    $channel->print(".topic %W${\esc $channame}%n %W${\esc $nick}%n:", MSGLEVEL_TOPICS);
    $channel->print("%K<<%n $d_old", MSGLEVEL_TOPICS);
    $channel->print("%K>>%n $d_new", MSGLEVEL_TOPICS);
};
