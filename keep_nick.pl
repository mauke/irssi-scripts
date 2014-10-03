use strict;
use warnings;

use Irssi ();

our $VERSION = '0.02';
our %IRSSI = (
    authors => 'mauke',
    name    => 'keep_nick',
);

sub fuzzy {
    my ($x) = @_;
    int($x / 2 + rand $x)
}

Irssi::settings_add_time $IRSSI{name}, "$IRSSI{name}_delay", '5m';

my %active;

sub cantnick {
    my ($srv, $data) = @_;
    my (undef, $wanted_nick) = split / /, $data;
    $wanted_nick =~ s/^://;
    return if $wanted_nick =~ /^[#&!+]/;
    my $tag = $srv->{tag};
    return if $active{$tag};
    $active{$tag} = Irssi::timeout_add_once
        fuzzy(Irssi::settings_get_time "$IRSSI{name}_delay"),
        sub {
            delete $active{$tag};
            my $server = Irssi::server_find_tag $tag or return;
            my $current_nick = $server->{nick};
            return if $server->mask_match("$current_nick!*\@*", $wanted_nick, 'x', 'y');
            $server->command("nick $wanted_nick");
        },
        undef,
    ;
}

Irssi::signal_add 'message own_nick' => sub {
    my ($server, $newnick, $oldnick, $address) = @_;
    $server->{connected} or return;
    my $tag = $server->{tag};
    my $timer = delete $active{$tag} or return;
    Irssi::timeout_remove $timer;
};

Irssi::signal_add 'event 433' => \&cantnick;
Irssi::signal_add 'event 437' => \&cantnick;
