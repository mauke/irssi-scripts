use strict;
use warnings;

use Irssi ();
use Time::HiRes qw(time);

our $VERSION = '0.03';
our %IRSSI = (
    authors => 'mauke',
    name    => 'auto_away',
);

sub on_settings_change (&) {
    my ($f) = @_;
    Irssi::signal_add 'setup changed', $f;
    $f->();
}

Irssi::settings_add_str  $IRSSI{name}, "$IRSSI{name}_message", "zZzZ";
Irssi::settings_add_time $IRSSI{name}, "$IRSSI{name}_time",    '23m';

my $here_heartbeat;
my $last_keypress_ts;

my $_message;
my $_time;

sub start_timer {
    $last_keypress_ts = time;
    $here_heartbeat = Irssi::timeout_add_once $_time, \&ding, undef;
}

sub go_away {
    for my $srv (Irssi::servers) {
        next if $srv->{chat_type} ne 'IRC' || $srv->{usermode_away};
        $srv->command("away -one $_message");
    }
}

sub come_back {
    for my $srv (Irssi::servers) {
        next if $srv->{chat_type} ne 'IRC' || !$srv->{usermode_away};
        $srv->command("away -one");
    }
    start_timer;
}

sub ding {
    my $delta = $_time - int((time - $last_keypress_ts) * 1000);
    if ($delta < 10) {
        $here_heartbeat = undef;
        go_away;
        return;
    }

    $here_heartbeat = Irssi::timeout_add_once $delta, \&ding, undef;
}

Irssi::signal_add 'gui key pressed' => sub {
    my ($c) = @_;
    if ($here_heartbeat) {
        $last_keypress_ts = time;
    } else {
        come_back if $c == ord "\n";
    }
};

on_settings_change {
    my $prev_time = $_time;
    $_message = Irssi::settings_get_str  "$IRSSI{name}_message";
    $_time    = Irssi::settings_get_time "$IRSSI{name}_time";
    if ($here_heartbeat && $_time < $prev_time) {
        Irssi::timeout_remove $here_heartbeat;
        ding;
    }
};

start_timer;
