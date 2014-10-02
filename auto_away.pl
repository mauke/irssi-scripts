use strict;
use warnings;

use Irssi ();
use Time::HiRes qw(time);

our $VERSION = '0.02';
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

my $_message;
my $_time;
on_settings_change {
    $_message = Irssi::settings_get_str  "$IRSSI{name}_message";
    $_time    = Irssi::settings_get_time "$IRSSI{name}_time";
};

my $detected_state_away;
my $last_keypress_ts;

sub start_timer {
    $last_keypress_ts = time;
    Irssi::timeout_add_once $_time, \&ding, undef;
}

sub go_away {
    $detected_state_away = 1;
    for my $srv (Irssi::servers) {
        next if $srv->{chat_type} ne 'IRC' || $srv->{usermode_away};
        $srv->command("away -one $_message");
    }
}

sub come_back {
    $detected_state_away = 0;
    for my $srv (Irssi::servers) {
        next if $srv->{chat_type} ne 'IRC' || !$srv->{usermode_away};
        $srv->command("away -one");
    }
    start_timer;
}

sub ding {
    my $delta = $_time - int((time - $last_keypress_ts) * 1000);
    if ($delta < 10) {
        go_away;
        return;
    }

    Irssi::timeout_add_once $delta, \&ding, undef;
}

Irssi::signal_add 'gui key pressed' => sub {
    my ($c) = @_;
    if ($detected_state_away) {
        come_back if $c == ord "\n";
    } else {
        $last_keypress_ts = time;
    }
};

start_timer;
