use v5.16.0;
use warnings;
use Irssi ();

our $VERSION = '0.01';

our %IRSSI = (
    name        => 'get_mono',
    authors     => 'mauke',
    description => "Turn the IRC format code for monospace (Ctrl-Q) into gray background",
);

my $target_color = "\cC00,90";

for my $signal (
    'message public',
    'message private',
    'message irc action',
) {
    Irssi::signal_add_first $signal => sub {
        my ($server, $msg, $nick, $address, $target) = @_;
        #$msg =~ tr/\cQ/\c]/ or return;
        $msg =~ /\cQ/ or return;
        my $default_reset_color = "\cC\cB\cB";
        my $reset_color = $default_reset_color;
        my $in_q = 0;
        $msg =~ s{
            (
                [\cQ\cO]
            |
                \cC (?: ( [0-9]{1,2} ) (?: , ( [0-9]{1,2} ) )? )?
            )
        }{
            my $subst;
            if ($1 eq "\cQ") {
                $subst = $in_q ? $reset_color : $target_color;
                $in_q = !$in_q;
            } elsif ($1 eq "\cO") {
                $subst = $1;
                $in_q = 0;
                $reset_color = $default_reset_color;
            } elsif ($1 eq "\cC") {
                $subst = $in_q ? $target_color : $1;
                $reset_color = $default_reset_color;
            } else {
                $subst = $1;
                $reset_color = defined $3
                    ? sprintf "\cC%02u,%02u", $2, $3
                    : sprintf "\cC%02u\cB\cB", $2;
            }
            $subst
        }xeg
            or return;
        Irssi::signal_continue $server, $msg, $nick, $address, $target;
    };
}
