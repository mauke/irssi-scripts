use warnings;
use strict;

use Irssi ();

use Dir::Self;
use lib __DIR__ . '/lib';

use again 'IrssiX::Util' => qw(later);

our $VERSION = '0.02';

our %IRSSI = (
	authors => 'mauke',
	name => 'reloader',
);

Irssi::signal_register {
	'reload script next' => [qw(string)],
};

Irssi::signal_add 'reload script next' => sub {
	my ($script) = @_;
	$script =~ s/^Irssi::Script:://;
	later {
		Irssi::command "script unload $script";
		Irssi::command "script load $script";
	};
};
