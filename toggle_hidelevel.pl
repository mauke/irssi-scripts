use v5.16.0;
use warnings;
use Irssi ();

our $VERSION = '0.01';

our %IRSSI = (
    name    => 'toggle_hidelevel',
    authors => 'mauke',
);

Irssi::command_bind 'window toggle_hidelevel' => sub {
    my ($data, $server, $witem) = @_;
    $witem or return;
    my $view = $witem->window->view;
    my $level = Irssi::level2bits $data;
    $view->set_hidden_level($view->{hidden_level} ^ $level);
    $view->redraw;
};
