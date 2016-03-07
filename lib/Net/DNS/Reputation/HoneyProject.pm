package Net::DNS::Reputation::HoneyProject;

use Net::DNS::Simple;
use 5.00006;
use strict;
use warnings;

require Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
@ISA = qw(Exporter);

%EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

@EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

@EXPORT = qw(
	
);

$VERSION = '0.01';

sub new {
	my $class = shift;
	my $args = shift;

	my $self = {
		_ip_addr => $args->{ipaddr},
		_honey_key => $args->{key},
		_method => $args->{method},
		_dhoneypot => '.dnsbl.httpbl.org',
	};

	my $object = bless $self, $class;
	$object->set_ipaddr;
	return $object;
}

sub set_ipaddr {
	my $self = shift;

	my @ip4 = split /\./, $self->{_ip_addr};
	#check for reverse first
	if ($self->{_ip_addr} =~ m/in-addr.arpa/is) {
		$self->{_ip_addr} = $ip4[0].".".$ip4[1].".".$ip4[2].".".$ip4[3];
		return;
	}

	#tip from txt2re.com
	my $re1='((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?![\\d])';# IPv4 IP Address 1
	my $re=$re1;
	if ($self->{_ip_addr} =~ m/$re/is) {
		$self->{_ip_addr} = $ip4[3].".".$ip4[2].".".$ip4[1].".".$ip4[0];
		return;
	}

}

sub get_response_short {
	my ($self, $array_ref) = @_;
	for my $entry (@{$array_ref}) {
		my @rr = split /\t/, $entry;
		return $rr[-1]; #ip address at last position
	}
}

sub get_treat_score {
	my ($self, $score) = @_;

	#25 100 spam messages
	#50 10,000 spam messages
	#75 1,000,000 spam messages
	return "low"    if ($score <= 25);
	return "medium" if ($score > 25 and $score <= 50);
	return "high"   if ($score > 50 and $score <= 75);
}

sub get_visitor_type {
	my ($self, $score) = @_;
	# Because the fourth octet is a bitset, visitors that have identified
	# as falling into multiple categories may be represented. 
	return "Search Engine"                        if ( $score == 0 );
	return "Suspicious"                           if ( $score == 1 );
	return "Harvester"                            if ( $score == 2 );
	return "Suspicious/Harvester"                 if ( $score == 3 );
	return "Comment Spammer"                      if ( $score == 4 );
	return "Suspicious/Comment Spammer"           if ( $score == 5 );
	return "Harvester/Comment Spammer"            if ( $score == 6 );
	return "Suspicious/Harvester/Comment Spammer" if ( $score == 7 );
	return "Reserved for Future Use"              if ( $score > 7 );
}

sub get_response_long {
	my $self = shift;
	my $array_ref = shift;
	my @rr;
	for my $entry (@{$array_ref}) { @rr = split /\t/, $entry; }

	my @ip_array = split/\./, $rr[-1];

	#http://www.projecthoneypot.org/httpbl_api.php
	#Amout of days
	my $days = $ip_array[1]; #2nd octet

	#http://www.projecthoneypot.org/threat_info.php
	my $treat = $self->get_treat_score($ip_array[2]); #3rd octet
	
	# This is a bug fix when answers come with 'number_space_)'
	# Very hard to reproduce!
	# Remove any white space and etc.
	if ( length($ip_array[3]) >= 2 ) { $ip_array[3]=~s/\ .*//g; }
	my $user_type = $self->get_visitor_type($ip_array[3]); #4th octet

	my $ip=$ip_array[0].".".$ip_array[1].".".$ip_array[2].".".$ip_array[3];

	my $long_response=$ip . "\t" . $days . "\t" . $treat . "\t" . $user_type;

	return $long_response;
}

sub get_response {
	my $self = shift;
	my $domain = $self->{_honey_key}. "." . $self->{_ip_addr}.$self->{_dhoneypot};
	my $res = Net::DNS::Simple->new($domain, "A");

	if ( $res->get_rcode() eq "NOERROR" and $res->get_ancount() >= 1 ) {

		if ( $self->{_method} eq "fast" ) { return 1; }

		my @entry = $res->get_answer_section();

		if ( $self->{_method} eq "short" ) {
			return $self->get_response_short(\@entry); #array_ref
		}

		if ( $self->{_method} eq "long" ) {
			return $self->get_response_long(\@entry); #array_ref
		}
	}
	return "";
}

1;

__END__

=head1 NAME

Net::DNS::Reputation::HoneyProject - Perl extension for sending DNS requests to Project Honey Pot.

=head1 SYNOPSIS

  use Net::DNS::Reputation::HoneyProject;
  ...
  my $res = Net::DNS::Reputation::HoneyProject->new({
		ipaddr => 'IP Address / Reversed IP',
		key => 'Honey Key',
		method => 'fast/short/long', 
	});

  print $res->get_response(), "\n";

=head1 DESCRIPTION

Net::DNS::Reputation::HoneyProject is a extension to send DNS requests to Project Honey Pot, and
provide useful DNS responses. 

=head2 EXPORT

None by default.

=head1 SEE ALSO

Net::DNS::Reputation::TeamCymru
Net::DNS::Simple

=head1 AUTHOR

Kaio Rafael, @kaiux

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016 by Kaio Rafael

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see L<http://www.gnu.org/licenses/>.

=cut
