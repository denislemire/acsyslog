#!/usr/bin/perl

use strict;
use warnings;

open (ACLOG, "combined.log") or die ("Unable to open log");

my $calls = {};
my $grabnext = 0;
my $nextpacket = undef;

sub dump_calls
{
	foreach my $call (keys $calls) {
		next unless (@{$calls->{$call}->{packets}}[0]->{Payload} =~ /^INVITE/i);

		print "SIP messages for call $call\n\n";

		foreach my $packet (@{$calls->{$call}->{packets}}) {
			printf ("\t%s %s %s\n\n", $packet->{Timestamp}, $packet->{Direction}, $packet->{Destination});

			#print $packet->{Payload} . "\n\n";
			foreach my $line (split ("\n", $packet->{Payload})) {
				print "\t\t$line\n";
			}

			print "\n";
		}
	}
}

sub dump_calls_summary
{
	foreach my $call (keys $calls) {
		next unless (@{$calls->{$call}->{packets}}[0]->{Payload} =~ /^INVITE/i);

		print "SIP messages for call $call\n\n";

		foreach my $packet (@{$calls->{$call}->{packets}}) {
			my $firstline;

			foreach my $line (split ("\n", $packet->{Payload})) {
				$firstline = $line;
				last;
			}

			if ($packet->{Direction} eq "Incoming") {
				printf ("\t%s %s ---> %s\n", $packet->{Timestamp}, $packet->{Destination}, $firstline);
			} else {
				printf ("\t%s %s <--- %s\n", $packet->{Timestamp}, $packet->{Destination}, $firstline);
			}

		}
		print "\n\n\n";
	}
}


while (<ACLOG>)
{
	if (defined ($nextpacket)) {
		if ($_ =~ /\[SID.+\] (.+)/) {
			my $msg = $1;
			my $callid = undef;

			$msg =~ s/  /\n/g;

			if ($msg =~ /CALL-ID: +(.+)/i) {
				$callid = $1;

				if (defined ($calls->{$callid})) {

				} else {
					#print "New call found, $callid\n";

					my @packets;

					$calls->{$callid} = {};
					$calls->{$callid}->{packets} = \@packets;
				}

				my $packet = { 
					Timestamp => $nextpacket->{Timestamp},
					Direction => $nextpacket->{Direction},
					Destination => $nextpacket->{Destination},
					Payload => $msg
				};

				push $calls->{$callid}->{packets},$packet;
			} else {
				die "Packet with no call-id:\n\n$msg";
			}
		}
		undef ($nextpacket);
	}

	if ($_ =~ /(\d+:\d+:\d+.\d+) :.+(Incoming|Outgoing) SIP Message (?:from|to) (.+) (?:to|from) SIPInterface/) {
		$nextpacket = { Timestamp => $1, Direction => $2, Destination => $3 };
	}
}

close (ACLOG);

#dump_calls();
dump_calls_summary();
