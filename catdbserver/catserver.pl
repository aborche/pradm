#!/usr/bin/perl
#
# Copyright (C) 2010 Kaltashkin Eugene <aborche@aborche.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Date: 2010-05-15 20:08:13 +0400 (сб, 15 май 2010) $
# $Revision: 65 $
# $LastChangedBy: zhecka $

use strict;
use IO::Socket;
use IO::Multiplex;
use Getopt::Std;
use DB_File;
use Digest::MD5 qw(md5_hex);

use vars qw /
    %groups %categories $PORTNO $result
    %opts %types $curtype %dom %domains $pidfile $listensocket
    %typesrev $dbfile $typesfile $recursivecheck/;

$Getopt::Std::STANDARD_HELP_VERSION = 1;
getopts('hvsdw:p:P:', \%opts);

if($opts{h})
{
  &HELP_MESSAGE;
}

$recursivecheck = 'off'; # change 'off' to 'on' if you want use recursive check for domain name
                         # (resolve ip of current domain name and check this ip in catserver database
$PORTNO = $opts{P} || '6510';
$listensocket = IO::Socket::INET->new(	LocalPort => $PORTNO,
				   	Proto	=> "udp",
				   	Blocking => 0
				     )  or die "Can't be a UDP server on port $PORTNO : $!\n";

undef $opts{v} if($opts{d});
$pidfile = $opts{p} || '/var/tmp/catserver.pid';

my $workdirectory = $opts{w} || '/usr/local/squid/catdbserver/';
$workdirectory .= '/' if($opts{w} !~ /\/$/ && defined($opts{w}));
$dbfile = $workdirectory."domains.tmp";
$typesfile = $workdirectory."types.tmp";

tie %domains, "DB_File", $dbfile, O_RDONLY, 0666, $DB_HASH or die "Cannot open file $dbfile: $!\n";
tie %types, "DB_File", $typesfile, O_RDONLY, 0666, $DB_HASH or die "Cannot open file $typesfile: $!\n";
%typesrev = reverse %types;

$SIG{HUP} = sub {
print STDERR "HANGUP signal received. Reloading databases\n" if($opts{v});
untie %domains;
untie %types;
tie %domains, "DB_File", $dbfile, O_RDONLY, 0666, $DB_HASH or die "Cannot open file $dbfile: $!\n";
tie %types, "DB_File", $typesfile, O_RDONLY, 0666, $DB_HASH or die "Cannot open file $typesfile: $!\n";
%typesrev = reverse %types;
};


if($opts{d} && fork)
{
	exit(0);
}
else
{
open OUT,">$pidfile" || die "cannot write to $pidfile $!\n";
print OUT $$;
close OUT;

print STDERR "Ready for incoming connections\n" if($opts{v});

my $mux = new IO::Multiplex;
$mux->add($listensocket);
$mux->set_timeout($listensocket,10);
$mux->set_callback_object(__PACKAGE__);
$mux->loop;

$listensocket->flush;
$listensocket->close;

untie %domains;
untie %types;
exit(0);
}

sub mux_eof {
  my $self = shift;
  my $mux  = shift;
  my $fh   = shift;
#
# when mux receives on socket eof data, it's shutdown this socket for read
# we must close shutdowned socket and reopen it
#
  print STDERR "End of file or error at socket detected!\n" if($opts{v});
  $mux->close($fh);
  return;
}

sub mux_input {
  my $package = shift;
  my $mux = shift;
  my $fh = shift;
  my $input = shift;

  if($fh == $listensocket)
  {
	my $saddr = $mux->{_fhs}{$listensocket}{udp_peer};
	my $reply = &request_filter($$input);
#	print STDERR $$input," ",$reply,"\n" if($opts{v});
	send($listensocket, $reply, 0, $saddr) or die "Cannon send back info $!";
  }
  else
  {
	die "$$: Not my fh?";
  }
  $$input = '';
}

sub mux_close
{
  my $self = shift;
  my $mux  = shift;
  my $fh   = shift;
#
# recreating socket, when original listening $fh is closed.
#  
  $listensocket = IO::Socket::INET->new(	LocalPort => $PORTNO,
				   		Proto	=> "udp",
				   		Blocking => 0
				        )  or die "Can't be a UDP server on port $PORTNO : $!\n";
  $mux->add($listensocket);
  print STDERR "Reconstructing listen socket is ok\n" if($opts{v});
#  exit;
}

sub mux_timeout
{
	my $self = shift;
	my $mux = shift;
	my $fh = shift;
	$mux->set_timeout($fh,10);
	print STDERR "Timeout for FH $fh reached\n" if($opts{v});
}


sub request_filter
{
my $domain = shift;
#print STDERR "Domain: $domain Result: $result\n" if($opts{v});
my $result = &check_domain_category($domain);

if((!$result || $result eq 'undef') && $recursivecheck eq 'on')
{
    print STDERR "Recursive check activated\n";
    my @addresses = gethostbyname($domain);
    @addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];
    my (@lists,$searchresult);
    if(@addresses && $domain !~ /^\d+\.\d+\.\d+\.\d+$/)
        {
         foreach my $address (@addresses)
          {
            $searchresult = &check_doubles($searchresult,$domains{md5_hex($address)});
          }
          print STDERR "\nChecking IP addresses ",join(":",@addresses)," for $domain Result: $searchresult\n" if($opts{v});
        }
$result = &check_doubles($result,join ';', map { $typesrev{$_} } split (';',$searchresult));
}
print STDERR "Result Returned: $result\n" if($opts{v});
return "$result\n";
}


sub check_domain_category
{
# Check domain category from predefined domains and categories
my $dom = shift;
my $dotlen = $dom;
$dotlen =~ s/[^\.]//g;
$dotlen = length($dotlen);

my $result;
my $searchresult;
#
# Get all recorded categories for secondlevel domain
#
if($dom eq 'get.catserver.categories.local')
{
  return join (';',keys %types) || 'undef';
}

if($dom =~ /^\d+\.\d+\.\d+\.\d+$/)
  {
    # define domain type
    $searchresult = $domains{md5_hex($dom)};
    $result = join ';', map { $typesrev{$_} } split (';',$searchresult);
    print STDERR "\nChecking IP: $dom MD:",md5_hex($dom)," MD5Result: $searchresult\n" if($opts{v});
  }
else
  {
    my $searchresult = $domains{md5_hex(sl($dom))};
    print STDERR "\nChecking Domain: $dom MD5Result: $searchresult\n" if($opts{v});
      if(defined($searchresult))
        {
          my (%level,$ind);
          #
          # If any category found - get from categories list all values where defined data for this domainlevel or less
          #
          foreach (split ";",$searchresult) { $ind = index($_,"="); next if(substr($_,0,$ind) > $dotlen);  $level{substr($_,0,$ind)} .= substr($_,$ind+1).';'; }
          #
          # After this procedure we get a hash with categories for domain level or less
          #
        if ($dotlen == 1)
          {
          #
          # If dotlen = 1 - we work with second level domain
          #
            $result = join ';', map { $typesrev{$_} } split (';',$level{1});
          #
          #	get all text types defined for domain into delimited list
          #
            print STDERR "Second Level Domain: $dom Level1: ",$level{1}," Result: $result\n" if($opts{v});
          }
    else
    {
#
# If dotlen > 1 - we work with domain level > 2
#
        foreach my $curlev (reverse sort keys %level)			# resort levels from bigest to smallest
        {
          my @domarr = split (/\./,$dom);				# put domain parts into array
          my $cutdom = join ('.',@domarr[$#domarr-$curlev..$#domarr]);	# make temporary domain name with level
                                                                        # where defined category
          $result = $domains{md5_hex($cutdom)};				# if result found and current level is
          last if($result && $curlev != 1);
          $result = ($curlev == 1) ? $level{1} : undef;			# if no defined categories found
                                                                        # result for domain - catefory of second
                                                                        # level domain
          print STDERR "$curlev Level Domain: $cutdom(Cutted) Level1: ",$level{1}," Result: $result\n" if($opts{v});
        }
#
# repack numeric domains categories to text categories defined in config
#
           $result = join ';', map { $typesrev{$_} } split (';',$result);
    }
  }
}
undef $result if(!defined($result) || $result eq '');
return $result // 'undef';
}

sub sl # secondlevel
{
# Cut secondlevel domain from full domain name
  my $dom = shift;
  return substr($dom, rindex($dom, '.', rindex($dom, '.')-1)+1);
}

sub HELP_MESSAGE
{
print << "[end]";
Category pradm server
  -h : This help page
  -v : Verbose output (disable daemon)
  -d : become a daemon after start
  -w <directory> : work directory for database files
  -p <pidfile> : use <pidfile> instead /var/run/catserver.pid
  -P <port> : listen at this port (default 6510)
[end]
exit(0);
}

sub VERSION_MESSAGE
{
}

sub check_doubles
{
  my $current = shift;
  my $value = shift;
  return $current if(!$current && !$value);
  my $list = (defined($current)) ? $current.';'.$value : $value;
  my %unique;
  map { $unique{$_} = 1 } split(";",$list);
  $list = join(";",keys %unique);
  print "Recheck Doubles result : $list\n" if($opts{v});
  return $list;
}
