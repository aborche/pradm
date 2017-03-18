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
# $Date: 2010-05-17 11:13:44 +0400 (пн, 17 май 2010) $
# $Revision: 76 $
# $LastChangedBy: zhecka $

use IO::Handle;
use IO::Socket;
use strict;
use Cache::Memcached::Fast;
use Digest::MD5 qw(md5_hex);


my($socket,$msg,$TIMEOUT,$MAXLEN);
#use vars qw /$hosts $src $dst $uri $perm @permblock @block %dom %types $domaincategory $lastdomaincategory %dom $lockdir/;
use vars qw /
  $hosts $cat $perm
  $src $dst $uri $url $excludestring
  %dom %types 
  $curtype $expire $lock %opts
  %permblock %allcategories %permallow
  %catserversocket %catservers $current_config_revision
  %socketfailures $maxsocketfailures %socketwaitflag $socketwaitcycles
  $socketcycleseconds %socketnexttime
  /;

require "/usr/local/squid/scripts/md5.pm";

# expire time for all records pushed to hosts namespace
#$opts{v} = 1;
#$opts{V} = 1;
#$opts{H} = 1;

$expire = 3600; # time in second for values in cache
$curtype = 1000; # offset for user defined categories
my $acllog = "/usr/local/squid/logs/redir.log";
$maxsocketfailures = 5; 
$socketwaitcycles = 3;
$socketcycleseconds = 15;
$TIMEOUT = 5;
$MAXLEN = 1024;

#
# Default values for allow/deny
# allow = 0
# deny = 1
#

#
# workaround for block multiple config inits
#

$perm = new Cache::Memcached::Fast({
                                     servers => [ { address => 'memcachedserver:11211', noreply => 1 } ],
                                     namespace => 'perm:'
                                   });
$hosts = new Cache::Memcached::Fast({
                                     servers => [ { address => 'memcachedserver:11211', noreply => 1 } ],
                                     namespace => 'hosts:'
                                    });
$cat = new Cache::Memcached::Fast({
                                     servers => [ { address => 'memcachedserver:11211', noreply => 1 } ],
                                     namespace => 'cat:'
                                    });

$SIG{HUP} = $SIG{INT} = $SIG{QUIT} = $SIG{TERM} = $SIG{STOP} = \&quit;

# 0 - allow, 1 - deny
# Order: 0 - Logical OR, 1 - Logical AND
#$perm->set("host1.domain.local=76",1); # Social Networking - deny
#$perm->set("host1.domain.local=78",0); # Social Media - deny
#$perm->set("host1.domain.local=15",0); # Warez - allow
#$perm->set("host1.domain.local=32",0); # Search - allow
#$perm->set("host1.domain.local=order",0); # Order: 0 - allow,deny; 1 - deny,allow

#$perm->set("0.0.0.0=76",1);
#$perm->set("0.0.0.0=78",1);
#$perm->set("0.0.0.0=15",0);
#$perm->set("0.0.0.0=32",0);
#$perm->set("0.0.0.0=order",0);

#
# External Socket Connector to Categorisation Server
# in - uri name
# out - numbers and name of categories for uri
#
#
# Warning !!! If you use pradm at OpenBSD box, read text below!!!
#
# IO::Socket::INET on OpenBSD do not generate a error when socket is unavailable !
# Be careful. You cannot detect dead of category server :(
#

open OUT,">>$acllog";
OUT->autoflush(1);
STDOUT->autoflush(1);
$|=1;

while(<>)
{
my $tmp_config_revision = $perm->get("config_revision");
while (!$tmp_config_revision || $tmp_config_revision eq '')
{
  print STDERR "PID $$ Waiting for config load. Use reloadconfig.pl for load current config\n";
  sleep 10;
  $tmp_config_revision = $perm->get("config_revision");
}
if($current_config_revision ne $tmp_config_revision)
{

  print STDERR "PID $$ New config revision '$tmp_config_revision' arrived. Old revision '$current_config_revision'\n";
  &init_catservers;
  undef %socketwaitflag;
  undef %socketfailures;
  $current_config_revision = $tmp_config_revision;
}
chomp();
($src,$uri,$url) = split(/ /,$_,3);
my $result;
my $srcname;
my $categ;
my $block;
my %check_cat_hash;
my $prefix;

#
# For minimize dns overload - cache all resolved ip info to hosts namespace
#
if(!$hosts->get("ip_".$src))
  { $srcname = gethostbyaddr(inet_aton($src), AF_INET) || $src; $hosts->set("ip_".$src,$srcname,$expire); }
  else
  { $srcname = $hosts->get("ip_".$src); }

#
# If user already do not have extendedtime flag - check timemap for current user request
# if check_timemap returns undef, then block user request and redirect them to error page
#
$excludestring = $perm->get('excludestring')||'^$';
if($uri =~ /$excludestring/)
{
  $prefix = 'LocalNet :';
  $block = 'false';
  $result = 'Skipped';
  $categ = 'Exclude List';
  goto ERROR;
}

if(!defined($perm->get($srcname."_extendedtime")))
{
    if(!check_timemap($srcname))
          {
            $prefix = 'TimeCheck :';
            $block = 'true';
            $result = 'TIME';
            $categ = "Non-work time";
            goto ERROR;		# jump to error handler
          }
}

#
# Check local domain categories defined in config file
# If uri is not categorized - make it to default 'Unknown' category = 255
# If uri succesfully categorized - check global and user permissions for founded categories
# 
#

$categ = &check_domain_category($uri) || 'undeflocal';
#
# foreach cycle faster than map cycle about 20k records per sec
# check_category retunrs 1 for block connecion and 0 for allow

foreach (split (";",$categ)) { $result = 'LOC' if(defined($perm->get('0.0.0.0='.$_)) || defined($perm->get($srcname.'='.$_))); }
if($result eq 'LOC')
{
  $block = &check_category($categ,$srcname);
  $block = ($block == 1) ? 'true' : 'false';
  $categ = $categ = join '; ',map { $cat->get($_.'_name') } split (';',$categ);
  print STDERR "Category $categ DST: $srcname BLOCK: $block\n" if($opts{v});
  $prefix = 'LocalCheck:'; goto ERROR;  
#print OUT "Category $categ DST: $srcname BLOCK: $block\n";
}

#
# Check external categorisation service( for ex: opendns )
#

if(!$hosts->get($uri))
{
my %resultarray;
foreach my $server (keys %catservers)
{
    # if found waitflag for socket - skip any requests for this socket

    foreach my $waitserver (keys %socketwaitflag)
    {
      # if current time is less than defined next check time, then skip checks
      # if current time is greather than defined next check time, decrease wait cycles
      # and set next check time
      # if number of cycles is 0, then create socket and reset all wait variables
      print STDERR "PID $$ Next Time: ",$socketnexttime{$waitserver}," Current Time:",time()," Waittime:",$socketwaitflag{$waitserver},"\n" if($opts{v});
      if($socketnexttime{$waitserver} <= time())
      {
          $socketwaitflag{$waitserver}--;
          if($socketwaitflag{$waitserver} <= 0)
            {
              delete $socketwaitflag{$waitserver};
              delete $socketnexttime{$waitserver};
              &create_socket($waitserver);
              print STDERR "PID $$ Rebuild new socket to server $waitserver \n"; 
              next;
            }
          else
            {
              $socketnexttime{$waitserver} = time() + $socketcycleseconds;
            }
      }
      else
      {
        next;
      }
    }
    next if $socketwaitflag{$server};


    $catserversocket{$server}->send($uri) or die "cannot send to $server: $!";

    eval {
            local $SIG{ALRM} = sub { die "alarm\n" };
            alarm $TIMEOUT;
            $catserversocket{$server}->recv($result,$MAXLEN) // 'undef';
            alarm 0;
            1;
         };

    if ($@ =~ /alarm/)
    {
      print STDERR "PID $$. Connection to socket $server lost. Go to wait cycle.\n";
      # if receive data from category server failed, then try to wait until category server is up
      # when receiving data fails $maxsocketfailures time, then delete failed categoryserver socket
      $socketfailures{$server} += 1;
      # close socket
      close $catserversocket{$server};
      # set number of cycles for waiting. $socketwaitcycles*$socketcycleseconds
      $socketwaitflag{$server} = $socketwaitcycles;
      # set next time for decrease value of $socketwaitflag
      $socketnexttime{$server} = time() + $socketcycleseconds;
      # if socket failures > maximum socket failures - destroy socket from socket list
      if($socketfailures{$server} >= $maxsocketfailures)
        {
          my %tmp;
          map { $tmp{$_} = 1 } split (';',$perm->get("category_servers"));
          delete $tmp{$server};
          $perm->set("category_servers",join ';',keys %tmp);
          delete $catservers{$server};
          print STDERR "Destroying socket connection for category server $server\n";
          next;
        }
    } else {
      # if failured socket correctly receive data, then delete socketfailures counter;
      if($socketfailures{$server}) { delete $socketfailures{$server}; }
      chomp($result);
      map { $resultarray{$_} = 1; } split (';',$result);
    }
}

# if External category server is unavailable - kill redirector process.
# it can be very dangerous - pass any connection when category server is down
#
# returned result must have two parts delimited by space
# - category numbers delimited by ';'
# - category names delimited by ';'
#
  $result = join (';',keys %resultarray);
  chomp($result);
#  print OUT "Found Category: $result for $uri\n";
#  ($result,$categ) = split (/ /,$result,2);
  $categ = join '; ',map { $cat->get($_.'_name') } split (';',$result);
  print STDERR "Found Categories: $categ for $uri\n" if($opts{v});
  $categ =~ s/\"//g;
  $hosts->set($uri."b",$categ,$expire);		# cache category names for uri
  $hosts->set($uri,$result,$expire);		# cache numbers of categories for uri
  $prefix = 'To Cache  :';
}
else
{
  $result = $hosts->get($uri);			# get category list from cache
  $categ = $hosts->get($uri."b");
  $categ =~ s/\"//g;
  $prefix = 'From Cache:';
}
$block = &check_category($result,$srcname);
$block = ($block == 1) ? 'true' : 'false';

ERROR:
print OUT "$prefix Blocked:$block DST:$src/$srcname URI:$uri RES:$result CAT:$categ\n";
print STDERR "Blocked:$block DST:$src/$srcname URI:$uri RES:$result CAT:$categ\n" if($opts{v});

#  print "ERR message=\"$categ\"\n";
if($block eq 'true')	{ print STDOUT "ERR\n"; } else { print STDOUT "OK\n"; }

undef $categ;
undef $result;
}
&close_catsockets;
close OUT;

sub quit
{
&close_catsockets;
close OUT;
exit(0);
}

sub check_category
{
  my $result = shift;
  my $src = shift;
  my %categories;
  my $deforder = $perm->get("0.0.0.0_order") // 0;		# default order "allow,deny"
  my $usrorder = $perm->get($src."_order") // $deforder;
#
# allow = 0, deny = 1
#
# Matrix UsrPERM|AllPerm
  my %matrix = ("00" => 0, "01" => 0, "10" => 1, "11" => 1);
  my $lastresult = undef;

  foreach my $tmpcat (split (/\;/,$result))
  {
    my $defperm = $perm->get("0.0.0.0=".$tmpcat) // 0;		# default permission to category for all users or allow if not defined
    my $usrperm = $perm->get($src."=".$tmpcat) // $defperm;	# if not defined user permission - get default
    my $catresult = $matrix{$usrperm.$defperm};
    $lastresult //= $catresult;
    if($usrorder == 0) # allow,deny . logical OR
    {
      $lastresult = $lastresult | $catresult;
#      print "Last OR result $lastresult CATResult $catresult CATMatrix $usrperm:$defperm Order $usrorder\n";
    }
    else	# deny, allow . logical AND
    {
      $lastresult = $lastresult & $catresult;
#    print "Last AND result $lastresult CATResult $catresult CATMatrix $usrperm:$defperm Order $usrorder\n";
#    print "Last result $lastresult $catresult $usrperm:$defperm\n";
    }
  }
  return $lastresult;
#  print "Result = $lastresult\n";
}

sub close_catsockets
{
  foreach my $server (keys %catservers)
  {
    close $catserversocket{$server};
    delete $catservers{$server};
  }
}

sub init_catservers
{
&close_catsockets;

foreach my $server (split(';',$perm->get("category_servers")))
  {
    &create_socket($server);
  }
}

sub create_socket
{
  my $server = shift;
  my($SERVERADDR,$PORTNO) = split(':',$server);
  $catserversocket{$server} = IO::Socket::INET->new(
                                                  PeerPort => $PORTNO,
                                                  PeerAddr => $SERVERADDR,
                                                  Proto => 'udp'
                                                  ) or die "Cannot create client socket to $SERVERADDR:$PORTNO $!\n";
  $catservers{$server} = $PORTNO;
  print STDERR "PID $$ make client socket to $SERVERADDR:$PORTNO\n";
}