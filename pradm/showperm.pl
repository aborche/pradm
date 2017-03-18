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
# $Date: 2010-05-15 22:57:23 +0400 (сб, 15 май 2010) $
# $Revision: 72 $
# $LastChangedBy: zhecka $

use strict;
use Getopt::Std;
use Data::Dumper;
use Cache::Memcached::Fast;

use vars qw /
 $perm %types $curtype %dom $cat %opts
 %permblock %allcategories %permallow
 $memcachedserver $memcachedserverport
 /;


getopts('hH:S:P:', \%opts);
if($opts{h} || !defined(%opts))
{
  &HELP_MESSAGE;
}

$memcachedserver = ($opts{S}) ? $opts{S} : 'memcachedserver';
$memcachedserverport = ($opts{P}) ? $opts{P} : '11211';
$perm = new Cache::Memcached::Fast({
                                     servers => [ { address => "$memcachedserver:$memcachedserverport", noreply => 1 } ],
                                     namespace => 'perm:',
                                     close_on_error => 1
                                   }) or die "Cannot open connect to memcached server: $!\n";
$cat = new Cache::Memcached::Fast({
                                     servers => [ { address => "$memcachedserver:$memcachedserverport", noreply => 1 } ],
                                     namespace => 'cat:',
                                     close_on_error => 1
                                   }) or die "Cannot open connect to memcached server: $!\n";

  
foreach my $tmpcat (split ';',$cat->get("allcategorieslist"))
{
 $allcategories{$tmpcat} = $cat->get($tmpcat."_name");
}
my $hostname = $opts{H} || die "Host is not defined $!\n";
print "Access list for $hostname\n";
foreach my $cat ( sort {$allcategories{$a} cmp $allcategories{$b} } keys %allcategories)
{
my $cataction = $perm->get("0.0.0.0=".$cat);
my $action = $perm->get($hostname."=".$cat);
#if(!defined($action) && !defined($cataction)) { next; }
$action = $perm->get($hostname."=".$cat) // $cataction;
$action = ($action == 1) ? "block" : "allow";
print $action," = \'",$allcategories{$cat},"\' ",$cat,"\n";
}

exit(0);

sub HELP_MESSAGE
{
print << "[end]";
Category permission checker
  -h : This help page
  -H <hostname/ip> : show category permissions for hostname/ip
  -S <memcached server address> : change default memcachedserver name
  -P <port> : change default memcachedserver port
[end]
exit(0);
}
                      