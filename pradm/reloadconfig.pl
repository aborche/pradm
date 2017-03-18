#!/usr/bin/perl -w
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
# $Date: 2010-05-15 23:38:17 +0400 (сб, 15 май 2010) $
# $Revision: 74 $
# $LastChangedBy: zhecka $

use strict;
use Getopt::Std;
use Digest::MD5 qw(md5_hex);
use Data::Dumper;
use Cache::Memcached::Fast;

# change this path to right place of md5.pm
require "/usr/local/squid/scripts/md5.pm";

use vars qw /
 $perm %types $curtype %dom $cat %opts
 %permblock %allcategories %permallow
 $memcachedserver $memcachedserverport
 /;


$curtype = 1000; # offset for user defined categories

getopts('cvhH:S:P:C:', \%opts);
if($opts{h})
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
if($opts{c})
{
  $perm->flush_all;
}

&load_config;
$perm->set("config_revision",scalar localtime());
exit(0);

sub HELP_MESSAGE
{
print << "[end]";
Category permission checker
  -h : This help page
  -� : clear memcached database
  -v : verbose output
  -H <hostname/ip> : show category permissions for hostname/ip
  -S <memcached server address> : change default memcachedserver name
  -P <port> : change default memcachedserver port
  -C <config> : use custom config instead default '/usr/local/etc/squid/pradm.conf'
[end]
exit(0);
}
