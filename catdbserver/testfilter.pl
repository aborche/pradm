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
# $Date: 2010-05-14 20:05:24 +0400 (пт, 14 май 2010) $
# $Revision: 60 $
# $LastChangedBy: zhecka $

use IO::Socket;
use strict;
use Getopt::Std;

my($socket,$msg,$PORTNO,$SERVERADDR,$TIMEOUT,$MAXLEN,%opts);

getopts('P:H:',\%opts);
$PORTNO = $opts{P} || 6510 ;
$SERVERADDR = $opts{H} || "localhost";
$TIMEOUT = 10;
$MAXLEN = 1024;
$socket = IO::Socket::INET->new(
                                    PeerPort => $PORTNO,
                                    PeerAddr => $SERVERADDR,
                                    Proto => 'udp'
                                  ) or die "Cannot create request socket $!\n";

while(<STDIN>)
{
chomp();
my $data = $_;

$socket->send($data) or die "send: $!";

eval {
  local $SIG{ALRM} = sub { die "alarm time out" };
  alarm $TIMEOUT;
  $socket->recv($msg,$MAXLEN);
  alarm 0;
  1;
} or die "recv from $SERVERADDR time out after $TIMEOUT seconds.\n";

print "Server $SERVERADDR domain $data answer $msg";
}

$socket->flush;
$socket->close;

exit(0);
