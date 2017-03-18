#!/bin/sh
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
# $Date: 2010-05-15 22:15:39 +0400 (сб, 15 май 2010) $
# $Revision: 67 $
# $LastChangedBy: zhecka $

export dbpath="/usr/local/squid/catdbserver"

export quiet="--quiet"

$dbpath/categoryloader.pl -c -f $dbpath/malwaredomains.com.txt -r malware
perl $dbpath/parsemalwaredomainslist.pl < $dbpath/malwaredomainlist.com.csv > $dbpath/malwaredomainlist.com.parsed.txt
$dbpath/categoryloader.pl -f $dbpath/malwaredomainlist.com.parsed.txt -r malware
$dbpath/categoryloader.pl -f $dbpath/torlist.txt -r tor -R
