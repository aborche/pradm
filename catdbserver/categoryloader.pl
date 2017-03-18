#!/usr/local/bin/perl
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

use strict;
use Getopt::Std;
use Data::Dumper;
use DB_File;
use Digest::MD5 qw(md5_hex);

use vars qw /$cat %types $curtype %dom %opts $perm $sth $dbh $listdir %startuptypes %domains %whitelist/;

$Getopt::Std::STANDARD_HELP_VERSION = 1;
$curtype = 2000; # offset for user defined categories

getopts('chvVstkRr:f:d:w:p:', \%opts);
if($opts{h} || scalar keys %opts < 1)
{
  &HELP_MESSAGE;
}
my $workdirectory = $opts{w} || '/usr/local/squid/catdbserver/';
$workdirectory .= '/' if($opts{w} !~ /\/$/ && defined($opts{w}));
my $dbfile = $workdirectory."domains.tmp";
my $typesfile = $workdirectory."types.tmp";

$opts{v} = 1 if(defined($opts{V}));

if($opts{c})
{
unlink $dbfile;
unlink $typesfile;
}
tie %domains, "DB_File", $dbfile, O_RDWR|O_CREAT, 0666, $DB_HASH or die "Cannot open file $dbfile: $!\n";
tie %types, "DB_File", $typesfile, O_RDWR|O_CREAT, 0666, $DB_HASH or die "Cannot open file $typesfile: $!\n";

# If types file already contains saved categories, find maximum number from list of categories
foreach my $tmp (keys %types)	{	if($types{$tmp} > $curtype) { $curtype = $types{$tmp}; }	}

&load_whitelist;
&load_file($opts{f}) if(defined($opts{f}));
&load_dir($opts{d}) if(defined($opts{d}));

# get some statistics from database
if($opts{"s"})
{
print "Statistics for database: DB: $dbfile TYPES: $typesfile\n";
print "Domains : ",scalar keys %domains,"\n";
print "Types   : ",scalar keys %types,"\n";
print "List of used types\n";
map { print $_," = ",$types{$_},"\n"; } sort keys %types if($opts{t});
map { print $_," = ",$domains{$_},"\n"; } keys %domains if($opts{k});
print join (" ",keys %types),"\n" if($opts{t});
}

untie %domains;
untie %types;
if($opts{R})
{
  my $pidfile = $opts{p} || '/var/tmp/catserver.pid';
  open IN,"$pidfile";
    my $catserverpid = <IN>;
    chomp($catserverpid);
    kill 1,$catserverpid or die "Cannot send HUP signal to PID $catserverpid: $!\n";
  close IN;
}

exit(0);

sub HELP_MESSAGE
{
print << "[end]";
DBFile category loader for pradm category server
  -h : This help page
  -c : Clear current database before loading data
  -v : Verbose procedures
  -V : Verbose converting process
  -f <filename>  : use file with domains info in format "domain:category"
  -r <name> : use category name(replace) instead defined in <filename>
  -d <directory> : use directory with category directories. Each category directory must have a file named "domains"
  -w <directory> : work directory for database files
  -s : get some statistics for current database
  -t : show types list
  -k : show md5 domain list
  -p : catserver pid file for HUP signal
  -R : send HUP signal to categoryserver
[end]
exit(0);
}

sub VERSION_MESSAGE
{
}

sub load_file
{
my $filename = shift;
my $lastcat;
open IN,"<$filename";
my $counter = 0;
while(<IN>)
{
chomp();
my($tmpname,$tmpcat) = split(":",$_,2);
if($opts{r}) { $tmpcat = $opts{r}; }
next if(exists($whitelist{$tmpname}));
&put_domain_to_memory($tmpname,$tmpcat);
$counter++;
if($counter%1000 == 0)
  {
    print "Processing $counter lines from file $filename\n" if($opts{v});
    &packtodatabase; undef %dom;
  }
}
    print "Processing $counter lines from file $filename\n" if($opts{v});
&packtodatabase; undef %dom;
close IN;
}

sub load_dir
{
my $listdir = shift;
opendir(my $dh, $listdir) || die "can't opendir $listdir: $!";
my @dirs = grep { -d "$listdir/$_" && $_ !~ /^\./} readdir($dh);
closedir $dh;
foreach my $dir (@dirs)
{
  next if(!-f "$listdir/$dir/domains");
  open IN,"<$listdir/$dir/domains" or die "Can't open file $listdir/$dir/domains: $!";
  print STDERR "Begin processing category $dir\n" if($opts{v});
  my $counter = 0;
  while(<IN>)
  {
    chomp();
    if($opts{r}) { $dir = $opts{r}; }
    &put_domain_to_memory($_,$dir);
    $counter++;
    if($counter%1000 == 0) { &packtodatabase; undef %dom; print "Processed $counter records for category $dir\n" if($opts{v}); }
  }
  print "Processed $counter records for category $dir\n" if($opts{v}); 
  &packtodatabase;
  undef %dom;
  close IN;
}
}


sub put_domain_to_memory
{
  my $domain = shift;
  my $type = shift;
#
# make temporary cache for user defined domains and categories
#
  print STDOUT "\nProcess Domain: $domain Category: $type\n" if($opts{V});
  $type =~ s/[^0-9A-Za-z\-\_]//g;
  $type = lc($type);
  if($type =~ /^$/)
    {
      print "Warning !!! Null category found for domain $domain. Skipping\n" if($opts{v});
      return;
    }
  if(!defined($types{$type})) { $curtype++; $types{$type} = $curtype; }
  my $dots = $domain;
  if($dots =~ /^\d+\.\d+\.\d+\.\d+$/)
  {
    $dom{$domain}->{type} = &check_doubles($dom{$domain}->{type},$types{$type});
    print "Put_to_memory IP. IP Address $dots. Types:",$dom{$domain}->{type},"\n" if($opts{V});
  }
  else
  {
    $dots =~ s/[^\.]//g;	# delete all symbols excluded dots
    my $dotl = length($dots);	# detect domain level ( 1 dot - second level, 2 dots - third level and ... )
    my $sldom = sl($domain);	# cut domain to second level

    if($dotl > 1)		# if domainlevel > 1 - record domain type and define domain levels categories
    {
      # cut duplicate types for host
      $dom{$domain}->{type} = &check_doubles($dom{$domain}->{type},$types{$type});

      print "Put_to_memory HL. FullDomain $domain Types:",$dom{$domain}->{type},"\n" if($opts{V});
      #	cut duplicate categories for second level domain
      $dom{$sldom}->{dots}->{$dotl} = &check_doubles($dom{$sldom}->{dots}->{$dotl},$types{$type});

      print "Put_to_memory HL. SecLDomain $sldom Dots: $dotl Types:",$dom{$sldom}->{dots}->{$dotl},"\n" if($opts{V});
    }
    else
    {
      # cut duplicate categories
      $dom{$domain}->{dots}->{$dotl} = &check_doubles($dom{$domain}->{dots}->{$dotl},$types{$type});

      print "Put_to_memory SL. SecLDomain $sldom Dots: $dotl Types:",$dom{$domain}->{dots}->{$dotl},"\n" if($opts{V});
    }
  }
}


sub packtodatabase
{
#
# unpack temporary cache to hash objects
#
print "PackToMemory: ",scalar keys %dom," domains \n" if($opts{V});
return if(scalar keys %dom < 1);
  foreach my $name (sort keys %dom)
  {
    if(!defined($dom{$name}->{type}))	# if not defined domain type, then we work with domain with level > 2
    {
#
# For each second level domain we make a list with categories defined at all detected sublevels > 2
#
      my $catstr = join ";",map { my $curlevel = $_; map { $curlevel.'='.$_ } split (';',$dom{$name}->{dots}->{$_}) } sort keys %{$dom{$name}->{dots}};
#
# If category for second level domain already defined - append new values
#
      print "Domain $name Types: $catstr\n" if($opts{V});

      $domains{md5_hex($name)} = &check_doubles($domains{md5_hex($name)},$catstr);

      print "SingleDot Name $name MD ",md5_hex($name)," STR ",$domains{md5_hex($name)},"\n\n" if($opts{V});
    }
    else
    {
#
# For each domains with sublevel > 2 - define categories directly to domain
#
      print "Domain $name Types: $dom{$name}->{type}\n" if($opts{V});
      
      $domains{md5_hex($name)} = &check_doubles($domains{md5_hex($name)},$dom{$name}->{type});

      print "MultiDots Name $name MD ",md5_hex($name)," STR ",$domains{md5_hex($name)},"\n\n" if($opts{V});
    }
}

}

sub sl # secondlevel
{
# Cut secondlevel domain from full domain name
  my $dom = shift;
  return substr($dom, rindex($dom, '.', rindex($dom, '.')-1)+1);
}

sub check_doubles
{
  my $current = shift;
  my $value = shift;
  my $list = (defined($current)) ? $current.';'.$value : $value;
  my %unique;
  map { $unique{$_} = 1 } split(";",$list);
  $list = join(";",keys %unique);
  print "Recheck Doubles result : $list\n" if($opts{V});
  return $list;
}

sub load_whitelist
{
open IN,"<".$workdirectory."whitelist.txt" or die "$!";
while(<IN>)
{
  chomp();
  $whitelist{$_} = "1";
}
close IN;
}
