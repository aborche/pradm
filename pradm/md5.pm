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
# $Date: 2010-05-15 23:38:17 +0400 (сб, 15 май 2010) $
# $Revision: 74 $
# $LastChangedBy: zhecka $

use strict;

return 1;

sub put_domain_to_memory
{
  my $domain = shift;
  my $type = shift;
#
# make temporary cache for user defined domains and categories
#
  print STDERR "Process Domain: $domain Category: $type\n" if($opts{v});
  $type = lc($type);
  if(!defined($types{$type})) { $curtype++; $types{$type} = $curtype; $cat->set("type_".$curtype,$type); $cat->set("lastcat",$curtype); }

  my $dots = $domain;
  if($dots =~ /^\d+\.\d+\.\d+\.\d+$/)
  {
    $dom{$domain}->{type} = &check_doubles($dom{$domain}->{type},$types{$type});
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
#
      print STDERR  "Put_to_memory HL. FullDomain $domain Types:",$dom{$domain}->{type},"\n" if($opts{v});
#
      #	cut duplicate categories for second level domain
      $dom{$sldom}->{dots}->{$dotl} = &check_doubles($dom{$sldom}->{dots}->{$dotl},$types{$type});
#
      print STDERR  "Put_to_memory HL. SecLDomain $sldom Dots: $dotl Types:",$dom{$sldom}->{dots}->{$dotl},"\n" if($opts{v});
#
    }
    else
    {
      # cut duplicate categories
      $dom{$domain}->{dots}->{$dotl} = &check_doubles($dom{$domain}->{dots}->{$dotl},$types{$type});
#
      print STDERR  "Put_to_memory SL. SecLDomain $domain Dots: $dotl Types:",$dom{$domain}->{dots}->{$dotl},"\n" if($opts{v});
#
    }
    
#    if($dotl > 1)			# if domainlevel > 1 - record domain type and define domain levels categories
#    {
#      $dom{$domain}->{type} = $types{$type};		# define domain type
#      $dom{$sldom}->{dots}->{$dotl} = $types{$type};	# save type for second level domain
#    }
#    else
#    {
#      $dom{$domain}->{dots}->{$dotl} = $types{$type};	# save type for seconf level domain
#    }
  }
}


sub packtomemory
{
#
# unpack temporary cache to memcached objects
#
#
print STDERR "PackToMemory: ",scalar keys %dom," domains \n" if($opts{v});
#
return if(!defined(%dom));
  foreach my $name (sort keys %dom)
  {
    print STDERR "Domain $name\n" if($opts{v});
    if(!defined($dom{$name}->{type}))	# if not defined domain type, then we work with domain with level > 2
    {
#
# For each second level domain we make a list with categories defined at all detected sublevels > 2
#
      my $catstr = join ";",map { my $curlevel = $_; map { $curlevel.'='.$_ } split (';',$dom{$name}->{dots}->{$_}) } sort keys %{$dom{$name}->{dots}};

#      my $catstr = join ";",map { $_.'='.$dom{$name}->{dots}->{$_} } sort keys %{$dom{$name}->{dots}};
#
# If category for second level domain already defined - append new values
#

      $cat->set(md5_hex($name),&check_doubles($cat->get(md5_hex($name)),$catstr));

#      my $retstr = (defined($cat->get(md5_hex($name)))) ? $cat->get(md5_hex($name)).';'.$catstr : $catstr;
      print STDERR "SingleDot Name $name STR ",$cat->get(md5_hex($name)),"\n" if($opts{v});
    }
    else
    {
#
# For each domains with sublevel > 2 - define categories directly to domain
#

      $cat->set(md5_hex($name),&check_doubles($cat->get(md5_hex($name)),$dom{$name}->{type}));

#      my $retstr = (defined($cat->get(md5_hex($name)))) ? $cat->get(md5_hex($name)).';'.$dom{$name}->{type} : $dom{$name}->{type};
      print STDERR "MultiDots Name $name STR ",$cat->get(md5_hex($name)),"\n" if($opts{v});
    }
  }

}

sub sl # secondlevel
{
# Cut secondlevel domain from full domain name
  my $dom = shift;
  return substr($dom, rindex($dom, '.', rindex($dom, '.')-1)+1);
}

sub check_domain_category
{
# Check domain category from predefined domains and categories
my $dom = shift;
my $dotlen = $dom;
$dotlen =~ s/[^\.]//g;
$dotlen = length($dotlen);

my $result;
#
# Get all recorded categories for secondlevel domain
#
my $searchresult = $cat->get(md5_hex(sl($dom)));

print STDERR "\nLocal check Domain: $dom MD5Result: ",$searchresult||'undeflocal',"\n" if($opts{v});
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
      $result = join ';', map { $cat->get("type_".$_) } split (';',$level{1});
#
# get all text types defined for domain into delimited list
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
          $result = $cat->get(md5_hex($cutdom));			# if result found and current level is
                                                                        # not 1(second level domain) - stop search 
          last if($result && $curlev != 1);
          $result = ($curlev == 1) ? $level{1} : undef;			# if no defined categories found
                                                                        # result for domain - catefory of second
                                                                        # level domain
          print STDERR "$curlev Level Domain: $cutdom(Cutted) Level1: ",$level{1}," Result: $result\n" if($opts{v});
        }
#
# repack numeric domains categories to text categories defined in config
#
          $result = join ';', map { $cat->get("type_".$_) } split (';',$result);
    }
}
return $result;

}

sub load_config
{
my %weekdays = ( "Sun" => 0, "Mon" => 1, "Tue" => 2, "Wed" => 3, "Thu" => 4, "Fri" => 5, "Sat" => 6 );
$allcategories{"undef"} = 'Not Found in Category Server';	# Predefine default category
my $configname = $opts{C} || '/usr/local/etc/squid/pradm.conf';
open (IN,"<",$configname) or die "Cannot open config $configname $!\n";
my ($section,$domaincategory,@block,@catserverstmp);
while(<IN>)
{
  # Permanent block of categories
  chomp();
  next if( /^$/ || /^#/ );
  my $line = $_;
  if(/^\[(.*)\]/)
  {
    $section = $1;  
    print STDERR "\nSection: $section\n" if($opts{v});
    next;
  }  
  print STDERR "line $line \n" if($opts{v});
  &permissions($line) if($section eq 'permissions');
  &sethosts($line) if($section eq 'hosts');
  
  # ========== BasicBlock ==========
  #
  # Process host category definition

  if($section eq 'catservers')
  {
    push(@catserverstmp,$line);
    next;
  }  

  if($section =~ /^timemap_(.*)$/)
  {
    my $timemap = $1;
    next if($line =~ /^\[/);
    my($day,$bh,$bm,$eh,$em) = unpack("A3xA2xA2xA2xA2",$line);
    $day = $weekdays{$day};
    my $tmptimevalue = $perm->get("timemap_".$timemap."_".$day);
    $tmptimevalue = (defined($tmptimevalue)) ? $tmptimevalue.','.($bh*60+$bm).'_'.($eh*60+$em) : ($bh*60+$bm).'_'.($eh*60+$em);
    $perm->set("timemap_".$timemap."_".$day,$tmptimevalue);
    print STDERR "Set TimeMap for $timemap day:$day mapvalue:$tmptimevalue\n" if($opts{v}); 
  }
  
  # =========== Process category definition =======
  if($section =~ /^category_(.*)$/)
  {
    $domaincategory = $1;
    $allcategories{$domaincategory} = $domaincategory if(!defined($allcategories{$domaincategory}));
    if($line =~ /^desc\=(.*)$/)
      {
        $allcategories{$domaincategory} = $1;
        next;
      }
    &put_domain_to_memory($line,$domaincategory);
  }

  if($section eq 'catserver_categories')
  {
    my($catid,$catname) = split(/\=/,$line);
    $allcategories{$catid} = $catname;
  }

}
print STDERR "File is over. Packing domains list\n" if($opts{v});
&packtomemory;
#$allcategories{'undeflocal'} = 'Not Found in Local Categories';
map { $cat->set($_."_name",$allcategories{$_}); } keys %allcategories;
$perm->set("category_servers",join (';',@catserverstmp));
$cat->set("allcategorieslist",join (';',keys %allcategories));
close IN;
}

sub check_timemap
{
my $srcname = shift;
return 'ok' if (!defined($perm->get('0.0.0.0_timemap')));
my $timemap = (defined($perm->get($srcname.'_timemap'))) ? $perm->get($srcname.'_timemap') : $perm->get('0.0.0.0_timemap');
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
my $curtime = ($hour*60)+$min;
my $found = undef;
foreach (split (",",$perm->get('timemap_'.$timemap.'_'.$wday)))
  {
#    print STDERR "DSTNAME: $srcname CURTIMEMAP: $_ ",$curtime," ",substr($_,0,index($_,"_"))," ",substr($_,index($_,"_")+1),"\n";

    if($curtime >= substr($_,0,index($_,"_")) && $curtime < substr($_,index($_,"_")+1))
    {
      $found = 'ok';
    }
    
  }
#print STDERR $found,"\n";
return $found;
}

sub check_doubles
{
  my $current = shift;
  my $val = shift;
  my ($list,%unique);
  
#  print STDERR "Current : $current, Value: $val\n" if($opts{v});
  if(defined($val))
  {
    $list = (defined($current)) ? $current.';'.$val : $val;
  }
  map { $unique{$_} = 1 } split(";",$list||$current);
  $list = join(";",keys %unique);
  print STDERR "Recheck Doubles result : $list\n" if($opts{v});
  return $list;
}

sub permissions
{
#
# Set permissions readed from config
# permblock - categories which cannon be unblocked for any user (ex: malware,fishing)
# block - categories which can be unblocked for any user
# allow - categories permanently allowed for all users, but can be blocked for any user
#
  shift;
  my($action,$list) = split(/=/,$_,2);
  if	($action eq 'permblock'){ &setperm('0.0.0.0',$list,1); map {$permblock{$_}=1} split(/ /,$list); }# permblock
  elsif	($action eq 'block')	{ &setperm('0.0.0.0',$list,1);	}# block all
  elsif	($action eq 'allow')	{ &setperm('0.0.0.0',$list,0); map {$permallow{$_}=1} split(/ /,$list);	}# permit allowed
  elsif	($action eq 'timemap')	{ &settimemap('0.0.0.0',$list);	}# set global timemap
  elsif ($action eq 'order')	{ $perm->set('0.0.0.0_order',$list);	}# set default order
  elsif ($action eq 'exclude')	{ $perm->set('excludestring',$list); 	}# set exclude string
  else	{	}
    
}

sub setperm
{
  my $host = shift;
  my $list = shift;
  my $permv = shift;
  map {
        my $tmpcat = $_;
        $permv = 1 if($tmpcat =~ /^\-/);
        $permv = 0 if($tmpcat =~ /^\+/);
        $permv //= 1;
        $tmpcat =~ s/^[\-|\+]//g;
        if($tmpcat eq 'ALL' && $permv == 0)
          {
#            print STDERR "Found ALL flag for host: $host perm: $permv\n" if($opts{v});
            my %allcat;
            map { $allcat{$_} = 1 if(!defined($permblock{$_})); } keys %allcategories;
            &setperm($host,join(' ',keys %allcat),$permv);
          }
        elsif($tmpcat eq 'ALL' && $permv == 1)
          {
            my %allcat;
            map { $allcat{$_} = 1 if(!defined($permallow{$_})); } keys %allcategories;
            &setperm($host,join(' ',keys %allcat),$permv);
          }
        else
          {
            print STDERR "SetPerm host: $host perm: $permv cat: $tmpcat\n" if($opts{v});
            $perm->set($host.'='.$tmpcat,$permv);
          }

      } split (/ /,$list);
}

sub settimemap
{
  my $host = shift;
  my $map = shift;
  $perm->set($host.'_timemap',$map);
  print STDERR "SetTimeMap host: $host map: $map\n" if($opts{v});
}

sub sethosts
{
  shift;
    my($host,$params) = split(/\=/,$_);
    if($host =~ /^(.*)_timemap$/)
      {
        &settimemap($1,$params);
#        $perm->set($host,$params);
      }
    elsif ($host =~ /^(.*)_order$/)
      {
        $perm->set($host,$params);
      }
    else
      {
        &setperm($host,$params);
      }
}
