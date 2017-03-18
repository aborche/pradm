#!/usr/bin/perl

use strict;
use Cache::Memcached::Fast;
use IO::Socket;
use Digest::MD5 qw(md5_hex);
use URI::URL;
use MIME::Base64;

use vars qw /%form %sv %cookie %rq /;
use vars qw /$hosts $src $dst $url $perm %dom %types $curtype $cat %opts %permblock %allcategories %permallow/;

require "/usr/local/squid/scripts/md5.pm";

&systeminit;

#print STDERR $form{code},"\n";
$perm = new Cache::Memcached::Fast({
                                     servers => [ { address => 'memcachedserver:11211', noreply => 1 } ],
#                                     servers => [ { address => '/var/tmp/memcached.sock', noreply => 1 } ],
                                     namespace => 'perm:'
                                   });
$hosts = new Cache::Memcached::Fast({
                                     servers => [ { address => 'memcachedserver:11211', noreply => 1 } ],
#                                     servers => [ { address => '/var/tmp/memcached.sock', noreply => 1 } ],
                                     namespace => 'hosts:'
                                    });
$cat = new Cache::Memcached::Fast({
                                     servers => [ { address => 'memcachedserver:11211', noreply => 1 } ],
#                                     servers => [ { address => '/var/tmp/memcached.sock', noreply => 1 } ],
                                     namespace => 'cat:'
                                    });



if($form{url} && $form{srcname})
{
$perm->set($form{srcname}."_extendedtime",1,3600);
my $decodedurl = decode_base64($form{url});
print STDERR "DECODED ",$decodedurl," srcname: ",$form{srcname},"\n";
print << "[end]";
Status: 302
Location: $decodedurl

[end]
exit(0);
}


&printhead;


my $src = $ENV{"REMOTE_ADDR"};
my $url = URI::URL->new($form{code});

&get_result("$src ".$url->host);

exit(0);

sub get_result
{
my $line = shift;
my($src,$uri) = split(/ /,$line,2);
chomp($uri);
my $result;
my $category;
my $srcname;
my $categ;
my $block;
my %check_cat_hash;
my $expire = 3600;

#$srcname = $hosts->get("ip_".$src);
if(!$hosts->get("ip_".$src))
  { $srcname = gethostbyaddr(inet_aton($src), AF_INET) || $src; $hosts->set("ip_".$src,$srcname,$expire); }
    else
  { $srcname = $hosts->get("ip_".$src); }
      
if(!defined($perm->get($srcname."_extendedtime")))
{
    if(!check_timemap($srcname))
      {
        $result = 'TIME';
        $categ = "Non-work time";
        goto ERROR;
      }
}

#map { print STDERR "KEY: $_ VALUE: $ENV{$_}\n"; } keys %ENV;

$categ = &check_domain_category($uri) || 'undeflocal';
map { $result = 'LOC' if(defined($perm->get('0.0.0.0='.$_)) || defined($perm->get($srcname.'='.$_))); } split (";",$categ);
if($result eq 'LOC')
{
    $block = &check_category($categ,$srcname);
    $block = ($block == 1) ? 'true' : 'false';
    #
    goto ERROR;
}

$result = $hosts->get($uri);
$block = &check_category($result,$srcname);
$block = ($block == 1) ? 'true' : 'false';
$categ = $hosts->get($uri."b");
$categ =~ s/\"//g;
$result = 'FLT';

print STDERR "Result: $result Block:$block CATEG: $categ\n";
ERROR:

#print "Blocked:$block DST:$src/$srcname URI:$uri RES:$result CAT:$categ\n";

&print_page_header;
print << "[end]" if($result eq 'FLT');
<div id="wrapper">
<div id="content">
<H1>Access Denied</H1>
<p class="info">Connection to domain <a href="$url">$uri</a> blocked! </p>
<p class="info">Domain found in next categories:<br><i>$categ</i></p>
<table class="thin-border">
<tr><td>Client IP Address:</td><td>$src</td></tr>
<tr><td>Client Host Name:</td><td>$srcname</td></tr>
</table>
<br>
</div>
[end]

print << "[end]" if($result eq 'LOC');
<div id="wrapper">
<div id="content">
<H1>Access Denied</H1>
<p class="info">Connection to domain <a href="$url">$uri</a> blocked! </p>
<p class="info">Domain found in next local categories:<br><i>$categ</i></p>
<table class="thin-border">
<tr><td>Client IP Address:</td><td>$src</td></tr>
<tr><td>Client Host Name:</td><td>$srcname</td></tr>
</table>
<br>
</div>
[end]


my $encodedurl = encode_base64($url);
chomp($encodedurl);
my $time = scalar localtime(time);
print << "[end]" if($result eq 'TIME');
<div id="wrapper">
<div id="content">
<h1>Work time is out!&nbsp;&nbsp;&nbsp;Current Time: $time</h1>
<p class="info">Connection to domain <a href="$url">$uri</a> blocked!<BR>
You try to use internet connection at non working time.<BR>
Non-Work time block option used for your data safety, when you out from your workspace.<BR>
To extend your work time, press button &quot;Extend working time&quot; below.</p>
<p class="info">п■п╬я│я┌я┐п© п╨ я│п╟п╧я┌я┐ <a href="$url">$uri</a> п╥п╟п╠п╩п╬п╨п╦я─п╬п╡п╟п╫! <BR>
п■п╩я▐ п╦я│п╨п╩я▌я┤п╣п╫п╦я▐ я│п╦я┌я┐п╟я├п╦п╦ п╫п╣я│п╟п╫п╨я├п╦п╬п╫п╦я─п╬п╡п╟п╫п╫п╬пЁп╬ п╦я│п©п╬п╩я▄п╥п╬п╡п╟п╫п╦я▐ п╡п╟я┬п╣пЁп╬ п╨п╬п╪п©я▄я▌я┌п╣я─п╟,п╡ п╢п╟п╫п╫п╬п╣ п╡я─п╣п╪я▐, п╢п╬я│я┌я┐п© п╡ п╦п╫я┌п╣я─п╫п╣я┌ п╥п╟п╠п╩п╬п╨п╦я─п╬п╡п╟п╫<BR>
п■п╩я▐ п©я─п╬п╢п╬п╩п╤п╣п╫п╦я▐ я─п╟п╠п╬я┌я▀ п╫п╟п╤п╪п╦я┌п╣ п╨п╫п╬п©п╨я┐ &quot;Extend working time&quot;.</p>
<table class="thin-border">
<form method=post><input type=hidden name="url" value="$encodedurl"><input type=hidden name="srcname" value="$srcname">
<tr><td>Client IP Address:</td><td>$src</td></tr>
<tr><td>Client Host Name:</td><td>$srcname</td></tr>
<tr><td colspan=2><center><input type=submit value="Extend working time (+1 hour)"></td></tr>
</form>
</table>
<br>
</div>
[end]






#map { print "$_ = $ENV{$_}<BR>\n"; } keys %ENV;

&print_page_footer;


undef $categ;
undef $result;
}

sub check_category
{
  my $result = shift;
  my $src = shift;
  my %categories;
  my $deforder = $perm->get("0.0.0.0=order") // 0;
  my $usrorder = $perm->get($src."=order") // $deforder;
  
# Matrix UsrPERM|AllPerm
  my %matrix = ("00" => 0, "01" => 0, "10" => 1, "11" => 1);
  my $lastresult = undef;

  foreach my $cat (split (/\;/,$result))
  {
    my $defperm = $perm->get("0.0.0.0=".$cat) // 0;
    my $usrperm = $perm->get($src."=".$cat) // $defperm;
    my $catresult = $matrix{$usrperm.$defperm};
    $lastresult //= $catresult;
    if($usrorder == 0) # allow,deny
    {
      $lastresult = $lastresult | $catresult;
#      print "Last OR result $lastresult CATResult $catresult CATMatrix $usrperm:$defperm Order $usrorder\n";
    }
    else	# deny, allow
    {
      $lastresult = $lastresult & $catresult;
#      print "Last AND result $lastresult CATResult $catresult CATMatrix $usrperm:$defperm Order $usrorder\n";
#    print "Last result $lastresult $catresult $usrperm:$defperm\n";
    }
  }
  return $lastresult;
#  print "Result = $lastresult\n";
}

sub print_page_header
{
print << "[end]";
<html>
<title>Access Denied</title>
<head>
  <style type="text/css">
    * {
      font-family: Arial;
      font-size: 14px;
    }
    #wrapper {
	     text-align: center;
      padding-top: 50px;
    }
    #content {
      	text-align: left;
      	width: 600px;
      	margin: 0px auto;
       border: 1px solid silver;
       padding: 20px;
       background-color: #eee;
    }
    h1 {
      background: url(/stop.gif) no-repeat left center;
      height: 36px;
      vertical-align: bottom;
      padding-left: 50px;
      line-height: 36px;
      font-size: 18px;
      margin-top: 0px;
    }

    table.thin-border {
       border-collapse: collapse;
       border: 1px solid silver;
       width: 100%;
    }
    table.thin-border td {
      border: 1px solid silver;
      padding: 5px;
      background-color: white;
    }
  </style>
</head>
<body>

[end]
}

sub print_page_footer
{
print << "[end]";
<br/>
IT Department contact email <a href="mailto:admin\@itdep.local">admin\@itdep.local</a><BR>
</div>
</body>
</html>
[end]

}

sub systeminit				# -- Процедура инициализации начальных переменных --
{
my $fdqn = $ENV{"HTTP_HOST"};		# Присвоение запрошенного дом. имени.
my $rhn = "myhost.mydomain.com";	 	# Really Host Name - Имя домена 2 уровня
$fdqn =~ s/$rhn$//;			# Вырезание имени домена из поддомена
chop $fdqn; $fdqn =~ s/.*\.(\w+)$/$1/;  # Вырезание домена 3-го уровня
#undef %sv;				# обнуление хешей переменной sv
#undef %form;
#undef %cookie;
$sv{"ip"} = $ENV{"REMOTE_ADDR"};	# присвоение ключу ip адреса удал. хоста
$sv{"userhost"} = $ENV{"REMOTE_HOST"};
$sv{"section"} = $fdqn;			# присвоение ключу section адреса домена
$sv{"host"} = $rhn;			# основной хост = $rhn (really host name)
$sv{"url"} = $ENV{"HTTP_HOST"};		# сохранение исходного запрашиваемого пути.
$sv{"doc"} = $ENV{"DOCUMENT_ROOT"};
$sv{"ref"} = $ENV{"HTTP_REFERER"};

# ----------------------------------------------------------------------------------------

my $request_url = $ENV{"REQUEST_URI"};	# Присвоение запрошенного адреса
$request_url =~ s/%(..)/pack("c",hex($1))/ge;
$request_url =~ s/[^A-Za-z0-9\-\_\+\=\:\.\,\/\@]//g;
$request_url =~ s/([\-\_\+\=\.\:\,\/\@\s]){2,}/$1/g;
$request_url =~ s/\+/\&/g; $request_url =~ s/^\/+//g;
my $count = 0;
while ($request_url =~ /^([\w\-\=\_\&\.\,\:\@\s]+)\//)
{	$rq{$count} = $1; $request_url =~ s/$rq{$count}\///; $count++;	}
$request_url =~ s/^\s+$//g;
chomp $request_url;
$rq{$count} = $request_url if (length($request_url) > 0);

# ----------------------------------------------------------------------------------------

if ( defined($ENV{"HTTP_COOKIE"}) && length($ENV{"HTTP_COOKIE"}) > 0 )
{
    my @cookies = split(/;/,$ENV{"HTTP_COOKIE"});	# занесение списка куков в массив
    foreach (@cookies)
    {	
	my ($name,$value) = split(/=/,$_);	# получение значения куков
	$cookie{$name} = $value;
    }
}

# ----------------------------------------------------------------------------------------

    if ((defined($ENV{"QUERY_STRING"}) && length($ENV{"QUERY_STRING"}) != 0) || (defined($ENV{"CONTENT_LENGTH"}) && $ENV{"CONTENT_LENGTH"} != 0))
    {
	my $data = undef;
	my @data = undef;
	    if ($ENV{"REQUEST_METHOD"} eq "GET")
	    {
	        $data = $ENV{"QUERY_STRING"};
	    }
	    else
	    {
		read(STDIN,$data,$ENV{"CONTENT_LENGTH"});
	    }
	@data = split(/&/,$data);
	    foreach (@data)
	    {
		$_ =~ s/\+/ /g;
		my ($name, $value) = split(/=/,$_,2);
		$name =~ s/%(..)/pack("c",hex($1))/ge;
		$name =~ tr/[^A-Za-z0-9\-\_\$\+\=\~\.\,]//;
		$value =~ s/%(..)/pack("c",hex($1))/ge;
		$form{$name} .= "\0" if (defined($form{$name}));
		$form{$name} .= $value;
	    }
    }

# ----------------------------------------------------------------------------------------

}				# -- Процедура инициализации начальных переменных --

sub printhead
{
print "Cache-Control: no-cache,no-store;\r\n";
print "Content-Type: text/html; charset=UTF-8;\r\n\r\n";
}

