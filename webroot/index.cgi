#! /usr/bin/perl

use strict;
use warnings;
use CGI;
use JSON;
use JSON::MaybeXS ();
use DBI;
use Digest::SHA;
use File::Temp qw/ tempfile /;
use Data::Dumper;
use File::Copy;
use LWP::UserAgent;

my $db_name     = 'api';
my $db_username = 'XXXXXXX';
my $db_passwd   = 'XXXXXXX';
my $db;
my $ref;
my @warn_code = ();
my @warn_msg = ();

my $CGI = CGI->new;
my %headers = map { $_ => $CGI->http($_) } $CGI->http();

sub logtodb {
    my ($login, $function, $exitcode, $subcode, $msg) = @_;
    my $account_id;
    my $ip = $ENV{REMOTE_ADDR};

    if (!defined($ip)) {
	$ip = 'NULL';
    }

    if (!defined($function)) {
	$function = 'NULL';
    }

    if (defined($login)) {
	$account_id = query ("select id from account where login = '$login' or apikey = '$login'");
    }
    if (!defined($account_id) or ($account_id eq '')) { $account_id = -1; }
    query ("insert into log values (0, '$account_id', now(), '$ip', '$function', '$exitcode', '$subcode', '$msg');");
}

sub okheader {
    print "Content-Type: application/json\n";
    print "Status: 200 OK\n\n";
}

sub checkDigit {
    my ($lijn) = @_;
    $lijn = substr($lijn, 0, 106);
    my $sum = 0;
    my $check = 0;
    foreach my $c (split //, $lijn) {
	if ($c =~ /\d/) { 
	    $sum = $sum + $c;
	} else {
	    $sum = $sum + ord($c);
	}
    }
    $check = $sum % 97;
    if ($check == 0) { $check = 97; }
    $check = sprintf("%02s", $check);
    return ($check);
}

sub tarifperiod {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();

    $year = $year + 1900;
    if ($mon == 0) { $mon = 12; $year--; }
    my ($t) = sprintf("%04s%02s", $year, $mon);

    return ($t);
}


sub addWarning {
    my ($code, $msg) = @_;
    push (@warn_code, $code);
    push (@warn_msg, $msg);
}

sub printWarnings {
    my $w = '';
    my $tel = 0;
    foreach my $c (@warn_code) {
	$w .= "code => $c,";
	my $m = $warn_msg[$tel];
	$w .= "msg => $m,";
	$tel++;
    }
    return ($w);
}

sub exitWithError {
    my ($httpstatus, $s, $e, $m, $login, $function) = @_;
    my $err = {
	statuscode => $s,
	feedback => [
	    { code => $e, msg => "$m", },
	],
    };

    if ($m ne "No function provided") { 
        logtodb ($login, $function, $s, $e, $m);
    }

    my $tel = 0;
    foreach my $c (@warn_code) {
        push (@{$err->{feedback}}, {code => $c, msg => $warn_msg[$tel] });
	$tel++;
    }

    my $json = JSON::MaybeXS->new(utf8 => 1, pretty => 1, canonical => 1);
    my $error_json = $json->encode($err);

    print "Content-Type: application/json\n";
    print "Status: $httpstatus\n\n";

    print $error_json;
    exit;
}

sub dbconnect {
    my $fout = 1;

    while ($fout != 0) {
        $db = DBI->connect("DBI:mysql:$db_name", "$db_username", "$db_passwd");
        if (!defined($db)) { $fout = 1; } else { $fout = 0; }
        if ($fout == 1) {
        }
    }
}

sub query {
    my ($q) = @_;
    my $code = 0;
    my $sth = $db->prepare ("$q");
    my $ref;
    $? = 0;
    if (!defined($sth)) { fout("Database fout", "$q\n\n$DBI::errstr"); }
    $sth->execute() || fout("Database fout", "$q\n\n$DBI::errstr");
    $code = $?;
    if ($q =~ /^select/i) {
        if (!($ref = $sth->fetch)) {
            $code = 1;
        }
    }
    if (defined($ref)) {
        $? = $code;
        return @{$ref};
    }
}

sub generateApiKey {
    my @chars = ("A".."Z", "a".."z");
    my $string;
    $string .= $chars[rand @chars] for 1..40;
    return ($string);
}

sub getApiKey {
    my ($login, $password) = @_;

    # sanitize injection attacks
    $login =~ s/[^a-z0-9]//gis;
    $password =~ s/[^a-z0-9]//gis;

    my ($p, $apikey) = query ("select password from account where login = '$login'");
    my $salt = substr($p, 3, 8);
    my $hash = "(undefined)";
    if (defined($password)) {
        ($hash) = crypt($password, "\$6\$$salt\$");
    }


    if ($json_obj->{is_error} != 0) {
        exitWithError(200, 1, $json_obj->{is_error}, $json_obj->{error_message}, $login, "testpw");
    }
    
    if ( !$json_obj->{match} ) {
        exitWithError(200, 1, 1, "Password incorrect or no tarif permission", $login, "testpw");
    }

    if ($hash ne $p) {
	exitWithError('401 Incorrect login or password', 1, 1, 'Incorrect login or password', $login, 'getapikey');
    } else {
	my $apikey = generateApiKey;
	query ("update account set apikey = '$apikey' where login = '$login'");
	my $err = {
	    statuscode => 0,
	    feedback => {
		code => 0,
	        msg => "$apikey",
	    },
	};
	my $json = JSON::MaybeXS->new(utf8 => 1, pretty => 1, canonical => 1);
        my $error_json = $json->encode($err);
	okheader();
        print $error_json;
	exit 0;
    }
}

sub showAllHeaders {
    print $CGI->header('text/plain');
    print "Got the following headers:\n";
    for my $header ( keys %headers ) {
        print "$header: $headers{$header}\n";
    }
}

sub sendTarifFile {
    my ($apikey, $file) = @_;
    my $tarifdate  = '';
    my $tdgversion = '';
    my $nroflines  = 0;
    my $numpresc   = 0;
    my $numspec    = 0;
    my $nummag     = 0;
    my $firstpresc = '';
    my $lastpresc  = '';

    $apikey =~ s/[^a-z0-9]//gis;

    my ($apbnr) = query ("select apbnr from account where apikey = '$apikey'");

    if (!defined($apbnr) || $apbnr eq '') {
	exitWithError('401 Invalid apikey', 1, 1, 'Apikey is not valid or does not exist', $apikey, 'getapikey');
    }

    my ($fh, $filename) = tempfile();
    binmode( $fh, ":utf8" );

    open ($fh, "> $filename");

    my $lastlijn = '';

    my $up = $CGI->upload('file');
    if (!defined($up)) {
	exitWithError('422 No file sent', 1, 9, 'No file sent', $apikey, 'sendfile');
    }

    while (my $i = <$up>) {
        print $fh $i;
	if ($nroflines == 0) { ### informatie van de eerste lijn
	    if ($i !~ /^1/) {
		exitWithError('422 Not a valid tdg file', 1, 2, 'This is not a valid tdg-file', $apikey, 'sendfile');
	    }
	    my $fapbnr = substr($i, 1, 6);
	    if ($fapbnr ne $apbnr) {
		exitWithError('401 Apbnr does not match apikey', 1, 2, 'Apbnr does not match apikey', $apikey, 'sendfile');
	    }
	    $tarifdate  = substr($i, 19, 6);
	    $tdgversion = substr($i, 28, 4);
	}
	if ($i =~ /^2/) { 
	    $numpresc++; 
	    if (substr($i, 1, 8) =~ /^\d+/) {
		$lastpresc = substr($i, 1, 8);
		if ($firstpresc eq '') { $firstpresc = $lastpresc; }
    	    }
	}
	if ($i =~ /^3/) {
	    $numspec++;
	}
	if ($i =~ /^4/) {
	    $nummag++;
	}
        my ($cd) = checkDigit($i);
        if (substr($i, 106, 2) ne "$cd") {
	    my $linenr = $nroflines + 1;
            addWarning (6, "Check digit for line $linenr is incorrect ($cd)");
        }
	$nroflines++;
	$lastlijn = $i;
    }
    close($fh);
    close($up);

    if ($lastlijn !~ /^T/) {
	chomp $lastlijn;
	exitWithError('422 T-Record does not exist', 1, 4, "T-record does not exist ($lastlijn)", $apikey, 'sendfile');
    }

    my ($cd) = checkDigit($lastlijn);
    if (substr($lastlijn, 106, 2) ne "$cd") {
    	    addWarning (6, "Check digit for T-record is incorrect ($cd)");
    }

    my $nrchecksum = substr($lastlijn, 12, 6);
    if ( ($nrchecksum !~ /^\d+/) || ($nrchecksum != $nroflines) ) {
	addWarning(5, 'number of lines does not match checksum number in T-record');
    }

    my $sha = Digest::SHA->new('sha256');
    $sha->addfile($filename);
    my $digest = $sha->b64digest;

    if ($tarifdate ne tarifperiod()) {
	addWarning(7, "Tarification period (" . $tarifdate . "!=" . tarifperiod() . ") not actual");
    }

    my ($did) = query ("select id from filehashes where hash = \"$digest\"");

    if ($did != 0) {
	@warn_code = ();
        exitWithError ('422 File already uploaded', 1, 8, 'File already uploaded', $apikey, 'sendfile');
    }
    query ("insert into filehashes values(0, now(), '$digest')");

    my $apikeynew = generateApiKey;
    query ("update account set apikey = '$apikeynew' where apikey = '$apikey'");
    $apikey = $apikeynew;

    my $err = {
	"statuscode" => 0,
	"date" => "$tarifdate",
	"number-lines" => $nroflines,
	"number-presc" => $numpresc,
	"first-presc" => $firstpresc,
	"last-presc" => $lastpresc,
	"number-spec" => $numspec,
	"number-mag" => $nummag,
	"protocol-version" => $tdgversion,
	"sha256-hash" => $digest,
	"apikey" => $apikey
    };

    my $tel = 0;
    foreach my $c (@warn_code) {
        push (@{$err->{feedback}}, {code => $c, msg => $warn_msg[$tel] });
	$tel++;
	$err->{statuscode} = 2; #warning
    }

    my $json = JSON::MaybeXS->new(utf8 => 1, pretty => 1, canonical => 1);
    my $error_json = $json->encode($err);

    okheader();
    print $error_json;

    logtodb($apikey, 'sendfile', 0, 0, "File for $apbnr received");

    my $volgnr = '';
    my $dest = "/tdfiles/$apbnr.$tarifdate";

    while (-e "$dest") {
	$volgnr++;
	$volgnr = sprintf("%02s", $volgnr);
	$dest = "/tdfiles/$apbnr.$tarifdate.$volgnr";
    }

    move ($filename, "$dest");
}


sub sendOcmwFile {
    my ($apikey, $file) = @_;
    my ($fh, $filename) = tempfile();
    binmode( $fh, ":utf8" );

    #sanitize
    $apikey =~ s/[^a-z0-9]//gis;

    open ($fh, "> $filename");

    my $lastlijn = '';

    my $up = $CGI->upload('file');
    if (!defined($up)) {
	exitWithError('422 No file sent', 1, 9, 'No file sent', $apikey, 'sendfile');
    }

    while (my $i = <$up>) {
        print $fh $i;
    }
    close($fh);
    close($up);

    my $volgnr = 0;
    $volgnr = sprintf("%02s", $volgnr);
    my $dest = "/ocmw/ocmw.$volgnr";

    while (-e "$dest") {
	$volgnr++;
	$volgnr = sprintf("%02s", $volgnr);
	$dest = "/ocmw/ocmw.$volgnr";
    }

    move ($filename, "$dest");

    okheader();

print <<EOF
{
   "feedback" : [
      {
         "code" : 0,
         "msg" : "File received"
      }
   ],
   "statuscode" : 0
}
EOF
;

}

####################### MAIN #####################

dbconnect();

if (!defined($headers{'HTTP_FUNCTION'})) {
    exitWithError('400 No function provided', 1, 2, 'No function provided');
}

my $filetype;

if ( (!defined($headers{'HTTP_FILETYPE'})) || ($headers{'HTTP_FILETYPE'} =~ /TAR/i) || ($headers{'HTTP_FILETYPE'} =~ /TUH/i) )  {
    $filetype = 'tarif';
} else {
    $filetype = 'ocmw';
}

if (lc $headers{'HTTP_FUNCTION'} eq 'getapikey') {
    getApiKey($headers{'HTTP_LOGIN'}, $headers{'HTTP_PASSWORD'});
} elsif (lc $headers{'HTTP_FUNCTION'} eq 'sendfile') {
    if ($filetype eq "tarif") {
        sendTarifFile($headers{'HTTP_APIKEY'}, $headers{'HTTP_FILENAME'});
    } else {
        sendOcmwFile($headers{'HTTP_APIKEY'}, $headers{'HTTP_FILENAME'});
    }
} else {
    exitWithError('400 Unknown function', 1, 2, 'Unknown function');
}
