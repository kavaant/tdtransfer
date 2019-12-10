#! /usr/bin/perl

use strict;
use warnings;
use CGI;
use JSON::MaybeXS ();
use DBI;
use Digest::SHA;
use File::Temp qw/ tempfile /;
use Data::Dumper;
use File::Copy;

my $db_name     = 'api';
my $db_username = 'XXXXXX';
my $db_passwd   = 'XXXXXXXXXX';
my $db;
my $ref;

sub dbconnect {
    my $fout = 1;

    while ($fout != 0) {
        $db = DBI->connect("DBI:mysql:$db_name", "$db_username", "$db_passwd");
        if (!defined($db)) { $fout = 1; } else { $fout = 0; }
        if ($fout == 1) {
	    exitWithError (1, 3, 'Internal error. Contact support', 'NULL', 'dbconnect');
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


####################### MAIN #####################

dbconnect();

print "Content-Type: text/html\n\n";

print "<html><table border=1>";

print "<tr><td>id</td> <td>account_id</td> <td>datum</td> <td>ip</td> <td>function</td> <td>exitcode</td> <td>subcode</td> <td>msg</td></tr>\n";

my $q = 'select * from log';

my $sth = $db->prepare ("$q");
$? = 0;
$sth->execute() or fout("Database fout", "$q\n\n$DBI::errstr");

while ($ref = $sth->fetch)
{
  my ($id, $account_id, $datum, $ip, $function, $exitcode, $subcode, $msg) = @{$ref} ;
  print "<tr>";
  print "<td>$id</td> <td>$account_id</td> <td>$datum</td> <td>$ip</td> <td>$function</td> <td>$exitcode</td> <td>$subcode</td> <td>$msg</td>\n";
  print "</tr>";

}

print "</table></html>";
