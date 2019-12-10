#! /usr/bin/perl

sub genshadow {
    my ($pwd, $salt) = @_;
    my @letters = ('A' .. 'Z', 'a' .. 'z', '0' .. '9', '/', '.');
    if ($salt =~ /^$/) { undef($salt); }
    if (!defined($salt)) {
	$salt = '$6$' . $letters[rand@letters] . $letters[rand@letters] . $letters[rand@letters] . $letters[rand@letters] .
		$letters[rand@letters] . $letters[rand@letters] . $letters[rand@letters] . $letters[rand@letters] . '$';
    } else {
	$salt = '$6$' . $salt . '$';
    }
    my $crypt = crypt("$pwd", $salt);
    return ($crypt);
}

print genshadow("$ARGV[0]");
print "\n";