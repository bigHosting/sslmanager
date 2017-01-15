#!/usr/bin/perl

use strict;
use warnings FATAL => "all";

#use File::Temp qw/ tempfile tempdir /;
use Getopt::Long;

sub ltrim;             # left trim function
sub rtrim;             # right trim function
sub trim;              # left & right trim function

my %opts = ();

my %commands = (
        key           => 'openssl genrsa -des3 -passout pass:PASSWORDHERE -out KEY 2048',
        csr           => 'openssl req -new -sha256 -passin pass:PASSWORDHERE -key KEY -out CSR -subj',
        verifycsr     => 'openssl req -noout -text -in CSR',
        verifysubject => 'openssl req -noout -subject -in CSR',
        strippassword => 'openssl rsa -in KEY -out KEY.nopass'
);

my %defaults = (
    C            => 'US',
    ST           => 'My State',
    L            => 'My City',
    O            => 'My Inc.',
    OU           => 'Internet',
    CN           => '*.sec.domain.com',
    emailAddress => 'security@domain.com',
);

GetOptions(\%opts, 
    'C|Country:s',
    'ST|State:s',
    'L|Locality|City:s',
    'O|Organization:s',
    'OU|OrganizationalUnit|U:s',
    'CN|CommonName|N:s',
    'emailAddress|email|E:s',
    'file|F:s',
    'help|H|h',
) or usage();

usage() if $opts{help};

# initialize defaults
foreach my $key ( keys %defaults ) {
        $opts{$key} = $defaults{$key} unless $opts{$key}
        #$country ||= "/C=$altCountry";
}

##########################
#####  global  VARs  #####
##########################
my $save_to = '/services/certificates';
my $filename = $opts{CN};

############################
#####  SAFETY  CHECKs  #####
############################

# 'number' the dots
my $count_dots = 0;
$count_dots++ while ($opts{CN} =~ m/\./g);

if ( $count_dots == 0 )
{
    die "[*] $0: ERROR: invalid domain name, you need at least one '.'\n";
}

# extract 'domain.com' from cert CN. Exclude situations where we generate cert for '.net'
my @domain = split(/\./, $opts{CN});
@domain = grep defined, @domain;
@domain = grep length, @domain;

if ( scalar (@domain) == 1 )
{
    die "[*] $0: ERROR: invalid domain";
}

my @last_two = @domain[ $#domain - 1 .. $#domain ];
my $folder =  join ".", @last_two;

# wildcards
if ( $opts{CN} =~ m/^\*/g )
{
        # replace * with 'wildcard'
        $filename =~ s/\*/wildcard/g;
}

##########################################
#####  check if files/folders exist  #####
##########################################
if ( ! -d "$save_to/$folder")
{
        print "[*] $0: INFO: mkdir $save_to/$folder/\n";
        mkdir "$save_to/$folder" or die "[*] $0: ERROR: mkdir $save_to/$folder failed: $!";
        chmod (0000, "$save_to/$folder") or die "[*] $0: ERROR: chmod 0000 $save_to/$folder failed: $!";
}

my $key = "$save_to/$folder/$filename.key";
my $csr = "$save_to/$folder/$filename.csr";

if ( ( -f $key) || (-f $csr) )
{
        die "[*] $0: ERROR: key $key or csr $csr already exists, manually remove them!";
}
print "\n";


#########################################
#####  replace strings in commands  #####
#########################################
$commands{key}       =~ s/KEY/$key/g;
$commands{csr}       =~ s/KEY/$key/g;
$commands{csr}       =~ s/CSR/$csr/g;
$commands{verifycsr} =~ s/CSR/$csr/g;
$commands{verifysubject} =~ s/CSR/$csr/g;


##########################
#####  generate key  #####
##########################

print "[*] $0: INFO: generating KEY: $key\n";
#print "[*] $0: INFO: " . $commands{key} . "\n";
sleep(4);
system($commands{key}) == 0 or die "Cannot create server key $key: $?";
if ( ! -f $key )
{
        die "[*] $0: ERROR: key generation failed";
} else {
        print "[*] $0: INFO: file $key generated successfully\n";
        chmod (0600, $key) or die "[*] $0: ERROR: chmod 0600 $key failed: $!";
}
print "\n";

##########################
#####  generate csr  #####
##########################
print "[*] $0: INFO: generating CSR: $csr\n";
#print "[*] $0: INFO: $cmd\n";
sleep(4);
my $cmd = sprintf ("%s '/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s'",$commands{csr},$opts{C},$opts{ST},$opts{L},$opts{O},$opts{OU},$opts{CN},$opts{emailAddress});
system($cmd) == 0 or die "Cannot create server csr $csr: $?";
if ( ! -f $csr )
{
        die "[*] $0: ERROR: csr generation failed";
} else {
        print "[*] $0: INFO: file $csr generated successfully\n";
        chmod (0600, $csr) or die "[*] $0: ERROR: chmod 0600 $csr failed: $!";
}
print "\n";

########################
#####  verify csr  #####
########################
print "[*] $0: INFO: verify CSR subject: INFO: " . $commands{verifysubject} . "\n";
sleep(3);
system($commands{verifysubject}) == 0 or die "[*] $0: ERROR: Cannot verify csr subject $csr: $?";
print "\n";

print "[*] $0: INFO: verify CSR: INFO: " . $commands{verifycsr} . "\n";
sleep(3);
system($commands{verifycsr}) == 0 or die "[*] $0: ERROR: Cannot verify csr $csr: $?";
print "\n";



exit(0);

sub usage {
    print STDERR <<"EOT";

 $0 will generate a TLS certificate "the quick way",
 i.e. without interaction.  You can change some defaults however.

 These options are recognized:             Default:

  --C       Country (two letters, e.g. DE) $defaults{C}
  --ST      State (spelled out)            $defaults{ST}
  --L       City                           $defaults{L}
  --O       Organization                   $defaults{O}
  --OU      Organizational Unit            $defaults{OU}
  --CN      Common name                    $defaults{CN}
  --email   Email address of postmaster    $defaults{emailAddress}
  --help    Show usage

EOT
    exit(1);
}

sub ltrim {
        my $s = shift;
        $s =~ s/^\s+//;
        return $s;
};

sub rtrim {
        my $s = shift;
        $s =~ s/\s+$//;
        return $s;
};
sub trim  {
        my $s = shift;
        $s =~ s/^\s+|\s+$//g;
        return $s;
};

