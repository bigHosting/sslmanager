#!/usr/bin/perl

#
# (c) SecurityGuy
#
# Changelog:
#     2016.04.06 - added initial release
#

#CREATE TABLE `sslmanager` (
#  `id` mediumint(10) unsigned NOT NULL AUTO_INCREMENT,
#  `partner` varchar(255) NOT NULL DEFAULT 'NONE',
#  `HID` int(8) DEFAULT '99999',
#  `cluster` smallint(4) DEFAULT '9999',
#  `country` varchar(2) NOT NULL,
#  `state` varchar(255) NOT NULL,
#  `city` varchar(255) NOT NULL,
#  `organization` varchar(255) NOT NULL,
#  `organizationalunit` varchar(255) NOT NULL DEFAULT 'Internet',
#  `commonname` varchar(255) NOT NULL,
#  `email` varchar(255) NOT NULL,
#  `key` text,
#  `csr` text,
#  `crt` text,
#  `intermediate` text NOT NULL,
#  `partnerapproved` varchar(255) NOT NULL DEFAULT 'no',
#  `lastupdates` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
#  `comment` text,
#  PRIMARY KEY (`id`),
#  UNIQUE KEY `index` (`commonname`)
#) ENGINE=InnoDB AUTO_INCREMENT=461 DEFAULT CHARSET=latin1;



use strict;
use warnings;

# flush buffers
$| = 1;

######################
# included in distro #
######################
use File::Basename qw(dirname);                     # dirname
use POSIX qw(strftime);                             # time


# set debug to 1 to see details on each action!
our $debug = 1;
our $debug_mysql = 1;

# check if modules exist
my $count_failed_modules = 0;
my @modules = qw( File::stat File::Basename File::Path File::Find  DBI DBD::mysql POSIX utf8 Data::Dumper);

for my $module (@modules) {
        eval "require $module";
        my $ok = '';
        if ($@) {
                $ok =  "NOT INSTALLED\n";
                $count_failed_modules++;
        } else {
                $ok = "INSTALLED\n";
        }
        printf ("%-23s  %-s",($module, $ok)) if ($debug);

}

if ( $count_failed_modules != 0)
{
                die "[*]: $0: ERROR: one or more required modules not installed. On CentOS you should run: yum install perl-.....";
}

use DBI;
use DBD::mysql;
use Data::Dumper 'Dumper';

#####################
##### functions #####
#####################
sub _read_file;
sub _get_dbh;
sub _select_hashref;
sub _update_row_hashref;
sub ltrim;             # left trim function
sub rtrim;             # right trim function
sub trim;              # left & right trim function

#######################
#####  constants  #####
#######################
use constant
{
        USER       => "sslmanager",
        DB         => "sslmanager",
        PWD        => "*****",
        MYSQLHOST  => "127.0.0.1"
};

#########################
######  GLOBAL vars  #####
##########################
my %attr = (
        PrintError                  => 1,
        RaiseError                  => 1,
        PrintWarn                   => 0,
        mysql_enable_utf8           => 1
);
my $query = "SELECT * FROM `sslmanager` WHERE ( `key` = '' OR `key` IS NULL) AND (id >= (SELECT FLOOR( MAX(id) * RAND()) FROM `sslmanager` )) ORDER BY id LIMIT 1";
my $save_to = '/services/certificates';



## test mysql
my $dbh = &_get_dbh ( USER, PWD, MYSQLHOST, DB );

my $db_entries  = &_select_hashref ($dbh, $query);

if (scalar(@{$db_entries}) > 0)
{
        foreach my $item ( @{ $db_entries })
        {

                my %info = (); # hash for inserting key, csr
                print Dumper ($item);
                print "\n";

                # row id
                my $id             = $item->{'id'};

                # rest of row entries
                my $country             = trim($item->{'country'});
                my $state               = trim($item->{'state'});
                my $city                = trim($item->{'city'});
                my $organization        = trim($item->{'organization'});
                my $organizationalunit  = trim($item->{'organizationalunit'});
                my $commonname          = trim($item->{'commonname'});
                my $email               = trim($item->{'email'});

                # sanity checks #
                next if ( length ($country) != 2);
                next if ( (length($state) < 2) );
                next if ( (length($city)  < 2) );
                next if ( (length($organization) < 2) );
                next if ( (length($organizationalunit) < 2) );
                next if ( (length($commonname) < 2) );
                next if ( ($email =~ m/NONE/) || (length($email) <= 5) );

                # filename #
                my $filename = $commonname;
                $filename =~ s/\*/wildcard/g;  # replace * -> wildcard

                # domain #
                my @domain = split(/\./, $commonname);
                @domain = grep defined, @domain;
                @domain = grep length, @domain;
                if ( scalar (@domain) == 1 )
                {
                        warn "[*] $0: ERROR: invalid domain";
                        next;
                }
                my @last_two = @domain[ $#domain - 1 .. $#domain ];
                my $folder =  join ".", @last_two;


                my $key = "$save_to/$folder/$filename.key";
                my $csr = "$save_to/$folder/$filename.csr";
                my $crt = "$save_to/$folder/$filename.crt";

                # skip if certificates exist
                next if ( ( -f $key) && ( -f $csr) );

                ##########################
                #####  generate cert #####
                ##########################
                if ( (! -f $key) && (! -f $csr) )
                {
                        my $cmd = sprintf ("/localservices/sbin/gen_csr.pl --C '%s' --ST '%s' --L '%s' --O '%s' --OU '%s' --CN '%s' --email '%s'", $country, $state, $city, $organization, $organizationalunit, $commonname, $email);
                        print "CMD: " . $cmd . "\n"; 
                        system ($cmd);
                }

                ########################
                #####  upload cert #####
                ########################
                if ( ( -f $key) && ( -f $csr) )
                {
                        # read key, csr
                        $info{key} = _read_file($key);
                        $info{csr} = _read_file($csr);
                        # update certs in DB
                        _update_row_hashref ($dbh,"sslmanager", \%info , $id);
                }
        }
}

$dbh->disconnect();



#####  DO NOT MODIFY  #####

#######################
#####  FUNCTIONS  #####
#######################

sub _get_dbh($$$$)
{
        my ($username, $password, $host, $database) = @_;
        my ($wait,$i) = 0;

        if ( (!defined ($username)) || (!defined ($password)) || (!defined ($database)) || (!defined ($host)) )
        {
                die ("[*] $0: ERROR: _get_dbh arguments not properly defined");
        }

        print "[*] $0: INFO: MySQL settings USER: " . $username . " PAS: " . $password . " HOST: " . $host . " DB: " . $database . "\n" if ($debug);

        my $dsn = sprintf("DBI:mysql:database=%s;host=%s;mysql_connect_timeout=10",$database,$host);
        for ($i = 0; $i < 5; $i++)
        {

                my ($dbh) = undef;

                eval
                {
                        $dbh = DBI->connect($dsn, $username, $password, \%attr);
                };

                if ($dbh)
                {
                        $dbh->{"mysql_auto_reconnect"} = 1;
                        $dbh->do(q{SET SESSION sql_mode=STRICT_ALL_TABLES;});  # for record integrity we need strict mode
                        #$dbh->exec('SET SESSION sql_mode=STRICT_TRANS_TABLES', $noop);
                        return $dbh;
                }

                print "[*] $0: ERROR: could not connect to mysql, try number " . $i . "\n" if ($debug);
                $wait += 5;
                sleep($wait * 60);
        }
        die "[*] $0: ERROR: $dbh->errstr\n";
}

# update row
sub _update_row_hashref($$$$)
{
        my ( $dbh, $table, $hash_ref, $id ) = ( shift, shift, shift, shift );

        if ( (!defined ($table))    ||  (!length ($table)) )    { die ("[*] $0: ERROR: _update() arg table"); }
        if ( (!defined ($hash_ref)) ||  (!length ($hash_ref)) ) { die ("[*] $0: ERROR: _update() arg hash_ref"); }
        if ( (!defined ($id))       ||  (!length ($id)) )       { die ("[*] $0: ERROR: _update() arg id"); }

        $table = $dbh->quote_identifier($table);

        my $query = $dbh->prepare( "UPDATE $table SET "
                           . join( ", ",   map { $dbh->quote_identifier($_) . ' = ' . $dbh->quote($hash_ref->{$_}) } keys %{ $hash_ref } )
                                 . " WHERE id = '$id'" );
                                #. join( ", ", map { "$_ = '$hash_ref->{$_}'" } keys %$hash_ref )

        print $query->{Statement} . ";\n" if ($debug_mysql);
        $query->execute ();
        if ( $dbh->err() ) {
                die "$DBI::errstr\n";
        }
        return (0);

}

# select rows
sub _select_hashref ($$)
{
        my ($dbh, $sql) = @_;

        if ( (!defined ($sql)) ||  (!length ($sql)) ) { die ("[*] $0: ERROR: _select_execute() arg sql"); }

        my $sth = $dbh->prepare($sql);

        print $sth->{Statement} . ";\n" if ($debug_mysql);

        $sth->execute();
        if ( $dbh->err() )
        {
                die "$DBI::errstr\n";
        }

        my $ref = $sth->fetchall_arrayref({});

        if ( ! defined $ref )
        {
                return undef;
        }

        return  $ref;
}

# Reads en entire file for processing
sub _read_file
{
        my $filename = $_[0];
        #print "$filename\n";
        my $localcontent;
        open(my $fh, '<', $filename) or die "cannot open file $filename";
        {
                local $/;
                $localcontent = <$fh>;
        }
        close($fh);

        return $localcontent;
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

