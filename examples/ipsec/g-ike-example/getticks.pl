#!/usr/bin/perl
use File::Copy;

# getting number of candidate members
$totalcandidatemember = 0;
my $conffile 	= '/home/user/contiki/examples/Group-IKE/apps/ipsec/ike/g-ike-conf.h';
open CONF, $conffile or die "$conffile: Open failed: $!";
while (<CONF>) {
	(/#define NUM_OF_CAN_MEMBERS (.*)/) && do {$totalcandidatemember = $1};
}
print "NUM_OF_CAN_MEMBERS: $totalcandidatemember\n";

# CLIENT
my @logfiles 	= glob('/home/user/contiki/examples/Group-IKE/examples/ipsec/g-ike-example/cc*');

$temp1 = 0; $temp2 = 0; $temp3 = 0; $temp4 = 0; $temp5 = 0; $temp6 = 0; $temp7 = 0; $temp8 = 0;
$temp9 = 0; $temp10 = 0; $temp11 = 0; $temp12 = 0; $temp13 = 0; $temp14 = 0; $temp15 = 0; $temp16 = 0;
$temp17 = 0;
$continue0 = 0;
$continue1 = 0;
$continue2 = 0;
$continue3 = 0;
$continue4 = 0;
$continue5 = 0;
$type = 0;

$tempfile = "temp.csv";
open RESULT, ">$tempfile";

for my $file (@logfiles) {
	$order = 0;
	print RESULT "$file\n";
	open CONF, $file or die "$file: Open failed: $!";

	while (<CONF>) {
		(/\#P IKE Init > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp1 = $4;
			$temp2 = $5;
			$temp3 = $6;
			$temp4 = $7;
			print RESULT "IKE Initialization,$temp1,$temp2,$temp3,$temp4\n";
		};
		(/\#P Group-IKE start > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp5 = $4;
			$temp6 = $5;
			$temp7 = $6;
			$temp8 = $7;
			$continue1 = 1;
		};
		if ($continue1 == 1) {
			(/\#P (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				if ($6 > 0) {
					$temp7 = $6 + $temp7;
					print RESULT "IKE_SA_INIT,$temp5,$temp6,$temp7,$temp8\n";
					$continue1 = 0;
					$continue2 = 1;
				}
			}
		}
		if ($continue2 == 1) {
			(/\#P IKE_Timeout > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp9 = $4;
				$temp10 = $5;
				$temp11 = $6;
				$temp12 = $7;
				$continue3 = 1;
			};
			if ($continue3 == 1) {
				(/\#P (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
					if ($6 > 0) {
						$temp11 = $6 + $temp11;
						print RESULT "IKE TIMEOUT,$temp9,$temp10,$temp11,$temp12\n";
						$continue3 = 0;
					}
				}
			}

			(/End of GSA_AUTH message/) && do {$type = 1};
			(/PARSED THE GSA_AUTH SUCCESSFULLY/) && do {$type = 2};
			(/NOTIFY MESSAGE FAILURE/) && do {$type = 3};
			(/GSAK ENTRY WITH SPI/) && ($type != 6) && ($type != 7) && do {$type = 4};
			(/GSA_REKEY/) && ($type != 4) && ($type != 6) && ($type != 7) && do {$type = 5};
			(/Rekey message - Leave1/) && do {$type = 6};
			(/Rekey message - Leave2/) && do {$type = 7};

			(/\#P IKE > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp13 = $4;
				$temp14 = $5;
				$temp15 = $6;
				$temp16 = $7;
				$continue4 = 1;
			};
			if ($continue4 == 1) {
				if ($type == 1) {
					((/\#P (.*) < (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) ||
			 		(/\#P UDP (.*) (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/)) && do {
						$temp15 = $7 + $temp15;
						print RESULT "GSA_AUTH REQUEST,$temp13,$temp14,$temp15,$temp16\n";
						$type = 0;
				$continue4 = 0;
					}
				} elsif ($type == 2) {
					print RESULT "GSA_AUTH PARSING SUCCESSFUL,$temp13,$temp14,$temp15,$temp16\n";
					$type = 0;
				$continue4 = 0;
				} elsif ($type == 3) {
					print RESULT "IKE FAILED,$temp13,$temp14,$temp15,$temp16\n";
					$type = 0;
				$continue4 = 0;
				} elsif ($type == 4) {
					print RESULT "GSA_REKEY JOIN,$temp13,$temp14,$temp15,$temp16\n";
					$order++;
					$type = 0;
				$continue4 = 0;
				} elsif ($type == 5) {
					print RESULT "GSA_REKEY PERIODIC,$temp13,$temp14,$temp15,$temp16\n";
					$type = 0;
				$continue4 = 0;
				} elsif ($type == 6) {
					print RESULT "GSA_REKEY LEAVE1,$temp13,$temp14,$temp15,$temp16\n";
					$type = 0;
				$continue4 = 0;
				} elsif ($type == 7) {
					print RESULT "GSA_REKEY LEAVE2,$temp13,$temp14,$temp15,$temp16\n";
					$type = 0;
				$continue4 = 0;
				} else {
					print RESULT "IKE,$temp13,$temp14,$temp15,$temp16\n";
				$continue4 = 0;
				}
			}
		}
		(/Start time: (.*)/) && do {
			if ($continue5 == 0) {
				$temp17 = $1;
			}
			$continue5 = 1;
		};
		if ($continue5 == 1) {
			(/End time: (.*)/) && do {
				$temp17 = $1 - $temp17;
				print RESULT "IKE TIME,$temp17\n";
			}
		}
	}
	close CONF;
	$continue5 = 0;
	$temp17 = 0;
	$fixorder = $totalcandidatemember-$order;
	#print "order $order total candidate $totalcandidatemember\n";
	print RESULT "ORDER,$fixorder\n";
}
close RESULT;

#TOTAL FOR CLIENT
$temp1 = 0; $temp2 = 0; $temp3 = 0; $temp4 = 0;
$continue1 = 0;

$outputfile = "client.csv";
open RESULT, ">$outputfile";
open TEMP, $tempfile or die "$tempfile: Open failed: $!";
#open RESULT, "+<", $outputfile or die "$outputfile: Open failed: $!";

while (<TEMP>) {
	print RESULT $_;
	(/IKE_SA_INIT/) && do {
		$continue1 = 1;
	};
	if ($continue1 == 1) {
		(/(.*),(.*),(.*),(.*),(.*)/) && do {
			$temp1 += $2;
			$temp2 += $3;
			$temp3 += $4;
			$temp4 += $5;
		};

		(/GSA_AUTH PARSING SUCCESSFUL/) && do {
			$continue1 = 0;
			print RESULT "TOTAL,$temp1,$temp2,$temp3,$temp4\n";
			$temp1 = 0; $temp2 = 0; $temp3 = 0; $temp4 = 0;
		};
	}
}
close TEMP;
close RESULT;

# SERVER
my @logfiles 	= [];
my @logfiles 	= glob('/home/user/contiki/examples/Group-IKE/examples/ipsec/g-ike-example/ss*');

$temp1 = 0; $temp2 = 0; $temp3 = 0; $temp4 = 0; $temp5 = 0; $temp6 = 0; $temp7 = 0; $temp8 = 0;
$temp9 = 0; $temp10 = 0; $temp11 = 0; $temp12 = 0; $temp13 = 0; $temp14 = 0; $temp15 = 0; $temp16 = 0;
$temp17 = 0; $temp18 = 0; $temp19 = 0; $temp20 = 0;
$continue1 = 0;
$continue2 = 0;
$continue3 = 0;
$continue4 = 0;
$continue5 = 0;
$continue6 = 0;
$continue7 = 0;
$type = 0;

$tempfile = "temp.csv";
open RESULT, ">$tempfile";

#$outputfile = "server.csv";
#open RESULT, ">$outputfile";

for my $file (@logfiles) {
	print RESULT "$file\n";
	open CONF, $file or die "$file: Open failed: $!";

	while (<CONF>) {
			(/parse_peer_proposal/) && do {$type = 1};
			(/end = /) && do {$type = 3};
			(/PARSED THE GSA_AUTH SUCCESSFULLY/) && do {$type = 2};

		(/\#P IKE > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp1 = $4;
			$temp2 = $5;
			$temp3 = $6;
			$temp4 = $7;
			$continue1 = 1;
		};
		if ($continue1 == 1) {
			(/\#P (.*)< (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp3 = $7 + $temp3;
				if ($type == 1) {
					print RESULT "IKE_SA_INIT PARSING,$temp1,$temp2,$temp3,$temp4\n";
					$type = 0;
				} elsif ($type == 2) {
					print RESULT "GSA_AUTH PARSING SUCCESSFUL,$temp1,$temp2,$temp3,$temp4\n";
					$type = 0;
				} elsif ($type == 3) {
					print RESULT "GSA_AUTH PARSING FAILED,$temp1,$temp2,$temp3,$temp4\n";
					$type = 0;
				} else {
					print RESULT "IKE,$temp1,$temp2,$temp3,$temp4\n";
				}
				$continue1 = 0;
			};
		}
		(/\#P GSA_REKEY > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp5 = $4;
			$temp6 = $5;
			$temp7 = $6;
			$temp8 = $7;
			$continue2 = 1;
		};
		if ($continue2 == 1) {
			(/\#P (.*)< (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp7 = $7 + $temp7;
				print RESULT "GSA_REKEY PERIODIC,$temp5,$temp6,$temp7,$temp8\n";
				$continue2 = 0;
			};
		}
		(/\#P GSA_REKEY0 > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp9 = $4;
			$temp10 = $5;
			$temp11 = $6;
			$temp12 = $7;
			$continue3 = 1;
		};
		if ($continue3 == 1) {
			(/\#P (.*)< (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp11 = $7 + $temp11;
				print RESULT "GSA_REKEY PERIODIC,$temp9,$temp10,$temp11,$temp12\n";
				$continue3 = 0;
			};
		}
		(/\#P GSA_REKEY1 > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp13 = $4;
			$temp14 = $5;
			$temp15 = $6;
			$temp16 = $7;
			$continue4 = 1;
		};
		if ($continue4 == 1) {
			(/\#P (.*)< (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp15 = $7 + $temp15;
				print RESULT "GSA_REKEY JOIN,$temp13,$temp14,$temp15,$temp16\n";
				$continue4 = 0;
			};
		}
		(/\#P GSA_REKEY2 > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp17 = $4;
			$temp18 = $5;
			$temp19 = $6;
			$temp20 = $7;
			$continue5 = 1;
		};
		if ($continue5 == 1) {
			(/\#P (.*)< (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp19 = $7 + $temp19;
				print RESULT "GSA_REKEY LEAVE1,$temp17,$temp18,$temp19,$temp20\n";
				$continue5 = 0;
			};
		}
		(/\#P GSA_REKEY3 > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp21 = $4;
			$temp22 = $5;
			$temp23 = $6;
			$temp24 = $7;
			$continue6 = 1;
		};
		if ($continue6 == 1) {
			(/\#P (.*)< (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp23 = $7 + $temp23;
				print RESULT "GSA_REKEY LEAVE2,$temp21,$temp22,$temp23,$temp24\n";
				$continue6 = 0;
			};
		}
		(/\#P GSA_REKEY LEAVE > (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
			$temp25 = $4;
			$temp26 = $5;
			$temp27 = $6;
			$temp28 = $7;
			$continue7 = 1;
		};
		if ($continue7 == 1) {
			(/\#P (.*)< (.*) P (.*)\.(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s(.*)\s\((.*)\)/) && do {
				$temp27 = $7 + $temp27;
				print RESULT "GSA_REKEY LEAVE,$temp25,$temp26,$temp27,$temp28\n";
				$continue7 = 0;
			};
		}
	}
	close CONF;
}
close RESULT;

#TOTAL FOR SERVER
$temp1 = 0; $temp2 = 0; $temp3 = 0; $temp4 = 0;
$continue1 = 0;

$outputfile = "server.csv";
open RESULT, ">$outputfile";
open TEMP, $tempfile or die "$tempfile: Open failed: $!";
#open RESULT, "+<", $outputfile or die "$outputfile: Open failed: $!";

while (<TEMP>) {
	(/IKE_SA_INIT PARSING/) && do {
		$continue1 = 1;
	};
	if ($continue1 == 1) {
		unless ((/GSA_REKEY PERIODIC/) || (/GSA_REKEY LEAVE/)) {
			(/(.*),(.*),(.*),(.*),(.*)/) && do {
				$temp1 += $2;
				$temp2 += $3;
				$temp3 += $4;
				$temp4 += $5;
			};
		};
		

		((/ss/) || (eof)) && do {
			$continue1 = 0;
			if (eof) {print RESULT $_;}
			print RESULT "TOTAL,$temp1,$temp2,$temp3,$temp4\n";
			$temp1 = 0; $temp2 = 0; $temp3 = 0; $temp4 = 0;
		};
	}
	unless (eof) {print RESULT $_;}
}
close TEMP;
close RESULT;
