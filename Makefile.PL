use 5.00006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::DNS::Reputation::HoneyProject',
    VERSION_FROM      => 'lib/Net/DNS/Reputation/HoneyProject.pm',
    PREREQ_PM         => {
	    'Net::DNS::Simple' =>  0,
    }, 
    ABSTRACT_FROM     => 'lib/Net/DNS/Reputation/HoneyProject.pm', 
    AUTHOR            => 'Kaio Rafael <perl@kaiux.com>',
    LICENSE           => 'gpl_3',
    MIN_PERL_VERSION => 5.006,
);
