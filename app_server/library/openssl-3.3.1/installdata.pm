package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw($PREFIX
                  $BINDIR $BINDIR_REL
                  $LIBDIR $LIBDIR_REL
                  $INCLUDEDIR $INCLUDEDIR_REL
                  $APPLINKDIR $APPLINKDIR_REL
                  $ENGINESDIR $ENGINESDIR_REL
                  $MODULESDIR $MODULESDIR_REL
                  $PKGCONFIGDIR $PKGCONFIGDIR_REL
                  $CMAKECONFIGDIR $CMAKECONFIGDIR_REL
                  $VERSION @LDLIBS);

our $PREFIX             = '/usr/local/ssl';
our $BINDIR             = '/usr/local/ssl/bin';
our $BINDIR_REL         = 'bin';
our $LIBDIR             = '/usr/local/ssl/lib64';
our $LIBDIR_REL         = 'lib64';
our $INCLUDEDIR         = '/usr/local/ssl/include';
our $INCLUDEDIR_REL     = 'include';
our $APPLINKDIR         = '/usr/local/ssl/include/openssl';
our $APPLINKDIR_REL     = 'include/openssl';
our $ENGINESDIR         = '/usr/local/ssl/lib64/engines-3';
our $ENGINESDIR_REL     = 'lib64/engines-3';
our $MODULESDIR         = '/usr/local/ssl/lib64/ossl-modules';
our $MODULESDIR_REL     = 'lib64/ossl-modules';
our $PKGCONFIGDIR       = '/usr/local/ssl/lib64/pkgconfig';
our $PKGCONFIGDIR_REL   = 'lib64/pkgconfig';
our $CMAKECONFIGDIR     = '/usr/local/ssl/lib64/cmake/OpenSSL';
our $CMAKECONFIGDIR_REL = 'lib64/cmake/OpenSSL';
our $VERSION            = '3.3.1';
our @LDLIBS             =
    # Unix and Windows use space separation, VMS uses comma separation
    split(/ +| *, */, '-ldl -pthread ');

1;
