dnl Process this file with autoconf to produce a configure script.

AC_INIT(src/joinparty.cpp, 0.0.1)
dnl Every other copy of the package version number gets its value from here
AM_INIT_AUTOMAKE

dnl create a config.h file (Automake will add -DHAVE_CONFIG_H)
AM_CONFIG_HEADER(config.h)

AC_SUBST(VERSION)

ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_CC
AC_PROG_CXX
AC_LANG([C++])

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC

AC_HEADER_MAJOR

dnl Checks for library functions.

AC_MSG_CHECKING([--with-pkgconfigdir option])
AC_ARG_WITH([pkgconfigdir],
  AS_HELP_STRING([--with-pkgconfigdir=DIR],
    [Path to pkgconfig directory. @<:@default=${libdir}/pkgconfig@:>@]),
    [pkgconfigdir=$withval],
    [pkgconfigdir=${libdir}/pkgconfig])
AC_MSG_RESULT([$pkgconfigdir])
AC_SUBST([pkgconfigdir])

PKG_CHECK_MODULES([sodium], [libsodium >= 0.0.0])
AC_SUBST([sodium_CPPFLAGS], [${sodium_CFLAGS}])
AC_MSG_NOTICE([sodium_CPPFLAGS : ${sodium_CPPFLAGS}])
AC_MSG_NOTICE([sodium_LIBS : ${sodium_LIBS}])

PKG_CHECK_MODULES([bitcoin_client], [libbitcoin-client >= 3.0.0])
AC_SUBST([bitcoin_client_PKG], ['libbitcoin-client >= 3.0.0'])
AC_SUBST([bitcoin_client_CPPFLAGS], [${bitcoin_client_CFLAGS}])
AC_MSG_NOTICE([bitcoin_client_CPPFLAGS : ${bitcoin_client_CPPFLAGS}])
AC_MSG_NOTICE([bitcoin_client_LIBS : ${bitcoin_client_LIBS}])

AC_CHECK_LIB([gmp], [__gmpn_sub_n],
    [AC_SUBST([gmp_LIBS], [-lgmp])
    AC_MSG_NOTICE([gmp_LIBS : ${gmp_LIBS}])],
    [AC_MSG_ERROR([gmp library is required but was not found.])])
AC_SUBST([gmp_LIBS], [])

dnl needed for boost::asio::ssl
AC_CHECK_LIB([ssl], [SSL_connect],
    [AC_SUBST([ssl_LIBS], [-lssl])
    AC_MSG_NOTICE([ssl_LIBS : ${ssl_LIBS}])],
    [AC_MSG_ERROR([ssl library is required but was not found.])])
AC_SUBST([ssl_LIBS], [])

dnl needed for boost::asio::ssl
AC_CHECK_LIB([crypto], [X509_NAME_get_entry],
    [AC_SUBST([crypto_LIBS], [-lcrypto])
    AC_MSG_NOTICE([crypto_LIBS : ${crypto_LIBS}])],
    [AC_MSG_ERROR([crypto library is required but was not found.])])
AC_SUBST([crypto_LIBS], [])

dnl C/C++ flags
dnl DEBUG="-DBOOST_ASIO_ENABLE_HANDLER_TRACKING"

CXXFLAGS="-ggdb -I../include/ $CXXFLAGS -std=c++14 $sodium_CPPFLAGS $bitcoin_client_CPPFLAGS $DEBUG"
CFLAGS="-ggdb -I../include/ $CFLAGS $sodium_CFLAGS $bitcoin_client_CFLAGS -Wall -Wextra -pedantic -Wno-missing-braces $DEBUG"

dnl Add required SYSCONFDIR to include/joinparty/sysconfdir.hpp for
dnl proper libbitcoin client usage.  This is a hack, but bitcoin_LIBS
dnl has the path we want and starts with the for -LPATH/lib, so cut
dnl off the leading "-L" and trailing "lib"
SYSCONFDIR=$(echo "$bitcoin_LIBS" | cut -f 1 -d' ' | cut -b 3- | rev | cut -b 4- | rev)
echo "#define SYSCONFDIR $SYSCONFDIR" > include/joinparty/sysconfdir.hpp

AC_OUTPUT(Makefile src/Makefile)
