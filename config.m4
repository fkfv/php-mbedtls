dnl config.m4 for extension mbedtls

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(mbedtls, for mbedtls support,
dnl Make sure that the comment is aligned:
dnl [  --with-mbedtls             Include mbedtls support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(mbedtls, whether to enable mbedtls support,
dnl Make sure that the comment is aligned:
[  --enable-mbedtls          Enable mbedtls support], no)

if test "$PHP_MBEDTLS" != "no"; then
  dnl Write more examples of tests here...

  dnl # get library FOO build options from pkg-config output
  dnl AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
  dnl AC_MSG_CHECKING(for libfoo)
  dnl if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists foo; then
  dnl   if $PKG_CONFIG foo --atleast-version 1.2.3; then
  dnl     LIBFOO_CFLAGS=\`$PKG_CONFIG foo --cflags\`
  dnl     LIBFOO_LIBDIR=\`$PKG_CONFIG foo --libs\`
  dnl     LIBFOO_VERSON=\`$PKG_CONFIG foo --modversion\`
  dnl     AC_MSG_RESULT(from pkgconfig: version $LIBFOO_VERSON)
  dnl   else
  dnl     AC_MSG_ERROR(system libfoo is too old: version 1.2.3 required)
  dnl   fi
  dnl else
  dnl   AC_MSG_ERROR(pkg-config not found)
  dnl fi
  dnl PHP_EVAL_LIBLINE($LIBFOO_LIBDIR, MBEDTLS_SHARED_LIBADD)
  dnl PHP_EVAL_INCLINE($LIBFOO_CFLAGS)

  dnl # --with-mbedtls -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/mbedtls.h"  # you most likely want to change this
  dnl if test -r $PHP_MBEDTLS/$SEARCH_FOR; then # path given as parameter
  dnl   MBEDTLS_DIR=$PHP_MBEDTLS
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for mbedtls files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       MBEDTLS_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$MBEDTLS_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the mbedtls distribution])
  dnl fi

  dnl # --with-mbedtls -> add include path
  dnl PHP_ADD_INCLUDE($MBEDTLS_DIR/include)

  dnl # --with-mbedtls -> check for lib and symbol presence
  dnl LIBNAME=MBEDTLS # you may want to change this
  dnl LIBSYMBOL=MBEDTLS # you most likely want to change this

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $MBEDTLS_DIR/$PHP_LIBDIR, MBEDTLS_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_MBEDTLSLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong mbedtls lib version or lib not found])
  dnl ],[
  dnl   -L$MBEDTLS_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(MBEDTLS_SHARED_LIBADD)

  dnl # In case of no dependencies
  AC_DEFINE(HAVE_MBEDTLS, 1, [ Have mbedtls support ])

  PHP_NEW_EXTENSION(mbedtls, mbedtls.c, $ext_shared)
fi
