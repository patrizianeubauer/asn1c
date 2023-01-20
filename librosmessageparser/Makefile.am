
AM_CFLAGS = @ADD_CFLAGS@
AM_CPPFLAGS =                       \
    -I$(top_srcdir)/libasn1common   \
    -I$(top_srcdir)/libasn1parser   \
    -I$(top_srcdir)/libasn1print   \
    -I$(top_srcdir)/librosmessageparser   \
    -I$(top_srcdir)/libasn1fix

noinst_LTLIBRARIES = librosmessageparser.la

librosmessageparser_la_LIBADD = $(top_builddir)/libasn1common/libasn1common.la
librosmessageparser_la_SOURCES =           \
    asn1rosparser.c asn1rosparser.h