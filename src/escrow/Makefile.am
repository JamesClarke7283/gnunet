# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

EXTRA_DIST = \
  escrow.conf \
  test_escrow.conf \
  $(check_SCRIPTS)

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  escrow.conf

lib_LTLIBRARIES = \
  libgnunetescrow.la
plugin_LTLIBRARIES = \
  libgnunet_plugin_escrow_plaintext.la \
  libgnunet_plugin_escrow_gns.la \
  libgnunet_plugin_escrow_anastasis.la \
  libgnunet_plugin_gnsrecord_escrow.la \
  libgnunet_plugin_rest_escrow.la

bin_PROGRAMS = \
 gnunet-escrow


libgnunet_plugin_rest_escrow_la_SOURCES = \
  plugin_rest_escrow.c
libgnunet_plugin_rest_escrow_la_LIBADD = \
  libgnunetescrow.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_escrow_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_escrow_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


libgnunetescrow_la_SOURCES = \
 escrow_api.c \
 escrow.h
libgnunetescrow_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetescrow_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0


libgnunet_plugin_escrow_plaintext_la_SOURCES = \
  plugin_escrow_plaintext.c \
  escrow_plugin_helper.c \
  escrow_plugin_helper.h
libgnunet_plugin_escrow_plaintext_la_LIBADD = \
  libgnunetescrow.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(LTLIBINTL) $(MHD_LIBS)
libgnunet_plugin_escrow_plaintext_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_escrow_gns_la_SOURCES = \
  plugin_escrow_gns.c \
  escrow_plugin_helper.c \
  escrow_plugin_helper.h
libgnunet_plugin_escrow_gns_la_LIBADD = \
  libgnunetescrow.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  -lsss \
  $(LTLIBINTL) $(MHD_LIBS)
libgnunet_plugin_escrow_gns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_escrow_anastasis_la_SOURCES = \
  plugin_escrow_anastasis.c \
  escrow_plugin_helper.c \
  escrow_plugin_helper.h
libgnunet_plugin_escrow_anastasis_la_LIBADD = \
  libgnunetescrow.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(LTLIBINTL) $(MHD_LIBS)
libgnunet_plugin_escrow_anastasis_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_gnsrecord_escrow_la_SOURCES = \
  plugin_gnsrecord_escrow.c
libgnunet_plugin_gnsrecord_escrow_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_escrow_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)


gnunet_escrow_SOURCES = \
 gnunet-escrow.c
gnunet_escrow_LDADD = \
  libgnunetescrow.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

check_SCRIPTS = \
  test_plaintext_escrow.sh \
  test_gns_escrow.sh
  # test_anastasis_escrow.sh

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
