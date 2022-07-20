# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include \
  $(GNUNET_CPPFLAGS)
pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  multicast.conf

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetmulticast.la

libgnunetmulticast_la_SOURCES = \
  multicast_api.c multicast.h
libgnunetmulticast_la_LIBADD = \
  -lgnunetutil \
  $(GN_LIBINTL) $(XLIB)
libgnunetmulticast_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-multicast

libexec_PROGRAMS = \
 gnunet-service-multicast \
 $(EXP_LIBEXEC)

gnunet_multicast_SOURCES = \
 gnunet-multicast.c
gnunet_multicast_LDADD = \
  -lgnunetutil \
  $(GN_LIBINTL)

gnunet_service_multicast_SOURCES = \
 gnunet-service-multicast.c
gnunet_service_multicast_LDADD = \
  -lgnunetutil \
  -lgnunetcadet \
  -lgnunetstatistics \
  $(GN_LIBINTL)

check_PROGRAMS = \
  test_multicast \
  test_multicast_multipeer_star \
  test_multicast_multipeer_line

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@}; export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH; unset XDG_DATA_HOME; unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_multicast_SOURCES = \
 test_multicast.c
test_multicast_LDADD = \
  libgnunetmulticast.la \
  -lgnunettesting \
  -lgnunetutil
test_multicast_multipeer_star_SOURCES = \
  test_multicast_multipeer.c
test_multicast_multipeer_star_LDADD = \
  libgnunetmulticast.la \
  -lgnunettestbed \
  -lgnunetutil
test_multicast_multipeer_line_SOURCES = \
  test_multicast_multipeer.c
test_multicast_multipeer_line_LDADD = \
  libgnunetmulticast.la \
  -lgnunettestbed \
  -lgnunetutil
